#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::EbpfContext;

const TASK_COMM_LEN: usize = 16;
const MAX_ENTRIES: u32 = 10240;
const IPPROTO_TCP: u16 = 6;
const TCP_FIN_WAIT1: i32 = 4;
const TCP_SYN_SENT: i32 = 2;
const TCP_LAST_ACK: i32 = 9;
const TCP_CLOSE: i32 = 7;
const AF_INET: u16 = 2;

// Tracepoint context offsets for sock/inet_sock_set_state
const OFF_SKADDR: usize = 8;
const OFF_NEWSTATE: usize = 20;
const OFF_SPORT: usize = 24;
const OFF_DPORT: usize = 26;
const OFF_FAMILY: usize = 28;
const OFF_PROTOCOL: usize = 30;
const OFF_SADDR: usize = 32;
const OFF_DADDR: usize = 36;
const OFF_SADDR_V6: usize = 40;
const OFF_DADDR_V6: usize = 56;

// tcp_sock field offsets (from compiled C binary)
const OFF_BYTES_RECEIVED: usize = 1728;
const OFF_BYTES_ACKED: usize = 1784;

#[repr(C)]
struct Ident {
    pid: u32,
    comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
struct Event {
    saddr: u128,
    daddr: u128,
    ts_us: u64,
    span_us: u64,
    rx_b: u64,
    tx_b: u64,
    pid: u32,
    sport: u16,
    dport: u16,
    family: u16,
    comm: [u8; TASK_COMM_LEN],
}

#[map(name = "birth")]
static BIRTH: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "idents")]
static IDENTS: HashMap<u64, Ident> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> i32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<i32, i64> {
    // SAFETY: reading protocol field from tracepoint context
    let protocol: u16 = unsafe { ctx.read_at(OFF_PROTOCOL)? };
    if protocol != IPPROTO_TCP {
        return Ok(0);
    }

    // SAFETY: reading family field from tracepoint context
    let family: u16 = unsafe { ctx.read_at(OFF_FAMILY)? };
    // SAFETY: reading sport field from tracepoint context
    let sport: u16 = unsafe { ctx.read_at(OFF_SPORT)? };
    // SAFETY: reading dport field from tracepoint context
    let dport: u16 = unsafe { ctx.read_at(OFF_DPORT)? };
    // SAFETY: reading skaddr field from tracepoint context
    let sk: u64 = unsafe { ctx.read_at(OFF_SKADDR)? };
    // SAFETY: reading newstate field from tracepoint context
    let newstate: i32 = unsafe { ctx.read_at(OFF_NEWSTATE)? };

    if newstate < TCP_FIN_WAIT1 {
        // SAFETY: calling BPF helper to get current time
        let ts = unsafe { bpf_ktime_get_ns() };
        BIRTH.insert(&sk, &ts, 0).ok();
    }

    if newstate == TCP_SYN_SENT || newstate == TCP_LAST_ACK {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        let ident = Ident { pid, comm };
        IDENTS.insert(&sk, &ident, 0).ok();
    }

    if newstate != TCP_CLOSE {
        return Ok(0);
    }

    // SAFETY: looking up birth timestamp from hash map
    let start_val = match unsafe { BIRTH.get(&sk) } {
        Some(v) => *v,
        None => {
            IDENTS.remove(&sk).ok();
            return Ok(0);
        }
    };

    // SAFETY: calling BPF helper to get current time
    let ts = unsafe { bpf_ktime_get_ns() };
    let delta_us = (ts - start_val) / 1000;

    // SAFETY: looking up ident from hash map
    let identp = unsafe { IDENTS.get(&sk) };

    // Get pid from identp or current task (matching C order)
    let pid = match identp {
        Some(id) => id.pid,
        None => (bpf_get_current_pid_tgid() >> 32) as u32,
    };

    // Read bytes_received and bytes_acked BEFORE identp->comm
    // (must match C probe_read ordering for symbolic variable numbering)
    // SAFETY: reading bytes_received from kernel tcp_sock pointer
    let rx_b: u64 = unsafe {
        bpf_probe_read_kernel(((sk as *const u8).add(OFF_BYTES_RECEIVED)) as *const u64)
            .unwrap_or(0)
    };
    // SAFETY: reading bytes_acked from kernel tcp_sock pointer
    let tx_b: u64 = unsafe {
        bpf_probe_read_kernel(((sk as *const u8).add(OFF_BYTES_ACKED)) as *const u64)
            .unwrap_or(0)
    };

    // Now read comm (after bytes_received/bytes_acked to match C ordering)
    let mut event_comm = [0u8; TASK_COMM_LEN];
    if let Some(id) = identp {
        // SAFETY: reading comm from map value via probe_read to match C behavior
        event_comm = unsafe {
            bpf_probe_read_kernel(&id.comm as *const [u8; 16]).unwrap_or([0u8; 16])
        };
    } else {
        if let Ok(c) = bpf_get_current_comm() {
            event_comm = c;
        }
    }

    // Read source/dest addresses from tracepoint context
    let ctx_ptr = ctx.as_ptr() as *const u8;

    let mut event_saddr: u128 = 0;
    let mut event_daddr: u128 = 0;

    if family == AF_INET {
        // SAFETY: reading IPv4 saddr (4 bytes) from tracepoint context
        let saddr: u32 = unsafe {
            bpf_probe_read_kernel(ctx_ptr.add(OFF_SADDR) as *const u32).unwrap_or(0)
        };
        event_saddr = saddr as u128;
        // SAFETY: reading IPv4 daddr (4 bytes) from tracepoint context
        let daddr: u32 = unsafe {
            bpf_probe_read_kernel(ctx_ptr.add(OFF_DADDR) as *const u32).unwrap_or(0)
        };
        event_daddr = daddr as u128;
    } else {
        // SAFETY: reading IPv6 saddr (16 bytes) from tracepoint context
        let saddr: [u8; 16] = unsafe {
            bpf_probe_read_kernel(ctx_ptr.add(OFF_SADDR_V6) as *const [u8; 16])
                .unwrap_or([0; 16])
        };
        event_saddr = u128::from_ne_bytes(saddr);
        // SAFETY: reading IPv6 daddr (16 bytes) from tracepoint context
        let daddr: [u8; 16] = unsafe {
            bpf_probe_read_kernel(ctx_ptr.add(OFF_DADDR_V6) as *const [u8; 16])
                .unwrap_or([0; 16])
        };
        event_daddr = u128::from_ne_bytes(daddr);
    }

    let event = Event {
        saddr: event_saddr,
        daddr: event_daddr,
        ts_us: ts / 1000,
        span_us: delta_us,
        rx_b,
        tx_b,
        pid,
        sport,
        dport,
        family,
        comm: event_comm,
    };

    EVENTS.output(&ctx, &event, 0);

    // cleanup
    BIRTH.remove(&sk).ok();
    IDENTS.remove(&sk).ok();
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
