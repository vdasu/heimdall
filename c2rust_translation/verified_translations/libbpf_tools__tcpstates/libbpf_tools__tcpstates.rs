#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::cty::*;
use aya_ebpf::Global;

const TASK_COMM_LEN: usize = 16;
const MAX_ENTRIES: u32 = 10240;
const AF_INET: u16 = 2;
const IPPROTO_TCP: u16 = 6;
const TCP_CLOSE: i32 = 7;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    saddr: u128,
    daddr: u128,
    skaddr: u64,
    ts_us: u64,
    delta_us: u64,
    pid: u32,
    oldstate: i32,
    newstate: i32,
    family: u16,
    sport: u16,
    dport: u16,
    task: [u8; TASK_COMM_LEN],
}

#[map(name = "sports")]
static SPORTS: HashMap<u16, u16> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "dports")]
static DPORTS: HashMap<u16, u16> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "timestamps")]
static TIMESTAMPS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[no_mangle]
static filter_by_sport: Global<u8> = Global::new(0);

#[no_mangle]
static filter_by_dport: Global<u8> = Global::new(0);

#[no_mangle]
static target_family: Global<i16> = Global::new(0);

#[tracepoint]
pub fn handle_set_state(ctx: TracePointContext) -> i32 {
    match try_handle_set_state(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_set_state(ctx: TracePointContext) -> Result<i32, c_long> {
    // SAFETY: reading skaddr from tracepoint context at offset 8
    let sk: u64 = unsafe { ctx.read_at(8) }?;
    // SAFETY: reading family from tracepoint context at offset 28
    let family: u16 = unsafe { ctx.read_at(28) }?;
    // SAFETY: reading sport from tracepoint context at offset 24
    let sport: u16 = unsafe { ctx.read_at(24) }?;
    // SAFETY: reading dport from tracepoint context at offset 26
    let dport: u16 = unsafe { ctx.read_at(26) }?;
    // SAFETY: reading protocol from tracepoint context at offset 30
    let protocol: u16 = unsafe { ctx.read_at(30) }?;
    // SAFETY: reading oldstate from tracepoint context at offset 16
    let oldstate: i32 = unsafe { ctx.read_at(16) }?;
    // SAFETY: reading newstate from tracepoint context at offset 20
    let newstate: i32 = unsafe { ctx.read_at(20) }?;

    if protocol != IPPROTO_TCP {
        return Ok(0);
    }

    let tf = target_family.load();
    if tf != 0 && (tf as i32) != (family as i32) {
        return Ok(0);
    }

    if filter_by_sport.load() == 1 {
        // SAFETY: HashMap::get requires unsafe
        if unsafe { SPORTS.get(&sport) }.is_none() {
            return Ok(0);
        }
    }

    if filter_by_dport.load() == 1 {
        // SAFETY: HashMap::get requires unsafe
        if unsafe { DPORTS.get(&dport) }.is_none() {
            return Ok(0);
        }
    }

    // SAFETY: HashMap::get requires unsafe
    let tsp = unsafe { TIMESTAMPS.get(&sk) };
    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    let ts = unsafe { bpf_ktime_get_ns() };
    let delta_us = match tsp {
        Some(t) => (ts - *t) / 1000,
        None => 0,
    };

    let mut event = Event {
        saddr: 0,
        daddr: 0,
        skaddr: sk,
        ts_us: ts / 1000,
        delta_us,
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        oldstate,
        newstate,
        family,
        sport,
        dport,
        task: [0u8; TASK_COMM_LEN],
    };

    event.task = bpf_get_current_comm()?;

    if family == AF_INET {
        // SAFETY: reading skc_rcv_saddr from kernel sock struct at offset 4
        event.saddr = unsafe { bpf_probe_read_kernel((sk + 4) as *const u128) }?;
        // SAFETY: reading skc_daddr from kernel sock struct at offset 0
        event.daddr = unsafe { bpf_probe_read_kernel(sk as *const u128) }?;
    } else {
        // SAFETY: reading skc_v6_rcv_saddr from kernel sock struct at offset 72
        event.saddr = unsafe { bpf_probe_read_kernel((sk + 72) as *const u128) }?;
        // SAFETY: reading skc_v6_daddr from kernel sock struct at offset 56
        event.daddr = unsafe { bpf_probe_read_kernel((sk + 56) as *const u128) }?;
    }

    EVENTS.output(&ctx, &event, 0);

    if newstate == TCP_CLOSE {
        let _ = TIMESTAMPS.remove(&sk);
    } else {
        let _ = TIMESTAMPS.insert(&sk, &ts, 0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
