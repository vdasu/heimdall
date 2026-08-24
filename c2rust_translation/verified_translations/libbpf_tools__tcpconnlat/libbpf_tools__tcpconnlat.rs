#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

const TASK_COMM_LEN: usize = 16;
const AF_INET: i32 = 2;
const TCP_SYN_SENT: u8 = 2;

const SKC_DADDR_OFF: usize = 0;
const SKC_RCV_SADDR_OFF: usize = 4;
const SKC_DPORT_OFF: usize = 12;
const SKC_NUM_OFF: usize = 14;
const SKC_FAMILY_OFF: usize = 16;
const SKC_STATE_OFF: usize = 18;
const SKC_V6_DADDR_OFF: usize = 56;
const SKC_V6_RCV_SADDR_OFF: usize = 72;

#[repr(C)]
#[derive(Copy, Clone)]
struct Piddata {
    comm: [u8; TASK_COMM_LEN],
    ts: u64,
    tgid: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    saddr: [u32; 4],
    daddr: [u32; 4],
    comm: [u8; TASK_COMM_LEN],
    delta_us: u64,
    ts_us: u64,
    tgid: u32,
    af: i32,
    lport: u16,
    dport: u16,
    _pad: [u8; 4],
}

#[no_mangle]
static targ_min_us: Global<u64> = Global::new(0);

#[no_mangle]
static targ_tgid: Global<u32> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u64, Piddata> = HashMap::with_max_entries(4096, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn trace_connect(sk: u64) -> i32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target_tgid = targ_tgid.load();
    if target_tgid != 0 && target_tgid != tgid {
        return 0;
    }
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    let piddata = Piddata { comm, ts, tgid, _pad: 0 };
    let _ = START.insert(&sk, &piddata, 0);
    0
}

#[inline(always)]
fn handle_tcp_rcv<C: EbpfContext>(ctx: &C, sk: u64) -> i32 {
    // SAFETY: reading skc_state byte from sock struct via kernel pointer
    let state: u8 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_STATE_OFF) as *const u8)
    }
    .unwrap_or(0);

    if state != TCP_SYN_SENT {
        return 0;
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let piddatap = match unsafe { START.get(&sk) } {
        Some(p) => *p,
        None => return 0,
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    let delta = ts.wrapping_sub(piddatap.ts);

    if (delta as i64) >= 0 {
        let delta_us = delta / 1000;
        let min_us = targ_min_us.load();
        if min_us == 0 || delta_us >= min_us {
            let mut event = Event {
                saddr: [0u32; 4],
                daddr: [0u32; 4],
                comm: piddatap.comm,
                delta_us,
                ts_us: ts / 1000,
                tgid: piddatap.tgid,
                af: 0,
                lport: 0,
                dport: 0,
                _pad: [0u8; 4],
            };

            // SAFETY: reading skc_num (lport) from sock struct
            event.lport = unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_NUM_OFF) as *const u16)
            }
            .unwrap_or(0);

            // SAFETY: reading skc_dport from sock struct
            event.dport = unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_DPORT_OFF) as *const u16)
            }
            .unwrap_or(0);

            // SAFETY: reading skc_family from sock struct
            let family: u16 = unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_FAMILY_OFF) as *const u16)
            }
            .unwrap_or(0);
            event.af = family as i32;

            if event.af == AF_INET {
                // SAFETY: reading skc_rcv_saddr (IPv4 source) from sock struct
                event.saddr[0] = unsafe {
                    bpf_probe_read_kernel(
                        (sk as *const u8).add(SKC_RCV_SADDR_OFF) as *const u32,
                    )
                }
                .unwrap_or(0);

                // SAFETY: reading skc_daddr (IPv4 dest) from sock struct
                event.daddr[0] = unsafe {
                    bpf_probe_read_kernel(
                        (sk as *const u8).add(SKC_DADDR_OFF) as *const u32,
                    )
                }
                .unwrap_or(0);
            } else {
                // SAFETY: reading skc_v6_rcv_saddr (IPv6 source) from sock struct
                event.saddr = unsafe {
                    bpf_probe_read_kernel(
                        (sk as *const u8).add(SKC_V6_RCV_SADDR_OFF) as *const [u32; 4],
                    )
                }
                .unwrap_or([0u32; 4]);

                // SAFETY: reading skc_v6_daddr (IPv6 dest) from sock struct
                event.daddr = unsafe {
                    bpf_probe_read_kernel(
                        (sk as *const u8).add(SKC_V6_DADDR_OFF) as *const [u32; 4],
                    )
                }
                .unwrap_or([0u32; 4]);
            }

            EVENTS.output(ctx, &event, 0);
        }
    }

    let _ = START.remove(&sk);
    0
}

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let sk: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_connect(sk) as u32
}

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let sk: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_connect(sk) as u32
}

#[kprobe]
pub fn tcp_rcv_state_process(ctx: ProbeContext) -> u32 {
    let sk: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    handle_tcp_rcv(&ctx, sk) as u32
}

#[tracepoint]
pub fn tcp_destroy_sock(ctx: TracePointContext) -> u32 {
    // SAFETY: reading skaddr field from tracepoint context at offset 8
    let sk: u64 = match unsafe { ctx.read_at(8) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let _ = START.remove(&sk);
    0
}

#[fentry(function = "tcp_v4_connect")]
pub fn fentry_tcp_v4_connect(ctx: FEntryContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    trace_connect(sk)
}

#[fentry(function = "tcp_v6_connect")]
pub fn fentry_tcp_v6_connect(ctx: FEntryContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    trace_connect(sk)
}

#[fentry(function = "tcp_rcv_state_process")]
pub fn fentry_tcp_rcv_state_process(ctx: FEntryContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    handle_tcp_rcv(&ctx, sk)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
