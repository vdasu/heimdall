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
use aya_ebpf::{EbpfContext, Global};

const MAX_ENTRIES: u32 = 10240;
const RINGBUF_SIZE: u32 = 1024 * 256;
const AF_INET: u16 = 2;

// Kernel struct offsets (from compiled C binary CO-RE resolution)
const INET_SPORT_OFF: usize = 782;
const SKC_DPORT_OFF: usize = 12;
const SKC_FAMILY_OFF: usize = 16;
const SKC_DADDR_OFF: usize = 0;
const SKC_RCV_SADDR_OFF: usize = 4;
const SKC_V6_DADDR_OFF: usize = 56;
const SKC_V6_RCV_SADDR_OFF: usize = 72;
const SKB_DATA_OFF: usize = 208;
const SKB_LEN_OFF: usize = 112;
const TCPHDR_DOFF_OFF: usize = 12;

#[repr(C)]
struct Event {
    saddr: [u32; 4],
    daddr: [u32; 4],
    delta_us: u64,
    pid: u32,
    tid: u32,
    dport: u16,
    sport: u16,
    family: u16,
    comm: [u8; 16],
}

#[no_mangle]
static targ_pid: Global<u32> = Global::new(0);
#[no_mangle]
static targ_tid: Global<u32> = Global::new(0);
#[no_mangle]
static targ_sport: Global<u16> = Global::new(0);
#[no_mangle]
static targ_dport: Global<u16> = Global::new(0);
#[no_mangle]
static targ_min_us: Global<u64> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE, 0);

#[map(name = "heap")]
static HEAP: PerCpuArray<[u8; 10240]> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn get_sock_ident(sk: u64) -> u64 {
    // SAFETY: calling bpf_get_socket_cookie helper with sock pointer
    unsafe { bpf_get_socket_cookie(sk as *mut _) as u64 }
}

#[inline(always)]
fn do_handle_tcp_probe(sk: u64, skb: u64) {
    let ts = targ_sport.load();
    if ts != 0 {
        // SAFETY: reading inet_sport from kernel sock struct
        let sport = match unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(INET_SPORT_OFF) as *const u16)
        } {
            Ok(v) => v,
            Err(_) => return,
        };
        if ts != sport {
            return;
        }
    }

    let td = targ_dport.load();
    if td != 0 {
        // SAFETY: reading skc_dport from kernel sock struct
        let dport = match unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(SKC_DPORT_OFF) as *const u16)
        } {
            Ok(v) => v,
            Err(_) => return,
        };
        if td != dport {
            return;
        }
    }

    // SAFETY: reading skb->data pointer from kernel sk_buff struct
    let th: u64 = match unsafe {
        bpf_probe_read_kernel((skb as *const u8).add(SKB_DATA_OFF) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return,
    };

    // SAFETY: reading doff bitfield from tcp header
    let doff_raw: u32 = match unsafe {
        bpf_probe_read_kernel((th as *const u8).add(TCPHDR_DOFF_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return,
    };
    let doff: u64 = ((doff_raw as u64) << 56) >> 60;

    // SAFETY: reading skb->len from kernel sk_buff struct
    let len: u32 = match unsafe {
        bpf_probe_read_kernel((skb as *const u8).add(SKB_LEN_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return,
    };

    if (doff << 2) >= len as u64 {
        return;
    }

    let sock_ident = get_sock_ident(sk);
    // SAFETY: reading kernel monotonic time
    let ktime = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&sock_ident, &ktime, 0);
}

#[inline(always)]
fn do_handle_tcp_rcv_space_adjust(sk: u64) {
    let sock_ident = get_sock_ident(sk);
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // SAFETY: looking up start map entry
    let tsp = match unsafe { START.get(&sock_ident) } {
        Some(v) => *v,
        None => return,
    };

    let tpid = targ_pid.load();
    if tpid != 0 && tpid != pid {
        let _ = START.remove(&sock_ident);
        return;
    }

    let ttid = targ_tid.load();
    if ttid != 0 && ttid != tid {
        let _ = START.remove(&sock_ident);
        return;
    }

    // SAFETY: reading kernel monotonic time
    let ktime = unsafe { bpf_ktime_get_ns() };
    let delta_us: u64 = (ktime - tsp) / 1000;

    let min_us = targ_min_us.load();
    if delta_us <= min_us {
        let _ = START.remove(&sock_ident);
        return;
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let ptr = entry.as_mut_ptr();
        // SAFETY: zero-initializing reserved ringbuf entry to prevent stale data leaks
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0u8, core::mem::size_of::<Event>());
        }
        // SAFETY: writing pid to ringbuf entry
        unsafe { (*ptr).pid = pid };
        // SAFETY: writing tid to ringbuf entry
        unsafe { (*ptr).tid = tid };
        // SAFETY: writing delta_us to ringbuf entry
        unsafe { (*ptr).delta_us = delta_us };

        // SAFETY: reading inet_sport from kernel sock struct
        let sport = match unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(INET_SPORT_OFF) as *const u16)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                let _ = START.remove(&sock_ident);
                return;
            }
        };
        // SAFETY: writing sport to ringbuf entry
        unsafe { (*ptr).sport = sport };

        // SAFETY: reading skc_dport from kernel sock struct
        let dport = match unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(SKC_DPORT_OFF) as *const u16)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                let _ = START.remove(&sock_ident);
                return;
            }
        };
        // SAFETY: writing dport to ringbuf entry
        unsafe { (*ptr).dport = dport };

        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => {
                entry.discard(0);
                let _ = START.remove(&sock_ident);
                return;
            }
        };
        // SAFETY: writing comm to ringbuf entry
        unsafe { (*ptr).comm = comm };

        // SAFETY: reading skc_family from kernel sock struct
        let family = match unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(SKC_FAMILY_OFF) as *const u16)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                let _ = START.remove(&sock_ident);
                return;
            }
        };

        if family == AF_INET {
            // SAFETY: reading skc_rcv_saddr from kernel sock struct
            let saddr = match unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_RCV_SADDR_OFF) as *const u32)
            } {
                Ok(v) => v,
                Err(_) => {
                    entry.discard(0);
                    let _ = START.remove(&sock_ident);
                    return;
                }
            };
            // SAFETY: writing saddr to ringbuf entry
            unsafe { (*ptr).saddr[0] = saddr };

            // SAFETY: reading skc_daddr from kernel sock struct
            let daddr = match unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_DADDR_OFF) as *const u32)
            } {
                Ok(v) => v,
                Err(_) => {
                    entry.discard(0);
                    let _ = START.remove(&sock_ident);
                    return;
                }
            };
            // SAFETY: writing daddr to ringbuf entry
            unsafe { (*ptr).daddr[0] = daddr };
        } else {
            // SAFETY: reading skc_v6_rcv_saddr from kernel sock struct
            let saddr = match unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_V6_RCV_SADDR_OFF) as *const u32)
            } {
                Ok(v) => v,
                Err(_) => {
                    entry.discard(0);
                    let _ = START.remove(&sock_ident);
                    return;
                }
            };
            // SAFETY: writing saddr to ringbuf entry
            unsafe { (*ptr).saddr[0] = saddr };

            // SAFETY: reading skc_v6_daddr from kernel sock struct
            let daddr = match unsafe {
                bpf_probe_read_kernel((sk as *const u8).add(SKC_V6_DADDR_OFF) as *const u32)
            } {
                Ok(v) => v,
                Err(_) => {
                    entry.discard(0);
                    let _ = START.remove(&sock_ident);
                    return;
                }
            };
            // SAFETY: writing daddr to ringbuf entry
            unsafe { (*ptr).daddr[0] = daddr };
        }

        // SAFETY: writing family to ringbuf entry
        unsafe { (*ptr).family = family };
        entry.submit(0);
    }

    let _ = START.remove(&sock_ident);
}

#[inline(always)]
fn do_handle_tcp_destroy_sock(sk: u64) {
    let sock_ident = get_sock_ident(sk);
    let _ = START.remove(&sock_ident);
}

#[raw_tracepoint(tracepoint = "tcp_probe")]
pub fn tcp_probe(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading first arg (sk) from raw tracepoint context
    let sk = unsafe { *ctx_ptr };
    // SAFETY: reading second arg (skb) from raw tracepoint context
    let skb = unsafe { *(ctx_ptr.add(1)) };
    do_handle_tcp_probe(sk, skb);
    0
}

#[btf_tracepoint(function = "tcp_probe")]
pub fn tcp_probe_btf(ctx: BtfTracePointContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    let skb: u64 = ctx.arg(1);
    do_handle_tcp_probe(sk, skb);
    0
}

#[raw_tracepoint(tracepoint = "tcp_rcv_space_adjust")]
pub fn tcp_rcv_space_adjust(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading first arg (sk) from raw tracepoint context
    let sk = unsafe { *ctx_ptr };
    do_handle_tcp_rcv_space_adjust(sk);
    0
}

#[btf_tracepoint(function = "tcp_rcv_space_adjust")]
pub fn tcp_rcv_space_adjust_btf(ctx: BtfTracePointContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    do_handle_tcp_rcv_space_adjust(sk);
    0
}

#[raw_tracepoint(tracepoint = "tcp_destroy_sock")]
pub fn tcp_destroy_sock(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading first arg (sk) from raw tracepoint context
    let sk = unsafe { *ctx_ptr };
    do_handle_tcp_destroy_sock(sk);
    0
}

#[btf_tracepoint(function = "tcp_destroy_sock")]
pub fn tcp_destroy_sock_btf(ctx: BtfTracePointContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    do_handle_tcp_destroy_sock(sk);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
