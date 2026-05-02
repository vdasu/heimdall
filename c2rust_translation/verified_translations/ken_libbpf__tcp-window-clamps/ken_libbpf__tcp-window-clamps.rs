#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

const MIN_CLAMP: u32 = 32 * 1024;

#[map(name = "tcp_window_clamps_total")]
static TCP_WINDOW_CLAMPS_TOTAL: Array<u64> = Array::with_max_entries(1, 0);

#[map(name = "tcp_rmem_schedule_enters")]
static TCP_RMEM_SCHEDULE_ENTERS: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);

#[inline(always)]
fn enter_key() -> u64 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid != 0 {
        (tgid as u64) << 32
    } else {
        // SAFETY: calling BPF helper to get current processor ID
        let cpu = unsafe { bpf_get_smp_processor_id() };
        ((tgid as u64) << 32) | (cpu as u64)
    }
}

#[inline(always)]
fn increment_map(index: u32, increment: u64) {
    let ptr = TCP_WINDOW_CLAMPS_TOTAL.get_ptr_mut(index);
    match ptr {
        Some(p) => {
            // SAFETY: creating atomic from valid map pointer returned by get_ptr_mut
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = TCP_WINDOW_CLAMPS_TOTAL.set(index, &zero, 1); // BPF_NOEXIST
            let ptr2 = TCP_WINDOW_CLAMPS_TOTAL.get_ptr_mut(index);
            if let Some(p) = ptr2 {
                // SAFETY: creating atomic from valid map pointer returned by get_ptr_mut
                let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) };
                atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[inline(always)]
fn handle_tcp_sock(tp: u64) -> i32 {
    if tp == 0 {
        return 0;
    }

    // rcv_ssthresh is at offset 1388 from tcp_sock pointer (4 bytes, u32)
    let rcv_ssthresh_ptr = (tp + 1388) as *const u32;
    // SAFETY: reading rcv_ssthresh field from kernel tcp_sock struct via probe_read_kernel
    let rcv_ssthresh: u32 = match unsafe { bpf_probe_read_kernel(rcv_ssthresh_ptr) } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if rcv_ssthresh < MIN_CLAMP {
        let zero: u32 = 0;
        increment_map(zero, 1);
    }

    0
}

#[kprobe]
pub fn tcp_try_rmem_schedule(ctx: ProbeContext) -> u32 {
    let sk: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };

    let key = enter_key();
    let _ = TCP_RMEM_SCHEDULE_ENTERS.insert(&key, &sk, 1); // BPF_NOEXIST

    0
}

#[kretprobe]
pub fn tcp_try_rmem_schedule_ret(_ctx: RetProbeContext) -> u32 {
    let key = enter_key();

    // SAFETY: map lookup on valid LruHashMap
    let skp = match unsafe { TCP_RMEM_SCHEDULE_ENTERS.get(&key) } {
        Some(v) => *v,
        None => return 0,
    };

    let _ = TCP_RMEM_SCHEDULE_ENTERS.remove(&key);

    handle_tcp_sock(skp) as u32
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
