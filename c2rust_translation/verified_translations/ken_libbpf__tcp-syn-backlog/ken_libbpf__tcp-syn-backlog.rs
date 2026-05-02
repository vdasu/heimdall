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

const BUCKET_MULTIPLIER: u64 = 50;
const BUCKET_COUNT: u32 = 20;

#[map(name = "tcp_syn_backlog")]
static TCP_SYN_BACKLOG: HashMap<u64, u64> = HashMap::with_max_entries(BUCKET_COUNT + 2, 0);

#[inline(always)]
fn increment_map(key: &u64, increment: u64) -> u64 {
    let count_ptr = TCP_SYN_BACKLOG.get_ptr_mut(key);
    match count_ptr {
        Some(ptr) => {
            // SAFETY: creating atomic from valid map pointer
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            // SAFETY: reading value from valid map pointer after atomic add
            unsafe { *ptr }
        }
        None => {
            let zero: u64 = 0;
            let _ = TCP_SYN_BACKLOG.insert(key, &zero, 1);
            let count_ptr2 = TCP_SYN_BACKLOG.get_ptr_mut(key);
            match count_ptr2 {
                Some(ptr) => {
                    // SAFETY: creating atomic from valid map pointer
                    let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
                    atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
                    // SAFETY: reading value from valid map pointer after atomic add
                    unsafe { *ptr }
                }
                None => 0,
            }
        }
    }
}

#[inline(always)]
fn do_count(backlog: u64) -> i32 {
    let bucket: u64 = backlog / BUCKET_MULTIPLIER;

    increment_map(&bucket, 1);
    increment_map(&bucket, backlog);

    0
}

#[kprobe]
pub fn kprobe__tcp_v4_syn_recv_sock(ctx: ProbeContext) -> u32 {
    let sk: *const c_void = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    // SAFETY: reading sk_ack_backlog field from kernel sock struct pointer
    let sk_ack_backlog: u32 = match unsafe { bpf_probe_read_kernel((sk as *const u8).offset(292) as *const u32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    do_count((sk_ack_backlog as u64) / 50) as u32
}

#[kprobe]
pub fn kprobe__tcp_v6_syn_recv_sock(ctx: ProbeContext) -> u32 {
    let sk: *const c_void = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    // SAFETY: reading sk_ack_backlog field from kernel sock struct pointer
    let sk_ack_backlog: u32 = match unsafe { bpf_probe_read_kernel((sk as *const u8).offset(292) as *const u32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    do_count((sk_ack_backlog as u64) / 50) as u32
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
