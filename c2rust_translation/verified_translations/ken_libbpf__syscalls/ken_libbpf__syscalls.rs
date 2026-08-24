#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;

#[map(name = "syscalls_total")]
static SYSCALLS_TOTAL: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[btf_tracepoint(function = "sys_enter")]
pub fn sys_enter(ctx: BtfTracePointContext) -> i32 {
    let id: u64 = ctx.arg(1);
    increment_map(&id, 1);
    0
}

#[inline(always)]
fn increment_map(key: &u64, increment: u64) -> u64 {
    let count_ptr = SYSCALLS_TOTAL.get_ptr_mut(key);
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
            let _ = SYSCALLS_TOTAL.insert(key, &zero, 1);
            let count_ptr2 = SYSCALLS_TOTAL.get_ptr_mut(key);
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
