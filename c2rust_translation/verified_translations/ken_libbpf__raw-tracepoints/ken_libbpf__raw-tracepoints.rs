#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::EbpfContext;

#[map(name = "raw_timer_starts_total")]
static RAW_TIMER_STARTS_TOTAL: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[raw_tracepoint(tracepoint = "timer_start")]
pub fn do_count(ctx: RawTracePointContext) -> i32 {
    match try_do_count(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_do_count(ctx: RawTracePointContext) -> Result<i32, i64> {
    // Read args[0] from raw tracepoint context - the timer_list pointer
    // SAFETY: reading args[0] from raw tracepoint context pointer
    let timer_ptr = unsafe { *(ctx.as_ptr() as *const u64) };

    // BPF_CORE_READ(timer, function) - read function field at offset 24
    let func_ptr = (timer_ptr as *const u8).wrapping_add(24) as *const u64;
    // SAFETY: reading function field from timer_list via probe_read_kernel
    let function: u64 = unsafe { bpf_probe_read_kernel(func_ptr)? };

    increment_map(&function, 1);
    Ok(0)
}

#[inline(always)]
fn increment_map(key: &u64, increment: u64) -> u64 {
    let count_ptr = RAW_TIMER_STARTS_TOTAL.get_ptr_mut(key);
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
            let _ = RAW_TIMER_STARTS_TOTAL.insert(key, &zero, 1);
            let count_ptr2 = RAW_TIMER_STARTS_TOTAL.get_ptr_mut(key);
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
