#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;

#[map(name = "timer_starts_total")]
static TIMER_STARTS_TOTAL: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[inline(always)]
fn increment_map(key: &u64, increment: u64) {
    // SAFETY: looking up key in valid BPF hash map
    let lookup = unsafe { TIMER_STARTS_TOTAL.get(key) };
    match lookup {
        Some(count) => {
            let ptr = count as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map value pointer returned by map lookup
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = TIMER_STARTS_TOTAL.insert(key, &zero, 1); // BPF_NOEXIST
            // SAFETY: looking up key in valid BPF hash map after insert
            let lookup2 = unsafe { TIMER_STARTS_TOTAL.get(key) };
            if let Some(count) = lookup2 {
                let ptr = count as *const u64 as *mut u64;
                // SAFETY: creating atomic from valid map value pointer returned by map lookup
                let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
                atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[btf_tracepoint(function = "timer_start")]
pub fn timer_start(ctx: BtfTracePointContext) -> i32 {
    let timer: u64 = ctx.arg(0);
    // SAFETY: reading timer->function field at offset 24 from kernel pointer
    let function: u64 = unsafe { *((timer + 24) as *const u64) };
    increment_map(&function, 1);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
