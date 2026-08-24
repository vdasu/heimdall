#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;

#[map(name = "libc_malloc_calls_total")]
static LIBC_MALLOC_CALLS_TOTAL: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[inline(always)]
fn increment_map(key: &u64, increment: u64) {
    // SAFETY: looking up key in valid BPF hash map
    let lookup = unsafe { LIBC_MALLOC_CALLS_TOTAL.get(key) };
    match lookup {
        Some(count) => {
            let ptr = count as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map value pointer returned by map lookup
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = LIBC_MALLOC_CALLS_TOTAL.insert(key, &zero, 1); // BPF_NOEXIST
            // SAFETY: looking up key in valid BPF hash map after insert
            let lookup2 = unsafe { LIBC_MALLOC_CALLS_TOTAL.get(key) };
            if let Some(count) = lookup2 {
                let ptr = count as *const u64 as *mut u64;
                // SAFETY: creating atomic from valid map value pointer returned by map lookup
                let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
                atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[uprobe]
pub fn do_count(_ctx: ProbeContext) -> u32 {
    // SAFETY: calling BPF helper to get current cgroup ID
    let cgroup_id: u64 = unsafe { bpf_get_current_cgroup_id() };
    increment_map(&cgroup_id, 1);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
