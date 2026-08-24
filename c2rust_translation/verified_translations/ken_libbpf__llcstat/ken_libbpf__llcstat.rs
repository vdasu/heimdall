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
use aya_ebpf::EbpfContext;

const MAX_CPUS: u32 = 512;

#[map(name = "llc_references_total")]
static LLC_REFERENCES_TOTAL: HashMap<u32, u64> = HashMap::with_max_entries(MAX_CPUS, 0);

#[map(name = "llc_misses_total")]
static LLC_MISSES_TOTAL: HashMap<u32, u64> = HashMap::with_max_entries(MAX_CPUS, 0);

#[inline(always)]
fn increment_map(map: &HashMap<u32, u64>, key: &u32, increment: u64) -> i32 {
    let zero: u64 = 0;
    // SAFETY: looking up key in valid BPF hash map
    let count = unsafe { map.get(key) };
    if count.is_none() {
        let _ = map.insert(key, &zero, 1); // BPF_NOEXIST
        // SAFETY: looking up key in valid BPF hash map after insert
        let count2 = unsafe { map.get(key) };
        if let Some(val_ref) = count2 {
            // SAFETY: creating atomic from valid map pointer to perform fetch_add
            let atomic = unsafe {
                core::sync::atomic::AtomicU64::from_ptr(val_ref as *const u64 as *mut u64)
            };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            return *val_ref as i32;
        }
        return 0;
    }
    let val_ref = count.unwrap();
    // SAFETY: creating atomic from valid map pointer to perform fetch_add
    let atomic = unsafe {
        core::sync::atomic::AtomicU64::from_ptr(val_ref as *const u64 as *mut u64)
    };
    atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
    *val_ref as i32
}

#[no_mangle]
#[link_section = "perf_event/type=0,config=3,frequency=1"]
pub fn on_cache_miss(ctx: *mut c_void) -> i32 {
    let perf_ctx = PerfEventContext::new(ctx as *mut _);
    // SAFETY: calling BPF helper to get current CPU ID
    let cpu = unsafe { bpf_get_smp_processor_id() };
    // SAFETY: reading sample_period at offset 168 from valid perf_event context pointer
    let sample_period: u64 = unsafe { *(perf_ctx.as_ptr().byte_add(168) as *const u64) };
    increment_map(&LLC_MISSES_TOTAL, &cpu, sample_period);
    0
}

#[no_mangle]
#[link_section = "perf_event/type=0,config=2,frequency=1"]
pub fn on_cache_reference(ctx: *mut c_void) -> i32 {
    let perf_ctx = PerfEventContext::new(ctx as *mut _);
    // SAFETY: calling BPF helper to get current CPU ID
    let cpu = unsafe { bpf_get_smp_processor_id() };
    // SAFETY: reading sample_period at offset 168 from valid perf_event context pointer
    let sample_period: u64 = unsafe { *(perf_ctx.as_ptr().byte_add(168) as *const u64) };
    increment_map(&LLC_REFERENCES_TOTAL, &cpu, sample_period);
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
