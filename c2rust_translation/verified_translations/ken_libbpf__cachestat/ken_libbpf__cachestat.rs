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

#[map(name = "page_cache_ops_total")]
static PAGE_CACHE_OPS_TOTAL: HashMap<u64, u64> = HashMap::with_max_entries(4, 0);

#[inline(always)]
fn try_kprobe(ctx: &ProbeContext) -> Result<i32, i32> {
    // Read IP from pt_regs at offset 128 (x86_64 ip field)
    let ctx_ptr = ctx.as_ptr() as *const u8;
    let ip_ptr = ctx_ptr.wrapping_add(128) as *const u64;
    // SAFETY: reading IP field from pt_regs via bpf_probe_read_kernel
    let ip: u64 = unsafe { bpf_probe_read_kernel(ip_ptr) }.map_err(|_| 0i32)?;
    let ip = ip - 1; // KPROBE_REGS_IP_FIX for x86

    // increment_map logic
    // SAFETY: looking up key in BPF hash map
    let val = unsafe { PAGE_CACHE_OPS_TOTAL.get(&ip) };
    if val.is_none() {
        let zero: u64 = 0;
        let _ = PAGE_CACHE_OPS_TOTAL.insert(&ip, &zero, 1); // BPF_NOEXIST
        // SAFETY: looking up key in BPF hash map after insert
        let val2 = unsafe { PAGE_CACHE_OPS_TOTAL.get(&ip) };
        if let Some(v) = val2 {
            let ptr = v as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map pointer for atomic increment
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    } else if let Some(v) = val {
        let ptr = v as *const u64 as *mut u64;
        // SAFETY: creating atomic from valid map pointer for atomic increment
        let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
        atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    Ok(0)
}

#[kprobe]
pub fn add_to_page_cache_lru(ctx: ProbeContext) -> u32 {
    match try_kprobe(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[kprobe]
pub fn mark_page_accessed(ctx: ProbeContext) -> u32 {
    match try_kprobe(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[kprobe]
pub fn folio_account_dirtied(ctx: ProbeContext) -> u32 {
    match try_kprobe(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[kprobe]
pub fn mark_buffer_dirty(ctx: ProbeContext) -> u32 {
    match try_kprobe(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
