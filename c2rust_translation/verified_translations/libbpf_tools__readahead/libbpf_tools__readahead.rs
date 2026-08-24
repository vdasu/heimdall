#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;

const MAX_ENTRIES: u32 = 10240;
const MAX_SLOTS: usize = 20;

#[repr(C)]
struct Hist {
    unused: u32,
    total: u32,
    slots: [u32; MAX_SLOTS],
}

#[map(name = "in_readahead")]
static IN_READAHEAD: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "birth")]
static BIRTH: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
#[link_section = ".bss"]
static HIST: Hist = Hist {
    unused: 0,
    total: 0,
    slots: [0; MAX_SLOTS],
};

#[inline(always)]
fn log2_u32(v: u32) -> u32 {
    let mut v = v;
    let mut r: u32 = if v > 0xFFFF { 1 } else { 0 };
    r <<= 4;
    v >>= r;
    let mut shift: u32 = if v > 0xFF { 1 } else { 0 };
    shift <<= 3;
    v >>= shift;
    r |= shift;
    shift = if v > 0xF { 1 } else { 0 };
    shift <<= 2;
    v >>= shift;
    r |= shift;
    shift = if v > 0x3 { 1 } else { 0 };
    shift <<= 1;
    v >>= shift;
    r |= shift;
    r |= v >> 1;
    r
}

#[inline(always)]
fn log2l_u64(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi) as u64 + 32
    } else {
        log2_u32(v as u32) as u64
    }
}

#[inline(always)]
fn alloc_done(page: u64) -> i32 {
    let pid = bpf_get_current_pid_tgid() as u32;

    // SAFETY: looking up key in hash map
    if unsafe { IN_READAHEAD.get(&pid) }.is_none() {
        return 0;
    }

    // SAFETY: calling bpf_ktime_get_ns helper
    let ts = unsafe { bpf_ktime_get_ns() };
    BIRTH.insert(&page, &ts, 0).ok();

    let unused_ptr = core::ptr::addr_of!(HIST.unused) as *mut u32;
    // SAFETY: creating atomic from valid BSS-section pointer to hist.unused
    let unused_atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(unused_ptr) };
    unused_atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let total_ptr = core::ptr::addr_of!(HIST.total) as *mut u32;
    // SAFETY: creating atomic from valid BSS-section pointer to hist.total
    let total_atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(total_ptr) };
    total_atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    0
}

#[inline(always)]
fn mark_accessed(page: u64) -> i32 {
    // SAFETY: calling bpf_ktime_get_ns helper
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: looking up key in hash map
    let tsp = match unsafe { BIRTH.get(&page) } {
        Some(v) => *v,
        None => return 0,
    };

    let delta = ts.wrapping_sub(tsp) as i64;
    if delta >= 0 {
        let slot = log2l_u64(delta as u64 / 1000000u64);
        let slot = if slot >= MAX_SLOTS as u64 {
            MAX_SLOTS as u64 - 1
        } else {
            slot
        };

        let slots_ptr = core::ptr::addr_of!(HIST.slots) as *mut u32;
        // SAFETY: computing pointer to slot within valid hist.slots array
        let slot_ptr = unsafe { slots_ptr.add(slot as usize) };
        // SAFETY: creating atomic from valid BSS-section pointer
        let slot_atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(slot_ptr) };
        slot_atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    let unused_ptr = core::ptr::addr_of!(HIST.unused) as *mut u32;
    // SAFETY: creating atomic from valid BSS-section pointer to hist.unused
    let unused_atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(unused_ptr) };
    unused_atomic.fetch_add((-1i32) as u32, core::sync::atomic::Ordering::Relaxed);

    BIRTH.remove(&page).ok();

    0
}

#[fentry(function = "do_page_cache_ra")]
pub fn do_page_cache_ra(_ctx: FEntryContext) -> i32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    let one: u64 = 1;
    IN_READAHEAD.insert(&pid, &one, 0).ok();
    0
}

#[fexit(function = "__page_cache_alloc")]
pub fn page_cache_alloc_ret(ctx: FExitContext) -> i32 {
    let page: u64 = ctx.arg(1);
    alloc_done(page)
}

#[fexit(function = "filemap_alloc_folio")]
pub fn filemap_alloc_folio_ret(ctx: FExitContext) -> i32 {
    let folio: u64 = ctx.arg(2);
    alloc_done(folio)
}

#[fexit(function = "filemap_alloc_folio_noprof")]
pub fn filemap_alloc_folio_noprof_ret(ctx: FExitContext) -> i32 {
    let folio: u64 = ctx.arg(2);
    alloc_done(folio)
}

#[fexit(function = "do_page_cache_ra")]
pub fn do_page_cache_ra_ret(_ctx: FExitContext) -> i32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    IN_READAHEAD.remove(&pid).ok();
    0
}

#[fentry(function = "folio_mark_accessed")]
pub fn folio_mark_accessed(ctx: FEntryContext) -> i32 {
    let folio: u64 = ctx.arg(0);
    mark_accessed(folio)
}

#[fentry(function = "mark_page_accessed")]
pub fn mark_page_accessed(ctx: FEntryContext) -> i32 {
    let page: u64 = ctx.arg(0);
    mark_accessed(page)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
