#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::programs::*;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[no_mangle]
static total: AtomicI64 = AtomicI64::new(0);
#[no_mangle]
static misses: AtomicI64 = AtomicI64::new(0);
#[no_mangle]
static mbd: AtomicU64 = AtomicU64::new(0);

// ── fentry entry points ──────────────────────────────────────────────

#[fentry(function = "add_to_page_cache_lru")]
pub fn fentry_add_to_page_cache_lru(_ctx: FEntryContext) -> i32 {
    misses.fetch_add(1, Ordering::Relaxed);
    0
}

#[fentry(function = "mark_page_accessed")]
pub fn fentry_mark_page_accessed(_ctx: FEntryContext) -> i32 {
    total.fetch_add(1, Ordering::Relaxed);
    0
}

#[fentry(function = "account_page_dirtied")]
pub fn fentry_account_page_dirtied(_ctx: FEntryContext) -> i32 {
    misses.fetch_add(-1, Ordering::Relaxed);
    0
}

#[fentry(function = "mark_buffer_dirty")]
pub fn fentry_mark_buffer_dirty(_ctx: FEntryContext) -> i32 {
    total.fetch_add(-1, Ordering::Relaxed);
    mbd.fetch_add(1, Ordering::Relaxed);
    0
}

// ── kprobe entry points ──────────────────────────────────────────────

#[kprobe]
pub fn kprobe_add_to_page_cache_lru(_ctx: ProbeContext) -> u32 {
    misses.fetch_add(1, Ordering::Relaxed);
    0
}

#[kprobe]
pub fn kprobe_mark_page_accessed(_ctx: ProbeContext) -> u32 {
    total.fetch_add(1, Ordering::Relaxed);
    0
}

#[kprobe]
pub fn kprobe_account_page_dirtied(_ctx: ProbeContext) -> u32 {
    misses.fetch_add(-1, Ordering::Relaxed);
    0
}

#[kprobe]
pub fn kprobe_folio_account_dirtied(_ctx: ProbeContext) -> u32 {
    misses.fetch_add(-1, Ordering::Relaxed);
    0
}

#[kprobe]
pub fn kprobe_mark_buffer_dirty(_ctx: ProbeContext) -> u32 {
    total.fetch_add(-1, Ordering::Relaxed);
    mbd.fetch_add(1, Ordering::Relaxed);
    0
}

// ── tracepoint entry points ─────────────────────────────────────────

#[tracepoint]
pub fn tracepoint__writeback_dirty_folio(_ctx: TracePointContext) -> i32 {
    misses.fetch_add(-1, Ordering::Relaxed);
    0
}

#[tracepoint]
pub fn tracepoint__writeback_dirty_page(_ctx: TracePointContext) -> i32 {
    misses.fetch_add(-1, Ordering::Relaxed);
    0
}

// ── Boilerplate ─────────────────────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
