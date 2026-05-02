#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use core::sync::atomic::{AtomicU64, Ordering};

// ── Maps ─────────────────────────────────────────────────────────────

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

// ── Globals (.bss) ───────────────────────────────────────────────────

#[no_mangle]
#[link_section = ".bss"]
static latency: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
#[link_section = ".bss"]
static num: AtomicU64 = AtomicU64::new(0);

// ── Shared logic ─────────────────────────────────────────────────────

#[inline(always)]
fn migrate_misplaced_enter() -> i32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: bpf_ktime_get_ns is a BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&pid, &ts, 0);
    0
}

#[inline(always)]
fn migrate_misplaced_exit_impl() -> i32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: bpf_ktime_get_ns is a BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: HashMap::get requires unsafe in this Aya version
    let tsp = match unsafe { START.get(&pid) } {
        Some(v) => *v,
        None => return 0,
    };

    let delta = ts.wrapping_sub(tsp) as i64;
    if delta >= 0 {
        latency.fetch_add((delta / 1000000) as u64, Ordering::Relaxed);
        num.fetch_add(1, Ordering::Relaxed);
    }

    let _ = START.remove(&pid);
    0
}

// ── fentry entry points ─────────────────────────────────────────────

#[fentry(function = "migrate_misplaced_page")]
pub fn fentry_migrate_misplaced_page(_ctx: FEntryContext) -> i32 {
    migrate_misplaced_enter()
}

#[fentry(function = "migrate_misplaced_folio")]
pub fn fentry_migrate_misplaced_folio(_ctx: FEntryContext) -> i32 {
    migrate_misplaced_enter()
}

// ── kprobe entry points ─────────────────────────────────────────────

#[kprobe(function = "migrate_misplaced_page")]
pub fn kprobe_migrate_misplaced_page(_ctx: ProbeContext) -> u32 {
    migrate_misplaced_enter() as u32
}

#[kprobe(function = "migrate_misplaced_folio")]
pub fn kprobe_migrate_misplaced_folio(_ctx: ProbeContext) -> u32 {
    migrate_misplaced_enter() as u32
}

// ── fexit entry points ──────────────────────────────────────────────

#[fexit(function = "migrate_misplaced_page")]
pub fn fexit_migrate_misplaced_page_exit(_ctx: FExitContext) -> i32 {
    migrate_misplaced_exit_impl()
}

#[fexit(function = "migrate_misplaced_folio")]
pub fn fexit_migrate_misplaced_folio_exit(_ctx: FExitContext) -> i32 {
    migrate_misplaced_exit_impl()
}

// ── kretprobe entry points ──────────────────────────────────────────

#[kretprobe(function = "migrate_misplaced_page")]
pub fn kretprobe_migrate_misplaced_page_exit(_ctx: RetProbeContext) -> u32 {
    migrate_misplaced_exit_impl() as u32
}

#[kretprobe(function = "migrate_misplaced_folio")]
pub fn kretprobe_migrate_misplaced_folio_exit(_ctx: RetProbeContext) -> u32 {
    migrate_misplaced_exit_impl() as u32
}

// ── Boilerplate ──────────────────────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
