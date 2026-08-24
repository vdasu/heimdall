#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicU32, Ordering};

const MAX_ENTRIES: u32 = 10240;
const MAX_SLOTS: u32 = 32;
const F_READ: u32 = 0;
const F_WRITE: u32 = 1;
const F_OPEN: u32 = 2;
const F_FSYNC: u32 = 3;
const F_GETATTR: u32 = 4;
const F_MAX_OP: u32 = 5;

#[repr(C)]
struct Hist {
    slots: [AtomicU32; 32],
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

#[no_mangle]
static in_ms: Global<u8> = Global::new(0);

#[map(name = "starts")]
static STARTS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
static hists: [Hist; 5] = [const { Hist { slots: [const { AtomicU32::new(0) }; 32] } }; 5];

#[inline(always)]
fn log2_32(v: u32) -> u32 {
    let mut v = v;
    let r = (v > 0xFFFF) as u32;
    let mut result = r << 4;
    v >>= result;
    let shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    result |= shift;
    let shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    result |= shift;
    let shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    result |= shift;
    result |= v >> 1;
    result
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        (log2_32(hi) + 32) as u64
    } else {
        log2_32(v as u32) as u64
    }
}

#[inline(always)]
fn probe_entry() -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let targ_pid = target_pid.load();
    if targ_pid != 0 && targ_pid as u32 != pid {
        return 0;
    }

    // SAFETY: bpf_ktime_get_ns is an unsafe helper binding
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = STARTS.insert(&tid, &ts, 0);
    0
}

#[inline(always)]
fn probe_return(op: u32) -> i32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: bpf_ktime_get_ns is an unsafe helper binding
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let tsp = match unsafe { STARTS.get(&tid) } {
        Some(v) => *v,
        None => return 0,
    };

    if op >= F_MAX_OP {
        let _ = STARTS.remove(&tid);
        return 0;
    }

    let delta = ts.wrapping_sub(tsp) as i64;
    if delta < 0 {
        let _ = STARTS.remove(&tid);
        return 0;
    }

    let delta = if in_ms.load() != 0 {
        delta / 1000000
    } else {
        delta / 1000
    };

    let mut slot = log2l(delta as u64);
    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    if let Some(hist) = hists.get(op as usize) {
        if let Some(slot_atomic) = hist.slots.get(slot as usize) {
            slot_atomic.fetch_add(1, Ordering::Relaxed);
        }
    }

    let _ = STARTS.remove(&tid);
    0
}

#[kprobe]
pub fn file_read_entry(_ctx: ProbeContext) -> u32 {
    probe_entry() as u32
}

#[kretprobe]
pub fn file_read_exit(_ctx: RetProbeContext) -> u32 {
    probe_return(F_READ) as u32
}

#[kprobe]
pub fn file_write_entry(_ctx: ProbeContext) -> u32 {
    probe_entry() as u32
}

#[kretprobe]
pub fn file_write_exit(_ctx: RetProbeContext) -> u32 {
    probe_return(F_WRITE) as u32
}

#[kprobe]
pub fn file_open_entry(_ctx: ProbeContext) -> u32 {
    probe_entry() as u32
}

#[kretprobe]
pub fn file_open_exit(_ctx: RetProbeContext) -> u32 {
    probe_return(F_OPEN) as u32
}

#[kprobe]
pub fn file_sync_entry(_ctx: ProbeContext) -> u32 {
    probe_entry() as u32
}

#[kretprobe]
pub fn file_sync_exit(_ctx: RetProbeContext) -> u32 {
    probe_return(F_FSYNC) as u32
}

#[kprobe]
pub fn getattr_entry(_ctx: ProbeContext) -> u32 {
    probe_entry() as u32
}

#[kretprobe]
pub fn getattr_exit(_ctx: RetProbeContext) -> u32 {
    probe_return(F_GETATTR) as u32
}

#[fentry(function = "dummy_file_read")]
pub fn file_read_fentry(_ctx: FEntryContext) -> i32 {
    probe_entry()
}

#[fexit(function = "dummy_file_read")]
pub fn file_read_fexit(_ctx: FExitContext) -> i32 {
    probe_return(F_READ)
}

#[fentry(function = "dummy_file_write")]
pub fn file_write_fentry(_ctx: FEntryContext) -> i32 {
    probe_entry()
}

#[fexit(function = "dummy_file_write")]
pub fn file_write_fexit(_ctx: FExitContext) -> i32 {
    probe_return(F_WRITE)
}

#[fentry(function = "dummy_file_open")]
pub fn file_open_fentry(_ctx: FEntryContext) -> i32 {
    probe_entry()
}

#[fexit(function = "dummy_file_open")]
pub fn file_open_fexit(_ctx: FExitContext) -> i32 {
    probe_return(F_OPEN)
}

#[fentry(function = "dummy_file_sync")]
pub fn file_sync_fentry(_ctx: FEntryContext) -> i32 {
    probe_entry()
}

#[fexit(function = "dummy_file_sync")]
pub fn file_sync_fexit(_ctx: FExitContext) -> i32 {
    probe_return(F_FSYNC)
}

#[fentry(function = "dummy_getattr")]
pub fn getattr_fentry(_ctx: FEntryContext) -> i32 {
    probe_entry()
}

#[fexit(function = "dummy_getattr")]
pub fn getattr_fexit(_ctx: FExitContext) -> i32 {
    probe_return(F_GETATTR)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
