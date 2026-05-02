#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::{BtfTracePointContext, RawTracePointContext};
use aya_ebpf::{EbpfContext, Global};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const NR_SOFTIRQS: usize = 10;
const MAX_SLOTS: usize = 20;

#[repr(C)]
struct Hist {
    slots: [AtomicU32; MAX_SLOTS],
}

#[no_mangle]
static targ_dist: Global<u8> = Global::new(0);

#[no_mangle]
static targ_ns: Global<u8> = Global::new(0);

#[no_mangle]
static targ_cpu: Global<i32> = Global::new(-1);

#[map(name = "start")]
static START: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[no_mangle]
#[link_section = ".bss"]
static counts: [AtomicU64; NR_SOFTIRQS] = [const { AtomicU64::new(0) }; NR_SOFTIRQS];

#[no_mangle]
#[link_section = ".bss"]
static time: [AtomicU64; NR_SOFTIRQS] = [const { AtomicU64::new(0) }; NR_SOFTIRQS];

#[no_mangle]
#[link_section = ".bss"]
static hists: [Hist; NR_SOFTIRQS] = [const { Hist { slots: [const { AtomicU32::new(0) }; MAX_SLOTS] } }; NR_SOFTIRQS];

#[inline(always)]
fn is_target_cpu() -> bool {
    let cpu = targ_cpu.load();
    if cpu < 0 {
        return true;
    }
    // SAFETY: bpf_get_smp_processor_id is an unsafe BPF helper binding
    let current_cpu = unsafe { bpf_get_smp_processor_id() };
    current_cpu == cpu as u32
}

#[inline(always)]
fn log2_u32(v: u32) -> u64 {
    let mut v = v;
    let r = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    let r = r | shift;
    let shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    let r = r | shift;
    let shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    let r = r | shift;
    (r | (v >> 1)) as u64
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi) + 32
    } else {
        log2_u32(v as u32)
    }
}

#[inline(always)]
fn handle_entry(_vec_nr: u32) -> i32 {
    if !is_target_cpu() {
        return 0;
    }
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    let ts = unsafe { bpf_ktime_get_ns() };
    let key: u32 = 0;
    if let Some(ptr) = START.get_ptr_mut(key) {
        // SAFETY: writing timestamp to valid percpu array pointer
        unsafe { *ptr = ts };
    }
    0
}

#[inline(always)]
fn handle_exit(vec_nr: u32) -> i32 {
    if !is_target_cpu() {
        return 0;
    }
    if vec_nr as usize >= NR_SOFTIRQS {
        return 0;
    }
    let key: u32 = 0;
    let tsp = match START.get_ptr(key) {
        Some(ptr) => {
            // SAFETY: reading timestamp from valid percpu array pointer
            unsafe { *ptr }
        }
        None => return 0,
    };
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    let mut delta = unsafe { bpf_ktime_get_ns() } - tsp;
    if targ_ns.load() == 0 {
        delta /= 1000;
    }

    if targ_dist.load() == 0 {
        // SAFETY: index checked above (vec_nr < NR_SOFTIRQS)
        let c = unsafe { counts.get_unchecked(vec_nr as usize) };
        c.fetch_add(1, Ordering::Relaxed);
        // SAFETY: index checked above (vec_nr < NR_SOFTIRQS)
        let t = unsafe { time.get_unchecked(vec_nr as usize) };
        t.fetch_add(delta, Ordering::Relaxed);
    } else {
        let slot = log2l(delta);
        let slot = if slot >= MAX_SLOTS as u64 { MAX_SLOTS as u64 - 1 } else { slot };
        // SAFETY: index checked above (vec_nr < NR_SOFTIRQS)
        let h = unsafe { hists.get_unchecked(vec_nr as usize) };
        // SAFETY: slot is clamped to MAX_SLOTS - 1
        let s = unsafe { h.slots.get_unchecked(slot as usize) };
        s.fetch_add(1, Ordering::Relaxed);
    }

    0
}

#[btf_tracepoint(function = "softirq_entry")]
pub fn softirq_entry_btf(ctx: BtfTracePointContext) -> i32 {
    let vec_nr: u32 = ctx.arg(0);
    handle_entry(vec_nr)
}

#[btf_tracepoint(function = "softirq_exit")]
pub fn softirq_exit_btf(ctx: BtfTracePointContext) -> i32 {
    let vec_nr: u32 = ctx.arg(0);
    handle_exit(vec_nr)
}

#[raw_tracepoint(tracepoint = "softirq_entry")]
pub fn softirq_entry(ctx: RawTracePointContext) -> i32 {
    // SAFETY: reading first raw tracepoint argument at offset 0
    let vec_nr = unsafe { *(ctx.as_ptr() as *const u64) } as u32;
    handle_entry(vec_nr)
}

#[raw_tracepoint(tracepoint = "softirq_exit")]
pub fn softirq_exit(ctx: RawTracePointContext) -> i32 {
    // SAFETY: reading first raw tracepoint argument at offset 0
    let vec_nr = unsafe { *(ctx.as_ptr() as *const u64) } as u32;
    handle_exit(vec_nr)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
