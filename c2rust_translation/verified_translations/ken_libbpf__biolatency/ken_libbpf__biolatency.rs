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
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_LATENCY_SLOT: u64 = 27;
const MAX_DISKS: u32 = 255;

#[repr(C)]
#[derive(Copy, Clone)]
struct DiskLatencyKey {
    dev: u32,
    op: u8,
    slot: u64,
}

#[no_mangle]
static LINUX_KERNEL_VERSION: Global<i32> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u64, u64> = HashMap::with_max_entries(10000, 0);

#[map(name = "bio_latency_seconds")]
static BIO_LATENCY_SECONDS: HashMap<DiskLatencyKey, u64> =
    HashMap::with_max_entries((MAX_LATENCY_SLOT as u32 + 1) * MAX_DISKS, 0);

#[inline(always)]
fn log2_u32(v: u32) -> u64 {
    let mut v = v;
    let r = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let mut result = r;
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
    result as u64
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
fn increment_map(key: &DiskLatencyKey, increment: u64) {
    match BIO_LATENCY_SECONDS.get_ptr_mut(key) {
        Some(ptr) => {
            // SAFETY: creating atomic from valid map pointer for fetch_add
            let atomic = unsafe { AtomicU64::from_ptr(ptr as *mut u64) };
            atomic.fetch_add(increment, Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = BIO_LATENCY_SECONDS.insert(key, &zero, 1);
            if let Some(ptr) = BIO_LATENCY_SECONDS.get_ptr_mut(key) {
                // SAFETY: creating atomic from valid map pointer for fetch_add
                let atomic = unsafe { AtomicU64::from_ptr(ptr as *mut u64) };
                atomic.fetch_add(increment, Ordering::Relaxed);
            }
        }
    }
}

#[inline(always)]
fn trace_rq_start(rq: u64) -> i32 {
    // SAFETY: bpf_ktime_get_ns is an unsafe helper
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&rq, &ts, 0);
    0
}

#[raw_tracepoint(tracepoint = "block_rq_insert")]
pub fn block_rq_insert(ctx: RawTracePointContext) -> i32 {
    let version = LINUX_KERNEL_VERSION.load();
    if version < ((5i32 << 16) | (11i32 << 8)) {
        let rq: u64 = ctx.arg(1);
        trace_rq_start(rq)
    } else {
        let rq: u64 = ctx.arg(0);
        trace_rq_start(rq)
    }
}

#[raw_tracepoint(tracepoint = "block_rq_issue")]
pub fn block_rq_issue(ctx: RawTracePointContext) -> i32 {
    let version = LINUX_KERNEL_VERSION.load();
    if version < ((5i32 << 16) | (11i32 << 8)) {
        let rq: u64 = ctx.arg(1);
        trace_rq_start(rq)
    } else {
        let rq: u64 = ctx.arg(0);
        trace_rq_start(rq)
    }
}

#[raw_tracepoint(tracepoint = "block_rq_complete")]
pub fn block_rq_complete(ctx: RawTracePointContext) -> i32 {
    let rq: u64 = ctx.arg(0);

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let tsp = match unsafe { START.get(&rq) } {
        Some(ts) => *ts,
        None => return 0,
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe helper
    let now = unsafe { bpf_ktime_get_ns() };
    let delta_us = (now - tsp) / 1000;

    let mut latency_slot = log2l(delta_us);
    if latency_slot > MAX_LATENCY_SLOT {
        latency_slot = MAX_LATENCY_SLOT;
    }

    // SAFETY: reading rq_disk pointer from struct request (CO-RE offset 8)
    let disk: u64 = unsafe {
        bpf_probe_read_kernel((rq as *const u8).add(8) as *const u64)
    }
    .unwrap_or(0);

    // SAFETY: reading cmd_flags from struct request (offset 24)
    let flags: u32 = unsafe {
        bpf_probe_read_kernel((rq as *const u8).add(24) as *const u32)
    }
    .unwrap_or(0);

    let dev: u32 = if disk != 0 {
        // SAFETY: reading first_minor from gendisk (offset 4)
        let first_minor: u32 = unsafe {
            bpf_probe_read_kernel((disk as *const u8).add(4) as *const u32)
        }
        .unwrap_or(0);
        // SAFETY: reading major from gendisk (offset 0)
        let major: u32 = unsafe {
            bpf_probe_read_kernel((disk as *const u8).add(0) as *const u32)
        }
        .unwrap_or(0);
        // SAFETY: reading first_minor again (matches C binary register spill pattern)
        let first_minor_2: u32 = unsafe {
            bpf_probe_read_kernel((disk as *const u8).add(4) as *const u32)
        }
        .unwrap_or(0);
        (first_minor & 0xff) | (major << 8) | ((first_minor_2 & !0xffu32) << 12)
    } else {
        0
    };

    let op = (flags & 0xFF) as u8;

    // SAFETY: DiskLatencyKey is repr(C) with integer fields; all-zeros is valid
    let mut latency_key: DiskLatencyKey = unsafe { core::mem::zeroed() };
    latency_key.slot = latency_slot;
    latency_key.dev = dev;
    latency_key.op = op;

    increment_map(&latency_key, 1);

    latency_key.slot = MAX_LATENCY_SLOT + 1;
    increment_map(&latency_key, delta_us);

    let _ = START.remove(&rq);

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
