#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;

const MAX_LATENCY_SLOT: u64 = 26;

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "shrink_node_latency_seconds")]
static SHRINK_NODE_LATENCY_SECONDS: Array<u64> = Array::with_max_entries(27, 0);

#[kprobe]
pub fn shrink_node_enter(_ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: calling BPF helper to get timestamp
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&pid, &ts, 0);
    0
}

#[kretprobe]
pub fn shrink_node_exit(_ctx: RetProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;

    // SAFETY: looking up key in hash map
    let tsp = unsafe { START.get(&pid) };
    if let Some(tsp_ref) = tsp {
        let tsp_val = *tsp_ref;

        let now = // SAFETY: calling BPF helper to get timestamp
            unsafe { bpf_ktime_get_ns() };
        let latency_us = (now - tsp_val) / 1000;

        let mut latency_slot = log2l(latency_us);

        if latency_slot > MAX_LATENCY_SLOT {
            latency_slot = MAX_LATENCY_SLOT;
        }

        increment_array(latency_slot as u32, 1);

        let total_slot = (MAX_LATENCY_SLOT + 1) as u32;
        increment_array(total_slot, latency_us);

        let _ = START.remove(&pid);
    }

    0
}

#[inline(always)]
fn log2(v: u32) -> u64 {
    let mut v = v;
    let r_init = if v > 0xFFFF { 1u32 } else { 0u32 };
    let mut r = r_init << 4;
    v >>= r;
    let s1 = (if v > 0xFF { 1u32 } else { 0u32 }) << 3;
    v >>= s1;
    r |= s1;
    let s2 = (if v > 0xF { 1u32 } else { 0u32 }) << 2;
    v >>= s2;
    r |= s2;
    let s3 = (if v > 0x3 { 1u32 } else { 0u32 }) << 1;
    v >>= s3;
    r |= s3;
    r |= v >> 1;
    r as u64
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2(hi) + 32
    } else {
        log2(v as u32)
    }
}

#[inline(always)]
fn increment_array(index: u32, increment: u64) -> u64 {
    match SHRINK_NODE_LATENCY_SECONDS.get_ptr_mut(index) {
        Some(ptr) => {
            // SAFETY: creating atomic from valid map pointer
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            // SAFETY: reading value from valid map pointer after atomic add
            unsafe { *ptr }
        }
        None => {
            0
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
