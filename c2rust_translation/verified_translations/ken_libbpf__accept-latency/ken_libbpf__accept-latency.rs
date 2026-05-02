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

const MAX_LATENCY_SLOT: u64 = 26;

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketLatencyKey {
    port: u16,
    _pad: [u8; 6],
    slot: u64,
}

/// Matches the 80-byte probe_read of icsk_accept_queue in the C binary.
/// rskq_accept_head is at offset 24 within this struct.
#[repr(C)]
#[derive(Clone, Copy)]
struct IcskAcceptQueueBuf {
    _before: [u8; 24],
    rskq_accept_head: u64,
    _after: [u8; 48],
}

/// Matches the 136-byte probe_read of sock_common in the C binary.
/// skc_num is at offset 14 within this struct.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockCommonBuf {
    _before: [u8; 14],
    skc_num: u16,
    _after: [u8; 120],
}

#[map(name = "start")]
static START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "accept_latency_seconds")]
static ACCEPT_LATENCY_SECONDS: HashMap<SocketLatencyKey, u64> =
    HashMap::with_max_entries((MAX_LATENCY_SLOT as u32 + 1) * 1024, 0);

#[inline(always)]
fn log2(v: u32) -> u64 {
    let mut v = v;
    let mut r: u32;
    r = if v > 0xFFFF { 1u32 } else { 0u32 } << 4;
    v >>= r;
    let shift = if v > 0xFF { 1u32 } else { 0u32 } << 3;
    v >>= shift;
    r |= shift;
    let shift = if v > 0xF { 1u32 } else { 0u32 } << 2;
    v >>= shift;
    r |= shift;
    let shift = if v > 0x3 { 1u32 } else { 0u32 } << 1;
    v >>= shift;
    r |= shift;
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
fn increment_map(map: &HashMap<SocketLatencyKey, u64>, key: &SocketLatencyKey, increment: u64) {
    // SAFETY: map lookup on valid HashMap
    let lookup = unsafe { map.get(key) };
    match lookup {
        Some(count) => {
            let ptr = count as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map pointer returned by lookup
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = map.insert(key, &zero, 2); // BPF_NOEXIST = 2
            // SAFETY: map lookup on valid HashMap
            if let Some(count) = unsafe { map.get(key) } {
                let ptr = count as *const u64 as *mut u64;
                // SAFETY: creating atomic from valid map pointer returned by lookup
                let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
                atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[kprobe]
pub fn kprobe__inet_csk_reqsk_queue_hash_add(ctx: ProbeContext) -> u32 {
    match try_kprobe_hash_add(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1,
    }
}

fn try_kprobe_hash_add(ctx: ProbeContext) -> Result<i32, i32> {
    let req: u64 = ctx.arg(1).ok_or(1i32)?;
    // SAFETY: calling BPF helper to get current time
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&req, &ts, 0);
    Ok(0)
}

#[kprobe]
pub fn kprobe__inet_csk_accept(ctx: ProbeContext) -> u32 {
    match try_kprobe_accept(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1,
    }
}

fn try_kprobe_accept(ctx: ProbeContext) -> Result<i32, i32> {
    let sk: u64 = ctx.arg(0).ok_or(1i32)?;

    // BPF_CORE_READ(icsk, icsk_accept_queue).rskq_accept_head
    // C binary reads 80 bytes at sk+976, extracts u64 at offset 24
    let queue_ptr = (sk + 976) as *const IcskAcceptQueueBuf;
    // SAFETY: reading kernel struct field via probe_read_kernel
    let queue: IcskAcceptQueueBuf = unsafe { bpf_probe_read_kernel(queue_ptr).map_err(|_| 1i32)? };
    let req = queue.rskq_accept_head;

    // SAFETY: map lookup on valid HashMap
    let tsp = match unsafe { START.get(&req) } {
        Some(v) => *v,
        None => return Ok(0),
    };

    // SAFETY: calling BPF helper to get current time
    let now = unsafe { bpf_ktime_get_ns() };
    let delta_us = (now - tsp) / 1000;

    let mut latency_slot = log2l(delta_us);
    if latency_slot > MAX_LATENCY_SLOT {
        latency_slot = MAX_LATENCY_SLOT;
    }

    // BPF_CORE_READ(sk, __sk_common).skc_num
    // C binary reads 136 bytes at sk+0, extracts u16 at offset 14
    let common_ptr = sk as *const SockCommonBuf;
    // SAFETY: reading kernel struct field via probe_read_kernel
    let common: SockCommonBuf = unsafe { bpf_probe_read_kernel(common_ptr).map_err(|_| 1i32)? };
    let port = common.skc_num;

    let mut latency_key = SocketLatencyKey {
        port,
        _pad: [0u8; 6],
        slot: latency_slot,
    };

    increment_map(&ACCEPT_LATENCY_SECONDS, &latency_key, 1);

    latency_key.slot = MAX_LATENCY_SLOT + 1;
    increment_map(&ACCEPT_LATENCY_SECONDS, &latency_key, delta_us);

    let _ = START.remove(&req);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
