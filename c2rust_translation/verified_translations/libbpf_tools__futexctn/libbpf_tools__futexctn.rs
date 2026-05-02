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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;
const MAX_SLOTS: usize = 36;

const FUTEX_WAIT: i32 = 0;
const FUTEX_PRIVATE_FLAG: i32 = 128;
const FUTEX_CLOCK_REALTIME: i32 = 256;
const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

const BPF_F_USER_STACK: u64 = 1 << 8;

#[repr(C)]
#[derive(Copy, Clone)]
struct ValT {
    ts: u64,
    uaddr: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct HistKey {
    pid_tgid: u64,
    uaddr: u64,
    user_stack_id: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
    comm: [u8; TASK_COMM_LEN],
    contended: u64,
    total_elapsed: u64,
    min: u64,
    max: u64,
}

#[no_mangle]
static targ_summary: Global<u8> = Global::new(0);

#[no_mangle]
static targ_ms: Global<u8> = Global::new(0);

#[no_mangle]
static targ_lock: Global<u64> = Global::new(0);

#[no_mangle]
static targ_pid: Global<i32> = Global::new(0);

#[no_mangle]
static targ_tid: Global<i32> = Global::new(0);

#[link_section = ".bss"]
static INITIAL_HIST: Hist = Hist {
    slots: [0u32; MAX_SLOTS],
    comm: [0u8; TASK_COMM_LEN],
    contended: 0,
    total_elapsed: 0,
    min: 0,
    max: 0,
};

#[map(name = "start")]
static START: HashMap<u64, ValT> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "stackmap")]
static STACKMAP: StackTrace = StackTrace::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "hists")]
static HISTS: HashMap<HistKey, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn log2_u32(mut v: u32) -> u64 {
    let mut r: u32 = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let mut shift: u32 = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    r |= shift;
    shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;
    shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r |= shift;
    r |= v >> 1;
    r as u64
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

#[tracepoint(category = "syscalls", name = "sys_enter_futex")]
pub fn futex_enter(ctx: TracePointContext) -> i32 {
    match try_futex_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_futex_enter(ctx: TracePointContext) -> Result<i32, i32> {
    // SAFETY: reading args[1] at offset 24 from tracepoint context
    let args1: u64 = unsafe { ctx.read_at(24) }.map_err(|_| 0i32)?;
    if ((args1 as i32) & FUTEX_CMD_MASK) != FUTEX_WAIT {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;

    let tpid = targ_pid.load();
    if tpid != 0 && tpid as u64 != (pid_tgid >> 32) {
        return Ok(0);
    }
    let ttid = targ_tid.load();
    if ttid != 0 && ttid != tid as i32 {
        return Ok(0);
    }

    // SAFETY: reading args[0] at offset 16 from tracepoint context
    let args0: u64 = unsafe { ctx.read_at(16) }.map_err(|_| 0i32)?;
    let uaddr = args0;

    let tlock = targ_lock.load();
    if tlock != 0 && tlock != uaddr {
        return Ok(0);
    }

    // SAFETY: calling bpf_ktime_get_ns
    let ts = unsafe { bpf_ktime_get_ns() };

    let v = ValT { ts, uaddr };
    START.insert(&pid_tgid, &v, 0).ok();

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_exit_futex")]
pub fn futex_exit(ctx: TracePointContext) -> i32 {
    match try_futex_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_futex_exit(ctx: TracePointContext) -> Result<i32, i32> {
    // SAFETY: calling bpf_ktime_get_ns
    let ts = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let vp = match unsafe { START.get(&pid_tgid) } {
        Some(v) => *v,
        None => return Ok(0),
    };

    'body: {
        // SAFETY: reading ret at offset 16 from tracepoint context
        let ret: i64 = match unsafe { ctx.read_at(16) } {
            Ok(r) => r,
            Err(_) => break 'body,
        };
        if (ret as i32) < 0 {
            break 'body;
        }

        let delta_i64: i64 = ts as i64 - vp.ts as i64;
        if delta_i64 < 0 {
            break 'body;
        }

        let mut hkey = HistKey {
            pid_tgid,
            uaddr: vp.uaddr,
            user_stack_id: 0,
        };

        if targ_summary.load() == 0 {
            // SAFETY: calling get_stackid with valid tracepoint context
            let stack_id = match unsafe { STACKMAP.get_stackid::<TracePointContext>(&ctx, BPF_F_USER_STACK) } {
                Ok(id) => id,
                Err(_) => {
                    START.remove(&pid_tgid).ok();
                    return Ok(0);
                }
            };
            hkey.user_stack_id = stack_id as i32;
        } else {
            hkey.pid_tgid >>= 32;
        }

        // bpf_map_lookup_or_try_init pattern
        let histp: *mut Hist = {
            if let Some(p) = HISTS.get_ptr_mut(&hkey) {
                p
            } else {
                HISTS.insert(&hkey, &INITIAL_HIST, 1).ok();
                match HISTS.get_ptr_mut(&hkey) {
                    Some(p) => p,
                    None => break 'body,
                }
            }
        };

        let mut delta_i64 = delta_i64;
        if targ_ms.load() != 0 {
            delta_i64 /= 1000000;
        } else {
            delta_i64 /= 1000;
        }

        let delta = delta_i64 as u64;
        let mut slot = log2l(delta);
        if slot >= MAX_SLOTS as u64 {
            slot = (MAX_SLOTS - 1) as u64;
        }

        // Atomic add to slots[slot]
        // SAFETY: computing pointer to slots array base in valid map entry
        let slots_base = unsafe { core::ptr::addr_of_mut!((*histp).slots) as *mut u32 };
        // SAFETY: advancing pointer by slot offset (slot < MAX_SLOTS)
        let slot_ptr = unsafe { slots_base.add(slot as usize) };
        // SAFETY: creating atomic from valid aligned u32 map pointer
        let slot_atomic = unsafe { AtomicU32::from_ptr(slot_ptr) };
        slot_atomic.fetch_add(1, Ordering::Relaxed);

        // Atomic add to contended
        // SAFETY: computing pointer to contended field in valid map entry
        let contended_ptr = unsafe { core::ptr::addr_of_mut!((*histp).contended) };
        // SAFETY: creating atomic from valid aligned u64 map pointer
        let contended_atomic = unsafe { AtomicU64::from_ptr(contended_ptr) };
        contended_atomic.fetch_add(1, Ordering::Relaxed);

        // Atomic add to total_elapsed
        // SAFETY: computing pointer to total_elapsed field in valid map entry
        let elapsed_ptr = unsafe { core::ptr::addr_of_mut!((*histp).total_elapsed) };
        // SAFETY: creating atomic from valid aligned u64 map pointer
        let elapsed_atomic = unsafe { AtomicU64::from_ptr(elapsed_ptr) };
        elapsed_atomic.fetch_add(delta, Ordering::Relaxed);

        // Atomic read (fetch_or 0) + CAS for min
        // SAFETY: computing pointer to min field in valid map entry
        let min_ptr = unsafe { core::ptr::addr_of_mut!((*histp).min) };
        // SAFETY: creating atomic from valid aligned u64 map pointer
        let min_atomic = unsafe { AtomicU64::from_ptr(min_ptr) };
        let min_val = min_atomic.fetch_or(0, Ordering::Relaxed);
        if min_val == 0 || min_val > delta {
            let _ = min_atomic.compare_exchange(min_val, delta, Ordering::Relaxed, Ordering::Relaxed);
        }

        // Atomic read (fetch_or 0) + CAS for max
        // SAFETY: computing pointer to max field in valid map entry
        let max_ptr = unsafe { core::ptr::addr_of_mut!((*histp).max) };
        // SAFETY: creating atomic from valid aligned u64 map pointer
        let max_atomic = unsafe { AtomicU64::from_ptr(max_ptr) };
        let max_val = max_atomic.fetch_or(0, Ordering::Relaxed);
        if max_val < delta {
            let _ = max_atomic.compare_exchange(max_val, delta, Ordering::Relaxed, Ordering::Relaxed);
        }

        // Get current comm and write to histogram
        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => return Ok(0),
        };
        // SAFETY: writing comm field through valid map pointer
        unsafe { (*histp).comm = comm };
    }

    // cleanup: delete start entry
    START.remove(&pid_tgid).ok();
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
