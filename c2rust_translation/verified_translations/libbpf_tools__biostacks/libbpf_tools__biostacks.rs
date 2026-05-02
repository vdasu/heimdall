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
use aya_ebpf::cty::*;
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicU32, Ordering};

const MAX_ENTRIES: u32 = 10240;
const MAX_STACK: usize = 20;
const MAX_SLOTS: usize = 20;
const TASK_COMM_LEN: usize = 16;
const MINORBITS: u32 = 20;

#[repr(C)]
#[derive(Copy, Clone)]
struct Rqinfo {
    pid: u32,
    kern_stack_size: i32,
    kern_stack: [u64; MAX_STACK],
    comm: [u8; TASK_COMM_LEN],
    dev: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InternalRqinfo {
    start_ts: u64,
    rqinfo: Rqinfo,
}

#[no_mangle]
static targ_ms: Global<u8> = Global::new(0);
#[no_mangle]
static filter_dev: Global<u8> = Global::new(0);
#[no_mangle]
static targ_dev: Global<u32> = Global::new(0xFFFFFFFF);

#[map(name = "rqinfos")]
static RQINFOS: HashMap<u64, InternalRqinfo> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "hists")]
static HISTS: HashMap<Rqinfo, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".bss"]
static zero: Hist = Hist { slots: [0u32; MAX_SLOTS] };

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
fn trace_start(ctx_ptr: *mut c_void, rq: u64, merge_bio: bool) -> Result<i32, i64> {
    // Read disk pointer from request (CO-RE resolved to rq_disk at offset 8)
    let disk: u64 = match unsafe { bpf_probe_read_kernel((rq as *const u8).add(8) as *const u64) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let dev: u32 = if disk != 0 {
        let major: u32 = match unsafe { bpf_probe_read_kernel(disk as *const u32) } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        let first_minor: u32 = match unsafe { bpf_probe_read_kernel((disk as *const u32).add(1)) } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        (major << MINORBITS) | first_minor
    } else {
        0
    };

    let fdev = filter_dev.load();
    if fdev != 0 {
        let tdev = targ_dev.load();
        if tdev != dev {
            return Ok(0);
        }
    }

    let existing_ptr: Option<*mut InternalRqinfo> = if merge_bio {
        RQINFOS.get_ptr_mut(&rq)
    } else {
        None
    };

    match existing_ptr {
        Some(ptr) => {
            // SAFETY: bpf_ktime_get_ns is an unsafe helper
            let ts = unsafe { bpf_ktime_get_ns() };
            // SAFETY: writing start_ts to valid map entry
            unsafe { (*ptr).start_ts = ts };
            let pid = bpf_get_current_pid_tgid() as u32;
            // SAFETY: writing pid to valid map entry
            unsafe { (*ptr).rqinfo.pid = pid };
            // SAFETY: calling bpf_get_stack with valid buffer in map entry
            let stack_ret = unsafe {
                bpf_get_stack(
                    ctx_ptr,
                    (*ptr).rqinfo.kern_stack.as_mut_ptr() as *mut c_void,
                    160,
                    0,
                )
            };
            // SAFETY: writing kern_stack_size to valid map entry
            unsafe { (*ptr).rqinfo.kern_stack_size = stack_ret as i32 };
            let comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => return Ok(0),
            };
            // SAFETY: writing comm to valid map entry
            unsafe { (*ptr).rqinfo.comm = comm };
            // SAFETY: writing dev to valid map entry
            unsafe { (*ptr).rqinfo.dev = dev };
        }
        None => {
            // SAFETY: zeroing a POD struct for stack initialization
            let mut i_rqinfo: InternalRqinfo = unsafe { core::mem::zeroed() };
            // SAFETY: bpf_ktime_get_ns is an unsafe helper
            i_rqinfo.start_ts = unsafe { bpf_ktime_get_ns() };
            i_rqinfo.rqinfo.pid = bpf_get_current_pid_tgid() as u32;
            // SAFETY: calling bpf_get_stack with valid stack buffer
            let stack_ret = unsafe {
                bpf_get_stack(
                    ctx_ptr,
                    i_rqinfo.rqinfo.kern_stack.as_mut_ptr() as *mut c_void,
                    160,
                    0,
                )
            };
            i_rqinfo.rqinfo.kern_stack_size = stack_ret as i32;
            let comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => return Ok(0),
            };
            i_rqinfo.rqinfo.comm = comm;
            i_rqinfo.rqinfo.dev = dev;
            let _ = RQINFOS.insert(&rq, &i_rqinfo, 0);
        }
    }

    Ok(0)
}

#[inline(always)]
fn trace_done(rq: u64) -> Result<i32, i64> {
    // SAFETY: bpf_ktime_get_ns is an unsafe helper
    let ts = unsafe { bpf_ktime_get_ns() };

    let i_rqinfop = match unsafe { RQINFOS.get(&rq) } {
        Some(v) => v,
        None => return Ok(0),
    };

    let delta: i64 = (ts.wrapping_sub(i_rqinfop.start_ts)) as i64;
    if delta < 0 {
        let _ = RQINFOS.remove(&rq);
        return Ok(0);
    }

    let delta: u64 = if targ_ms.load() != 0 {
        (delta as u64) / 1000000
    } else {
        (delta as u64) / 1000
    };

    let slot = log2l(delta);
    let slot = if slot >= MAX_SLOTS as u64 {
        MAX_SLOTS as u64 - 1
    } else {
        slot
    };

    // lookup_or_try_init pattern
    let key = i_rqinfop.rqinfo;
    let histp = match HISTS.get_ptr_mut(&key) {
        Some(p) => p,
        None => {
            let _ = HISTS.insert(&key, &zero, 1); // BPF_NOEXIST
            match HISTS.get_ptr_mut(&key) {
                Some(p) => p,
                None => {
                    let _ = RQINFOS.remove(&rq);
                    return Ok(0);
                }
            }
        }
    };

    // Atomic increment of histp->slots[slot]
    let slot_ptr = unsafe { &raw mut (*histp).slots[slot as usize] } as *mut u32;
    // SAFETY: creating atomic from valid map pointer for fetch_add
    let atomic = unsafe { AtomicU32::from_ptr(slot_ptr) };
    atomic.fetch_add(1, Ordering::Relaxed);

    let _ = RQINFOS.remove(&rq);
    Ok(0)
}

#[kprobe]
pub fn blk_account_io_merge_bio(ctx: ProbeContext) -> i32 {
    match try_blk_account_io_merge_bio(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_blk_account_io_merge_bio(ctx: ProbeContext) -> Result<i32, i64> {
    let rq: u64 = ctx.arg(0).ok_or(1i64)?;
    trace_start(ctx.as_ptr(), rq, true)
}

#[fentry(function = "blk_account_io_start")]
pub fn blk_account_io_start(ctx: FEntryContext) -> i32 {
    match try_blk_account_io_start(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_blk_account_io_start(ctx: FEntryContext) -> Result<i32, i64> {
    let rq: u64 = ctx.arg(0);
    trace_start(ctx.as_ptr(), rq, false)
}

#[fentry(function = "blk_account_io_done")]
pub fn blk_account_io_done(ctx: FEntryContext) -> i32 {
    match try_blk_account_io_done(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_blk_account_io_done(ctx: FEntryContext) -> Result<i32, i64> {
    let rq: u64 = ctx.arg(0);
    trace_done(rq)
}

#[btf_tracepoint(function = "block_io_start")]
pub fn block_io_start(ctx: BtfTracePointContext) -> i32 {
    match try_block_io_start(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_block_io_start(ctx: BtfTracePointContext) -> Result<i32, i64> {
    let rq: u64 = ctx.arg(0);
    trace_start(ctx.as_ptr(), rq, false)
}

#[btf_tracepoint(function = "block_io_done")]
pub fn block_io_done(ctx: BtfTracePointContext) -> i32 {
    match try_block_io_done(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_block_io_done(ctx: BtfTracePointContext) -> Result<i32, i64> {
    let rq: u64 = ctx.arg(0);
    trace_done(rq)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
