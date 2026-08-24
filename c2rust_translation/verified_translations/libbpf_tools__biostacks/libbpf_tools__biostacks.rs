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
const MAX_SLOTS: usize = 20;
const MAX_STACK: usize = 20;
const MINORBITS: u32 = 20;

#[repr(C)]
#[derive(Copy, Clone)]
struct Rqinfo {
    pid: u32,
    kern_stack_size: i32,
    kern_stack: [u64; MAX_STACK],
    comm: [u8; 16],
    dev: u32,
    _pad: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InternalRqinfo {
    start_ts: u64,
    rqinfo: Rqinfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
}

#[map(name = "rqinfos")]
static RQINFOS: HashMap<u64, InternalRqinfo> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "hists")]
static HISTS: HashMap<Rqinfo, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".bss"]
static zero: Hist = Hist {
    slots: [0u32; MAX_SLOTS],
};

#[no_mangle]
static targ_ms: Global<u8> = Global::new(0);

#[no_mangle]
static filter_dev: Global<u8> = Global::new(0);

#[no_mangle]
static targ_dev: Global<u32> = Global::new(0xFFFFFFFF);

#[inline(always)]
fn log2_u32(v: u32) -> u32 {
    let mut v = v;
    let r = if v > 0xFFFF { 16u32 } else { 0u32 };
    v >>= r;
    let shift = if v > 0xFF { 8u32 } else { 0u32 };
    v >>= shift;
    let mut r = r | shift;
    let shift = if v > 0xF { 4u32 } else { 0u32 };
    v >>= shift;
    r |= shift;
    let shift = if v > 0x3 { 2u32 } else { 0u32 };
    v >>= shift;
    r |= shift;
    r | (v >> 1)
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi) as u64 + 32
    } else {
        log2_u32(v as u32) as u64
    }
}

#[inline(always)]
fn trace_start(ctx_ptr: *mut c_void, rq: u64, merge_bio: bool) -> Result<i32, i64> {
    // get_disk: BPF_CORE_READ(rq, rq_disk) at offset 8
    // SAFETY: reading rq_disk pointer from request struct
    let disk: u64 = unsafe { bpf_probe_read_kernel((rq + 8) as *const u64)? };

    let dev: u32 = if disk != 0 {
        // SAFETY: reading major field from gendisk at offset 0
        let major: u32 = unsafe { bpf_probe_read_kernel(disk as *const u32)? };
        // SAFETY: reading first_minor field from gendisk at offset 4
        let first_minor: u32 = unsafe { bpf_probe_read_kernel((disk + 4) as *const u32)? };
        (major << MINORBITS) | first_minor
    } else {
        0
    };

    if filter_dev.load() == 1 && targ_dev.load() != dev {
        return Ok(0);
    }

    if merge_bio {
        let _ = RQINFOS.get_ptr_mut(&rq);
    }

    let mut i_rqinfo = InternalRqinfo {
        start_ts: 0,
        rqinfo: Rqinfo {
            pid: 0,
            kern_stack_size: 0,
            kern_stack: [0u64; MAX_STACK],
            comm: [0u8; 16],
            dev: 0,
            _pad: [0u8; 4],
        },
    };

    // SAFETY: reading ktime via helper
    i_rqinfo.start_ts = unsafe { bpf_ktime_get_ns() };
    i_rqinfo.rqinfo.pid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: calling bpf_get_stack to fill kern_stack buffer on stack
    let stack_size = unsafe {
        bpf_get_stack(
            ctx_ptr as *mut _,
            i_rqinfo.rqinfo.kern_stack.as_mut_ptr() as *mut c_void,
            core::mem::size_of::<[u64; MAX_STACK]>() as u32,
            0,
        )
    };
    i_rqinfo.rqinfo.kern_stack_size = stack_size as i32;
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    i_rqinfo.rqinfo.comm = comm;
    i_rqinfo.rqinfo.dev = dev;

    RQINFOS.insert(&rq, &i_rqinfo, 0).ok();
    Ok(0)
}

#[inline(always)]
fn trace_done(rq: u64) -> Result<i32, i64> {
    // SAFETY: reading ktime via helper
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: HashMap::get is pub unsafe fn
    let i_rqinfop = match unsafe { RQINFOS.get(&rq) } {
        Some(v) => v,
        None => return Ok(0),
    };

    let delta = ts.wrapping_sub(i_rqinfop.start_ts) as i64;
    if delta < 0 {
        RQINFOS.remove(&rq).ok();
        return Ok(0);
    }

    // bpf_map_lookup_or_try_init: first lookup
    let mut histp = HISTS.get_ptr_mut(&i_rqinfop.rqinfo);
    if histp.is_none() {
        match HISTS.insert(&i_rqinfop.rqinfo, &zero, 1) {
            Ok(()) => {}
            Err(e) => {
                if (e as i32) != -17 {
                    RQINFOS.remove(&rq).ok();
                    return Ok(0);
                }
            }
        }
        histp = HISTS.get_ptr_mut(&i_rqinfop.rqinfo);
    }

    let histp = match histp {
        Some(p) => p,
        None => {
            RQINFOS.remove(&rq).ok();
            return Ok(0);
        }
    };

    let mut delta = delta as u64;
    if targ_ms.load() == 1 {
        delta /= 1000000;
    } else {
        delta /= 1000;
    }

    let mut slot = log2l(delta);
    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    // SAFETY: computing pointer to slots[slot] within valid Hist map entry
    let slot_ptr = unsafe { (histp as *mut u32).add(slot as usize) };
    // SAFETY: creating atomic from valid map pointer for atomic increment
    let atomic = unsafe { AtomicU32::from_ptr(slot_ptr) };
    atomic.fetch_add(1, Ordering::Relaxed);

    RQINFOS.remove(&rq).ok();
    Ok(0)
}

// --- Entry points ---

#[kprobe(function = "blk_account_io_merge_bio")]
pub fn blk_account_io_merge_bio(ctx: ProbeContext) -> u32 {
    match try_blk_account_io_merge_bio(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_blk_account_io_merge_bio(ctx: ProbeContext) -> Result<i32, i64> {
    let rq: u64 = ctx.arg(0).ok_or(1i64)?;
    let ctx_ptr = ctx.as_ptr() as *mut c_void;
    trace_start(ctx_ptr, rq, true)
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
    let ctx_ptr = ctx.as_ptr() as *mut c_void;
    trace_start(ctx_ptr, rq, false)
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
    let ctx_ptr = ctx.as_ptr() as *mut c_void;
    trace_start(ctx_ptr, rq, false)
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
