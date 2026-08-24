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
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const MAX_SLOTS: usize = 27;

#[repr(C)]
#[derive(Copy, Clone)]
struct HistKey {
    cmd_flags: u32,
    dev: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
}

#[no_mangle]
static filter_cg: Global<u8> = Global::new(0);
#[no_mangle]
static targ_per_disk: Global<u8> = Global::new(0);
#[no_mangle]
static targ_per_flag: Global<u8> = Global::new(0);
#[no_mangle]
static targ_queued: Global<u8> = Global::new(0);
#[no_mangle]
static targ_ms: Global<u8> = Global::new(0);
#[no_mangle]
static filter_dev: Global<u8> = Global::new(0);
#[no_mangle]
static targ_dev: Global<u32> = Global::new(0);
#[no_mangle]
static targ_single: Global<u8> = Global::new(1);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "start")]
static START: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "hists")]
static HISTS: HashMap<HistKey, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
#[link_section = ".bss"]
static initial_hist: Hist = Hist { slots: [0u32; MAX_SLOTS] };

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
    let r = r | (v >> 1);
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

#[inline(always)]
fn get_disk(rq: u64) -> Result<u64, i32> {
    // SAFETY: reading rq->rq_disk via bpf_probe_read_kernel at CO-RE default offset 8
    unsafe { bpf_probe_read_kernel((rq as *const u8).add(8) as *const u64) }
}

#[inline(always)]
fn trace_rq_start(rq: u64, issue: bool) -> Result<i32, i32> {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    if issue && targ_queued.load() == 1 {
        // SAFETY: reading rq->q at CO-RE default offset 0
        let q: u64 = unsafe { bpf_probe_read_kernel(rq as *const u64) }?;
        // SAFETY: reading q->elevator at CO-RE default offset 8
        let elevator: u64 =
            unsafe { bpf_probe_read_kernel((q as *const u8).add(8) as *const u64) }?;
        if elevator != 0 {
            return Ok(0);
        }
    }

    // SAFETY: bpf_ktime_get_ns is unsafe in aya-ebpf
    let ts = unsafe { bpf_ktime_get_ns() };

    if filter_dev.load() == 1 {
        let disk = get_disk(rq)?;
        let dev = if disk != 0 {
            // SAFETY: reading disk->major at CO-RE default offset 0
            let major: u32 = unsafe { bpf_probe_read_kernel(disk as *const u32) }?;
            // SAFETY: reading disk->first_minor at CO-RE default offset 4
            let first_minor: u32 =
                unsafe { bpf_probe_read_kernel((disk as *const u8).add(4) as *const u32) }?;
            (major << 20) | first_minor
        } else {
            0u32
        };
        if targ_dev.load() != dev {
            return Ok(0);
        }
    }

    START.insert(&rq, &ts, 0).ok();
    Ok(0)
}

#[inline(always)]
fn handle_insert(ctx_ptr: *const u64) -> Result<i32, i32> {
    let rq: u64 = if targ_single.load() != 0 {
        // SAFETY: reading ctx[0] from raw tracepoint context
        unsafe { *ctx_ptr }
    } else {
        // SAFETY: reading ctx[1] from raw tracepoint context
        unsafe { *ctx_ptr.add(1) }
    };
    trace_rq_start(rq, false)
}

#[inline(always)]
fn handle_issue(ctx_ptr: *const u64) -> Result<i32, i32> {
    let rq: u64 = if targ_single.load() != 0 {
        // SAFETY: reading ctx[0] from raw tracepoint context
        unsafe { *ctx_ptr }
    } else {
        // SAFETY: reading ctx[1] from raw tracepoint context
        unsafe { *ctx_ptr.add(1) }
    };
    trace_rq_start(rq, true)
}

#[inline(always)]
fn handle_complete(rq: u64) -> Result<i32, i32> {
    // SAFETY: bpf_ktime_get_ns is unsafe in aya-ebpf
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut hkey = HistKey { cmd_flags: 0, dev: 0 };

    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let tsp = match unsafe { START.get(&rq) } {
        Some(v) => *v,
        None => return Ok(0),
    };

    let delta = (ts.wrapping_sub(tsp)) as i64;
    if delta < 0 {
        START.remove(&rq).ok();
        return Ok(0);
    }

    if targ_per_disk.load() == 1 {
        let disk = get_disk(rq)?;
        if disk != 0 {
            // SAFETY: reading disk->major at CO-RE default offset 0
            let major: u32 = unsafe { bpf_probe_read_kernel(disk as *const u32) }?;
            // SAFETY: reading disk->first_minor at CO-RE default offset 4
            let first_minor: u32 =
                unsafe { bpf_probe_read_kernel((disk as *const u8).add(4) as *const u32) }?;
            hkey.dev = (major << 20) | first_minor;
        }
    }

    if targ_per_flag.load() == 1 {
        // SAFETY: reading rq->cmd_flags at CO-RE default offset 24
        let cmd_flags: u32 =
            unsafe { bpf_probe_read_kernel((rq as *const u8).add(24) as *const u32) }?;
        hkey.cmd_flags = cmd_flags;
    }

    let histp = match HISTS.get_ptr_mut(&hkey) {
        Some(p) => p,
        None => {
            HISTS.insert(&hkey, &initial_hist, 0).ok();
            match HISTS.get_ptr_mut(&hkey) {
                Some(p) => p,
                None => {
                    START.remove(&rq).ok();
                    return Ok(0);
                }
            }
        }
    };

    let delta = delta as u64;
    let delta = if targ_ms.load() == 1 {
        delta / 1000000
    } else {
        delta / 1000
    };

    let mut slot = log2l(delta);
    if slot >= MAX_SLOTS as u64 {
        slot = MAX_SLOTS as u64 - 1;
    }

    let slot_ptr = (histp as *mut u32).wrapping_add(slot as usize);
    // SAFETY: creating atomic from valid map pointer for atomic increment
    let atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(slot_ptr) };
    atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    START.remove(&rq).ok();
    Ok(0)
}

// ===== Raw Tracepoint Entry Points =====

#[raw_tracepoint(tracepoint = "block_rq_insert")]
pub fn block_rq_insert(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    match handle_insert(ctx_ptr) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[raw_tracepoint(tracepoint = "block_rq_issue")]
pub fn block_rq_issue(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    match handle_issue(ctx_ptr) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[raw_tracepoint(tracepoint = "block_rq_complete")]
pub fn block_rq_complete(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading rq from ctx[0]
    let rq: u64 = unsafe { *ctx_ptr };
    match handle_complete(rq) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// ===== BTF Tracepoint Entry Points =====

#[btf_tracepoint(function = "block_rq_insert")]
pub fn block_rq_insert_btf(ctx: BtfTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    match handle_insert(ctx_ptr) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[btf_tracepoint(function = "block_rq_issue")]
pub fn block_rq_issue_btf(ctx: BtfTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    match handle_issue(ctx_ptr) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[btf_tracepoint(function = "block_rq_complete")]
pub fn block_rq_complete_btf(ctx: BtfTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading rq from ctx[0]
    let rq: u64 = unsafe { *ctx_ptr };
    match handle_complete(rq) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
