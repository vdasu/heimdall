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
const TASK_RUNNING: u32 = 0;
const TASK_COMM_LEN: usize = 16;
const MAX_SLOTS: usize = 26;

const STATE_OFFSET: usize = 0;
const PID_OFFSET: usize = 2488;
const TGID_OFFSET: usize = 2492;
const THREAD_PID_OFFSET: usize = 2592;
const COMM_OFFSET: usize = 3032;
const PID_LEVEL_OFFSET: usize = 4;
const PID_NUMBERS_OFFSET: usize = 96;
const UPID_SIZE: usize = 16;
const NS_INUM_OFFSET: usize = 128;

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
    comm: [u8; TASK_COMM_LEN],
}

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "hists")]
static HISTS: HashMap<u32, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
static mut zero: Hist = Hist {
    slots: [0u32; MAX_SLOTS],
    comm: [0u8; TASK_COMM_LEN],
};

#[no_mangle]
static filter_cg: Global<bool> = Global::new(false);

#[no_mangle]
static targ_per_process: Global<bool> = Global::new(false);

#[no_mangle]
static targ_per_thread: Global<bool> = Global::new(false);

#[no_mangle]
static targ_per_pidns: Global<bool> = Global::new(false);

#[no_mangle]
static targ_ms: Global<bool> = Global::new(false);

#[no_mangle]
static targ_tgid: Global<i32> = Global::new(0);

#[inline(always)]
fn log2(v: u32) -> u64 {
    let mut v = v;
    let r = (if v > 0xFFFF { 1u32 } else { 0 }) << 4;
    v >>= r;
    let shift = (if v > 0xFF { 1u32 } else { 0 }) << 3;
    v >>= shift;
    let mut r = r | shift;
    let shift = (if v > 0xF { 1u32 } else { 0 }) << 2;
    v >>= shift;
    r |= shift;
    let shift = (if v > 0x3 { 1u32 } else { 0 }) << 1;
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
fn trace_enqueue(tgid: u32, pid: u32) -> i32 {
    if pid == 0 {
        return 0;
    }
    let target_tgid = targ_tgid.load();
    if target_tgid != 0 && target_tgid as u32 != tgid {
        return 0;
    }
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    START.insert(&pid, &ts, 0).ok();
    0
}

#[inline(always)]
fn pid_namespace(task: *const u8) -> u32 {
    // SAFETY: reading thread_pid from task_struct
    let thread_pid: u64 = match unsafe {
        bpf_probe_read_kernel(task.add(THREAD_PID_OFFSET) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let pid_ptr = thread_pid as *const u8;

    // SAFETY: reading level from pid struct
    let level: u32 = match unsafe {
        bpf_probe_read_kernel(pid_ptr.add(PID_LEVEL_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let upid_addr = pid_ptr as usize + PID_NUMBERS_OFFSET + (level as usize) * UPID_SIZE;
    // SAFETY: reading upid struct from pid->numbers[level]
    let upid: [u8; 16] = match unsafe {
        bpf_probe_read_kernel(upid_addr as *const [u8; 16])
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let ns_ptr = u64::from_ne_bytes([
        upid[8], upid[9], upid[10], upid[11],
        upid[12], upid[13], upid[14], upid[15],
    ]) as *const u8;

    // SAFETY: reading ns.inum from pid_namespace
    match unsafe {
        bpf_probe_read_kernel(ns_ptr.add(NS_INUM_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    }
}

#[inline(always)]
fn handle_switch(prev: *const u8, next: *const u8) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    // SAFETY: reading __state from prev task_struct
    let state: u32 = match unsafe {
        bpf_probe_read_kernel(prev.add(STATE_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    if state == TASK_RUNNING {
        // SAFETY: reading prev->tgid
        let prev_tgid: u32 = match unsafe {
            bpf_probe_read_kernel(prev.add(TGID_OFFSET) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        // SAFETY: reading prev->pid
        let prev_pid: u32 = match unsafe {
            bpf_probe_read_kernel(prev.add(PID_OFFSET) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        trace_enqueue(prev_tgid, prev_pid);
    }

    // SAFETY: reading next->pid
    let pid: u32 = match unsafe {
        bpf_probe_read_kernel(next.add(PID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let tsp = match unsafe { START.get(&pid) } {
        Some(v) => *v,
        None => return Ok(0),
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now as i64 - tsp as i64;
    if delta < 0 {
        START.remove(&pid).ok();
        return Ok(0);
    }

    let hkey: u32 = if targ_per_process.load() {
        // SAFETY: reading next->tgid
        match unsafe {
            bpf_probe_read_kernel(next.add(TGID_OFFSET) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => {
                START.remove(&pid)?;
                return Ok(0);
            }
        }
    } else if targ_per_thread.load() {
        pid
    } else if targ_per_pidns.load() {
        pid_namespace(next)
    } else {
        u32::MAX
    };

    let histp: *mut Hist = match HISTS.get_ptr_mut(&hkey) {
        Some(p) => p,
        None => {
            // SAFETY: reading zero-initialized template for map insert
            match HISTS.insert(&hkey, unsafe { &*(&raw mut zero) }, 1) {
                Ok(()) => {}
                Err(e) if e == -17 => {}
                Err(_) => {
                    START.remove(&pid).ok();
                    return Ok(0);
                }
            }
            match HISTS.get_ptr_mut(&hkey) {
                Some(p) => p,
                None => {
                    START.remove(&pid).ok();
                    return Ok(0);
                }
            }
        }
    };

    // SAFETY: reading comm[0] from valid map entry pointer
    let comm_first = unsafe { (*histp).comm[0] };
    if comm_first == 0 {
        // SAFETY: getting mutable reference to comm in map entry
        let comm_buf = unsafe { &mut (*histp).comm };
        // SAFETY: reading kernel string from task_struct comm field
        match unsafe {
            bpf_probe_read_kernel_str_bytes(next.add(COMM_OFFSET), comm_buf)
        } {
            Ok(_) => {}
            Err(_) => {
                START.remove(&pid).ok();
                return Ok(0);
            }
        }
    }

    let mut delta_u = delta as u64;
    if targ_ms.load() {
        delta_u /= 1_000_000;
    } else {
        delta_u /= 1000;
    }

    let mut slot = log2l(delta_u);
    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    // SAFETY: computing pointer to slots[slot] within valid map entry
    let slot_ptr = unsafe { (histp as *mut u32).add(slot as usize) };
    // SAFETY: creating atomic from valid map entry pointer
    let counter = unsafe { core::sync::atomic::AtomicU32::from_ptr(slot_ptr) };
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    START.remove(&pid).ok();
    Ok(0)
}

// ==================== tp_btf entries ====================

#[btf_tracepoint(function = "sched_wakeup")]
pub fn sched_wakeup(ctx: BtfTracePointContext) -> i32 {
    match try_sched_wakeup(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_wakeup(ctx: BtfTracePointContext) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading task pointer from BPF context args[0]
    let p = unsafe { *ctx_ptr } as *const u8;
    // SAFETY: tp_btf allows direct pointer access to task_struct tgid
    let tgid: u32 = unsafe { *(p.add(TGID_OFFSET) as *const u32) };
    // SAFETY: tp_btf allows direct pointer access to task_struct pid
    let pid_val: u32 = unsafe { *(p.add(PID_OFFSET) as *const u32) };
    Ok(trace_enqueue(tgid, pid_val))
}

#[btf_tracepoint(function = "sched_wakeup_new")]
pub fn sched_wakeup_new(ctx: BtfTracePointContext) -> i32 {
    match try_sched_wakeup_new(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_wakeup_new(ctx: BtfTracePointContext) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading task pointer from BPF context args[0]
    let p = unsafe { *ctx_ptr } as *const u8;
    // SAFETY: tp_btf allows direct pointer access to task_struct tgid
    let tgid: u32 = unsafe { *(p.add(TGID_OFFSET) as *const u32) };
    // SAFETY: tp_btf allows direct pointer access to task_struct pid
    let pid_val: u32 = unsafe { *(p.add(PID_OFFSET) as *const u32) };
    Ok(trace_enqueue(tgid, pid_val))
}

#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch(ctx: BtfTracePointContext) -> i32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_switch(ctx: BtfTracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading prev from BPF context args[1]
    let prev = unsafe { *ctx_ptr.add(1) } as *const u8;
    // SAFETY: reading next from BPF context args[2]
    let next = unsafe { *ctx_ptr.add(2) } as *const u8;
    handle_switch(prev, next)
}

// ==================== raw_tp entries ====================

#[raw_tracepoint(tracepoint = "sched_wakeup")]
pub fn handle_sched_wakeup(ctx: RawTracePointContext) -> i32 {
    match try_handle_sched_wakeup(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_sched_wakeup(ctx: RawTracePointContext) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading task pointer from BPF context args[0]
    let p = unsafe { *ctx_ptr } as *const u8;
    // SAFETY: reading tgid via probe_read
    let tgid: u32 = match unsafe {
        bpf_probe_read_kernel(p.add(TGID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    // SAFETY: reading pid via probe_read
    let pid_val: u32 = match unsafe {
        bpf_probe_read_kernel(p.add(PID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    Ok(trace_enqueue(tgid, pid_val))
}

#[raw_tracepoint(tracepoint = "sched_wakeup_new")]
pub fn handle_sched_wakeup_new(ctx: RawTracePointContext) -> i32 {
    match try_handle_sched_wakeup_new(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_sched_wakeup_new(ctx: RawTracePointContext) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading task pointer from BPF context args[0]
    let p = unsafe { *ctx_ptr } as *const u8;
    // SAFETY: reading tgid via probe_read
    let tgid: u32 = match unsafe {
        bpf_probe_read_kernel(p.add(TGID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    // SAFETY: reading pid via probe_read
    let pid_val: u32 = match unsafe {
        bpf_probe_read_kernel(p.add(PID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    Ok(trace_enqueue(tgid, pid_val))
}

#[raw_tracepoint(tracepoint = "sched_switch")]
pub fn handle_sched_switch(ctx: RawTracePointContext) -> i32 {
    match try_handle_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_sched_switch(ctx: RawTracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading prev from BPF context args[1]
    let prev = unsafe { *ctx_ptr.add(1) } as *const u8;
    // SAFETY: reading next from BPF context args[2]
    let next = unsafe { *ctx_ptr.add(2) } as *const u8;
    handle_switch(prev, next)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
