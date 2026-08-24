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
use core::sync::atomic::{AtomicU32, Ordering};

const TASK_RUNNING: u32 = 0;
const MAX_SLOTS: usize = 36;

const TGID_OFFSET: usize = 2492;
const PID_OFFSET: usize = 2488;
const STATE_OFFSET: usize = 0;
const COMM_OFFSET: usize = 3032;

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
    comm: [u8; 16],
}

#[no_mangle]
static filter_cg: Global<u8> = Global::new(0);

#[no_mangle]
static targ_per_process: Global<u8> = Global::new(0);

#[no_mangle]
static targ_per_thread: Global<u8> = Global::new(0);

#[no_mangle]
static targ_offcpu: Global<u8> = Global::new(0);

#[no_mangle]
static targ_ms: Global<u8> = Global::new(0);

#[no_mangle]
static targ_tgid: Global<u32> = Global::new(0xFFFFFFFF);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "hists")]
static HISTS: HashMap<u32, Hist> = HashMap::with_max_entries(512, 0);

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".bss"]
static initial_hist: Hist = Hist {
    slots: [0u32; MAX_SLOTS],
    comm: [0u8; 16],
};

#[inline(always)]
fn log2_32(mut v: u32) -> u32 {
    let mut r: u32;

    r = if v > 0xFFFF { 16 } else { 0 };
    v >>= r;
    let shift = if v > 0xFF { 8u32 } else { 0 };
    v >>= shift;
    r |= shift;
    let shift = if v > 0xF { 4u32 } else { 0 };
    v >>= shift;
    r |= shift;
    let shift = if v > 0x3 { 2u32 } else { 0 };
    v >>= shift;
    r |= shift;
    r |= v >> 1;

    r
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        (log2_32(hi) as u64) + 32
    } else {
        log2_32(v as u32) as u64
    }
}

#[inline(always)]
fn store_start(tgid: u32, pid: u32, ts: u64) {
    let target_tgid = targ_tgid.load();
    if target_tgid != 0xFFFFFFFF && target_tgid != tgid {
        return;
    }
    let _ = START.insert(&pid, &ts, 0);
}

#[inline(always)]
fn update_hist(task: *const u8, tgid: u32, pid: u32, ts: u64) {
    let target_tgid = targ_tgid.load();
    if target_tgid != 0xFFFFFFFF && target_tgid != tgid {
        return;
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let tsp = match unsafe { START.get(&pid) } {
        Some(v) => *v,
        None => return,
    };

    if ts < tsp {
        return;
    }

    let id: u32 = if targ_per_process.load() != 0 {
        tgid
    } else if targ_per_thread.load() == 1 {
        pid
    } else {
        0xFFFFFFFF
    };

    let histp: *mut Hist = match HISTS.get_ptr_mut(&id) {
        Some(p) => p,
        None => {
            let _ = HISTS.insert(&id, &initial_hist, 0);
            let p = match HISTS.get_ptr_mut(&id) {
                Some(p) => p,
                None => return,
            };
            let comm_src = task.wrapping_add(COMM_OFFSET);
            // SAFETY: obtaining mutable reference to comm field of valid map entry
            let comm_dst = unsafe { &mut (*p).comm };
            match unsafe { bpf_probe_read_kernel_str_bytes(comm_src, comm_dst) } {
                Ok(_) => {}
                Err(_) => return,
            }
            p
        }
    };

    let mut delta = ts - tsp;
    if targ_ms.load() == 1 {
        delta /= 1000000;
    } else {
        delta /= 1000;
    }

    let mut slot = log2l(delta);
    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    let slot_ptr = (histp as *mut u32).wrapping_add(slot as usize);
    // SAFETY: creating atomic from valid map pointer for slot increment
    let atomic = unsafe { AtomicU32::from_ptr(slot_ptr) };
    atomic.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
fn handle_switch(prev: *const u8, next: *const u8) -> i32 {
    // SAFETY: reading prev->tgid via probe_read_kernel
    let prev_tgid: u32 = match unsafe {
        bpf_probe_read_kernel(prev.wrapping_add(TGID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading prev->pid via probe_read_kernel
    let prev_pid: u32 = match unsafe {
        bpf_probe_read_kernel(prev.wrapping_add(PID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading next->tgid via probe_read_kernel
    let tgid: u32 = match unsafe {
        bpf_probe_read_kernel(next.wrapping_add(TGID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading next->pid via probe_read_kernel
    let pid: u32 = match unsafe {
        bpf_probe_read_kernel(next.wrapping_add(PID_OFFSET) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // SAFETY: calling bpf_ktime_get_ns helper
    let ts = unsafe { bpf_ktime_get_ns() };

    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return 0,
        }
    }

    if targ_offcpu.load() == 1 {
        store_start(prev_tgid, prev_pid, ts);
        update_hist(next, tgid, pid, ts);
    } else {
        // SAFETY: reading prev->__state via probe_read_kernel
        let state: u32 = match unsafe {
            bpf_probe_read_kernel(prev.wrapping_add(STATE_OFFSET) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => return 0,
        };
        if state == TASK_RUNNING {
            update_hist(prev, prev_tgid, prev_pid, ts);
        }
        store_start(tgid, pid, ts);
    }

    0
}

#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch_btf(ctx: BtfTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading prev pointer from btf tracepoint context at offset 8
    let prev = unsafe { *ctx_ptr.wrapping_add(1) } as *const u8;
    // SAFETY: reading next pointer from btf tracepoint context at offset 16
    let next = unsafe { *ctx_ptr.wrapping_add(2) } as *const u8;
    handle_switch(prev, next)
}

#[raw_tracepoint(tracepoint = "sched_switch")]
pub fn sched_switch_tp(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading prev pointer from raw tracepoint context at offset 8
    let prev = unsafe { *ctx_ptr.wrapping_add(1) } as *const u8;
    // SAFETY: reading next pointer from raw tracepoint context at offset 16
    let next = unsafe { *ctx_ptr.wrapping_add(2) } as *const u8;
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
