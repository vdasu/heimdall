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
use core::sync::atomic::{AtomicU64, Ordering};

const PF_KTHREAD: u32 = 0x00200000;
const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;
const MAX_PID_NR: u32 = 30;
const MAX_TID_NR: u32 = 30;
const BPF_F_USER_STACK: u64 = 256;
const BPF_NOEXIST: u64 = 1;

const PID_OFFSET: usize = 2488;
const TGID_OFFSET: usize = 2492;
const FLAGS_OFFSET: usize = 44;
const STATE_OFFSET: usize = 24;
const COMM_OFFSET: usize = 3032;

#[repr(C)]
#[derive(Copy, Clone)]
struct key_t {
    pid: u32,
    tgid: u32,
    user_stack_id: i32,
    kern_stack_id: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct val_t {
    delta: u64,
    comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct internal_key {
    start_ts: u64,
    key: key_t,
}

#[no_mangle]
static kernel_threads_only: Global<u8> = Global::new(0);

#[no_mangle]
static user_threads_only: Global<u8> = Global::new(0);

#[no_mangle]
static max_block_us: Global<u64> = Global::new(0xFFFFFFFFFFFFFFFF);

#[no_mangle]
static min_block_us: Global<u64> = Global::new(1);

#[no_mangle]
static filter_by_tgid: Global<u8> = Global::new(0);

#[no_mangle]
static filter_by_pid: Global<u8> = Global::new(0);

#[no_mangle]
static state: Global<i64> = Global::new(-1);

#[map(name = "start")]
static START: HashMap<u32, internal_key> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "stackmap")]
static STACKMAP: StackTrace = StackTrace::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "info")]
static INFO: HashMap<key_t, val_t> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "tgids")]
static TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_NR, 0);

#[map(name = "pids")]
static PIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_TID_NR, 0);

#[inline(always)]
fn allow_record(t: u64) -> Result<bool, i64> {
    // SAFETY: reading tgid from task_struct via probe_read
    let tgid: u32 = unsafe { bpf_probe_read_kernel((t as *const u8).add(TGID_OFFSET) as *const u32) }?;
    // SAFETY: reading pid from task_struct via probe_read
    let pid: u32 = unsafe { bpf_probe_read_kernel((t as *const u8).add(PID_OFFSET) as *const u32) }?;

    if filter_by_tgid.load() != 0 {
        // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
        if unsafe { TGIDS.get(&tgid) }.is_none() {
            return Ok(false);
        }
    }
    if filter_by_pid.load() != 0 {
        // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
        if unsafe { PIDS.get(&pid) }.is_none() {
            return Ok(false);
        }
    }

    if user_threads_only.load() != 0 {
        // SAFETY: reading flags from task_struct via probe_read
        let flags: u32 = unsafe { bpf_probe_read_kernel((t as *const u8).add(FLAGS_OFFSET) as *const u32) }?;
        if (flags & PF_KTHREAD) != 0 {
            return Ok(false);
        }
    }
    if kernel_threads_only.load() != 0 {
        // SAFETY: reading flags from task_struct via probe_read
        let flags: u32 = unsafe { bpf_probe_read_kernel((t as *const u8).add(FLAGS_OFFSET) as *const u32) }?;
        if (flags & PF_KTHREAD) == 0 {
            return Ok(false);
        }
    }

    let state_val = state.load();
    if state_val != -1 {
        // SAFETY: reading __state from task_struct via probe_read
        let task_state: u32 = unsafe { bpf_probe_read_kernel((t as *const u8).add(STATE_OFFSET) as *const u32) }?;
        if task_state as i64 != state_val {
            return Ok(false);
        }
    }
    Ok(true)
}

#[inline(always)]
fn handle_sched_switch<C: EbpfContext>(ctx: &C, prev: u64, next: u64) -> Result<i32, i64> {
    if allow_record(prev)? {
        // SAFETY: reading pid from prev task_struct
        let mut pid: u32 = unsafe { bpf_probe_read_kernel((prev as *const u8).add(PID_OFFSET) as *const u32) }?;

        if pid == 0 {
            // SAFETY: getting SMP processor ID
            pid = unsafe { bpf_get_smp_processor_id() };
        }

        // SAFETY: reading tgid from prev task_struct
        let tgid: u32 = unsafe { bpf_probe_read_kernel((prev as *const u8).add(TGID_OFFSET) as *const u32) }?;

        // SAFETY: getting current kernel time
        let start_ts = unsafe { bpf_ktime_get_ns() };

        // SAFETY: reading flags from prev task_struct
        let flags: u32 = unsafe { bpf_probe_read_kernel((prev as *const u8).add(FLAGS_OFFSET) as *const u32) }?;

        let user_stack_id: i32 = if (flags & PF_KTHREAD) != 0 {
            -1
        } else {
            // SAFETY: getting user stack ID from valid context
            match unsafe { STACKMAP.get_stackid::<C>(ctx, BPF_F_USER_STACK) } {
                Ok(id) => id as i32,
                Err(_) => return Ok(0),
            }
        };

        // SAFETY: getting kernel stack ID from valid context
        let kern_stack_id: i32 = match unsafe { STACKMAP.get_stackid::<C>(ctx, 0) } {
            Ok(id) => id as i32,
            Err(_) => return Ok(0),
        };

        let i_key = internal_key {
            start_ts,
            key: key_t {
                pid,
                tgid,
                user_stack_id,
                kern_stack_id,
            },
        };

        START.insert(&pid, &i_key, 0).ok();

        // Step 1: Read comm from kernel to stack buffer (matches C's BPF_CORE_READ)
        // SAFETY: reading comm bytes from task_struct
        let comm_raw: [u8; TASK_COMM_LEN] = unsafe {
            bpf_probe_read_kernel((prev as *const u8).add(COMM_OFFSET) as *const [u8; TASK_COMM_LEN])
        }?;

        // Step 2: String-copy from stack to val comm (matches C's bpf_probe_read_kernel_str)
        let mut val_comm = [0u8; TASK_COMM_LEN];
        // SAFETY: string-copying comm from stack buffer to val
        match unsafe { bpf_probe_read_kernel_str_bytes(comm_raw.as_ptr(), &mut val_comm) } {
            Ok(_) => {},
            Err(_) => return Ok(0),
        }

        let val = val_t {
            delta: 0,
            comm: val_comm,
        };

        INFO.insert(&i_key.key, &val, BPF_NOEXIST).ok();
    }

    // SAFETY: reading pid from next task_struct
    let next_pid: u32 = unsafe { bpf_probe_read_kernel((next as *const u8).add(PID_OFFSET) as *const u32) }?;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let i_keyp = match unsafe { START.get(&next_pid) } {
        Some(v) => v,
        None => return Ok(0),
    };

    let i_keyp_key = i_keyp.key;
    let i_keyp_start_ts = i_keyp.start_ts;

    // SAFETY: getting current kernel time
    let ktime = unsafe { bpf_ktime_get_ns() };
    let delta = ktime.wrapping_sub(i_keyp_start_ts) as i64;

    if delta >= 0 {
        let delta = delta / 1000;
        let min_block = min_block_us.load();
        let max_block = max_block_us.load();
        if (delta as u64) >= min_block && (delta as u64) <= max_block {
            if let Some(valp) = INFO.get_ptr_mut(&i_keyp_key) {
                let delta_ptr = valp as *mut u64;
                // SAFETY: creating atomic from valid map pointer for atomic add
                let atomic = unsafe { AtomicU64::from_ptr(delta_ptr) };
                atomic.fetch_add(delta as u64, Ordering::Relaxed);
            }
        }
    }

    START.remove(&next_pid).ok();
    Ok(0)
}

#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch(ctx: BtfTracePointContext) -> i32 {
    match try_sched_switch(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_switch(ctx: &BtfTracePointContext) -> Result<i32, i64> {
    let prev: u64 = ctx.arg(1);
    let next: u64 = ctx.arg(2);
    handle_sched_switch(ctx, prev, next)
}

#[raw_tracepoint(tracepoint = "sched_switch")]
pub fn sched_switch_raw(ctx: RawTracePointContext) -> i32 {
    match try_sched_switch_raw(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_switch_raw(ctx: &RawTracePointContext) -> Result<i32, i64> {
    let prev: u64 = ctx.arg(1);
    let next: u64 = ctx.arg(2);
    handle_sched_switch(ctx, prev, next)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
