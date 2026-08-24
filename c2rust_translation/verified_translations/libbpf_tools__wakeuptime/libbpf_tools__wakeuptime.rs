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

const TASK_COMM_LEN: usize = 16;
const MAX_ENTRIES: u32 = 10240;
const PF_KTHREAD: u32 = 0x00200000;

const FLAGS_OFFSET: usize = 44;
const PID_OFFSET: usize = 2488;
const TGID_OFFSET: usize = 2492;
const COMM_OFFSET: usize = 3032;

#[repr(C)]
#[derive(Copy, Clone)]
struct key_t {
    waker: [u8; TASK_COMM_LEN],
    target: [u8; TASK_COMM_LEN],
    w_k_stack_id: i32,
}

#[no_mangle]
static targ_pid: Global<u32> = Global::new(0);

#[no_mangle]
static max_block_ns: Global<u64> = Global::new(0xFFFFFFFFFFFFFFFF);

#[no_mangle]
static min_block_ns: Global<u64> = Global::new(1);

#[no_mangle]
static user_threads_only: Global<u8> = Global::new(0);

#[map(name = "counts")]
static COUNTS: HashMap<key_t, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "stackmap")]
static STACKMAP: StackTrace = StackTrace::with_max_entries(MAX_ENTRIES, 0);

#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch(ctx: BtfTracePointContext) -> i32 {
    match try_sched_switch(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_switch(ctx: &BtfTracePointContext) -> Result<i32, i64> {
    let prev: u64 = ctx.arg(1);

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let targ = targ_pid.load();
    if targ != 0 && targ != pid {
        return Ok(0);
    }

    let uto = user_threads_only.load();
    if uto != 0 {
        // SAFETY: direct read of flags from BTF-typed task_struct pointer
        let flags: u32 = unsafe { *((prev as *const u8).add(FLAGS_OFFSET) as *const u32) };
        if flags & PF_KTHREAD != 0 {
            return Ok(0);
        }
    }

    // SAFETY: reading kernel time
    let ts = unsafe { bpf_ktime_get_ns() };
    START.insert(&tid, &ts, 0).ok();

    Ok(0)
}

#[btf_tracepoint(function = "sched_wakeup")]
pub fn sched_wakeup(ctx: BtfTracePointContext) -> i32 {
    match try_sched_wakeup(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_wakeup(ctx: &BtfTracePointContext) -> Result<i32, i64> {
    let p: u64 = ctx.arg(0);

    // SAFETY: direct read of tgid from BTF-typed task_struct pointer
    let pid: u32 = unsafe { *((p as *const u8).add(TGID_OFFSET) as *const u32) };

    // SAFETY: direct read of pid from BTF-typed task_struct pointer
    let tid: u32 = unsafe { *((p as *const u8).add(PID_OFFSET) as *const u32) };

    let targ = targ_pid.load();
    if targ != 0 && targ != pid {
        return Ok(0);
    }

    // SAFETY: looking up start map entry
    let tsp = match unsafe { START.get(&tid) } {
        Some(v) => *v,
        None => return Ok(0),
    };
    START.remove(&tid).ok();

    // SAFETY: reading kernel time
    let ktime = unsafe { bpf_ktime_get_ns() };
    let delta = ktime - tsp;

    let min_block = min_block_ns.load();
    let max_block = max_block_ns.load();
    if delta < min_block || delta > max_block {
        return Ok(0);
    }

    let mut key = key_t {
        waker: [0u8; TASK_COMM_LEN],
        target: [0u8; TASK_COMM_LEN],
        w_k_stack_id: 0,
    };

    // SAFETY: calling get_stackid on valid BTF tracepoint context
    let stack_id = match unsafe { STACKMAP.get_stackid::<BtfTracePointContext>(ctx, 0) } {
        Ok(id) => id as i32,
        Err(_) => return Ok(0),
    };
    key.w_k_stack_id = stack_id;

    // SAFETY: reading comm from task_struct
    let target: [u8; TASK_COMM_LEN] = match unsafe {
        bpf_probe_read_kernel((p as *const u8).add(COMM_OFFSET) as *const [u8; TASK_COMM_LEN])
    } {
        Ok(t) => t,
        Err(_) => return Ok(0),
    };
    key.target = target;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    key.waker = comm;

    // SAFETY: looking up counts map
    if unsafe { COUNTS.get(&key) }.is_none() {
        let zero: u64 = 0;
        COUNTS.insert(&key, &zero, 0).ok();
    }
    if let Some(ptr) = COUNTS.get_ptr_mut(&key) {
        // SAFETY: creating atomic from valid map pointer
        let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
        counter.fetch_add(delta, core::sync::atomic::Ordering::Relaxed);
    }

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
