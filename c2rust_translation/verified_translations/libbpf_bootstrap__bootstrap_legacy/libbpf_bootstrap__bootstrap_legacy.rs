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

const TASK_COMM_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 127;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    _pad: u32,
    duration_ns: u64,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; MAX_FILENAME_LEN],
    exit_event: u8,
}

#[map(name = "exec_start")]
static EXEC_START: HashMap<i32, u64> = HashMap::with_max_entries(8192, 0);

#[map(name = "perf_buffer")]
static PERF_BUFFER: PerfEventArray<Event> = PerfEventArray::new(0);

#[no_mangle]
static min_duration_ns: Global<u64> = Global::new(0);

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn handle_exec(ctx: TracePointContext) -> i32 {
    match try_handle_exec(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_exec(ctx: TracePointContext) -> Result<i32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    EXEC_START.insert(&pid, &ts, 0).ok();

    if min_duration_ns.load() != 0 {
        return Ok(0);
    }

    let mut e = Event {
        pid: 0,
        ppid: 0,
        exit_code: 0,
        _pad: 0,
        duration_ns: 0,
        comm: [0u8; TASK_COMM_LEN],
        filename: [0u8; MAX_FILENAME_LEN],
        exit_event: 0,
    };

    // SAFETY: bpf_get_current_task is an unsafe BPF helper
    let task = unsafe { bpf_get_current_task() } as *const u8;

    e.exit_event = 0;
    e.pid = pid;

    // BPF_CORE_READ(task, real_parent, tgid)
    // SAFETY: reading real_parent pointer from task struct
    let real_parent = unsafe {
        bpf_probe_read_kernel::<u64>(task.add(2504) as *const u64)
    }
    .unwrap_or(0);

    // SAFETY: reading tgid from real_parent
    let ppid = unsafe {
        bpf_probe_read_kernel::<i32>((real_parent as *const u8).add(2492) as *const i32)
    }
    .unwrap_or(0);

    e.ppid = ppid;

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    e.comm = comm;

    PERF_BUFFER.output(&ctx, &e, 0);

    Ok(0)
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(ctx: TracePointContext) -> i32 {
    match try_handle_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as i32;
    let tid = id as u32;

    if pid as u32 != tid {
        return Ok(0);
    }

    let mut duration_ns: u64 = 0;
    // SAFETY: HashMap::get is unsafe in aya-ebpf
    let start_ts = unsafe { EXEC_START.get(&pid) };
    if let Some(ts_ref) = start_ts {
        // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
        let now = unsafe { bpf_ktime_get_ns() };
        duration_ns = now - *ts_ref;
    } else if min_duration_ns.load() != 0 {
        return Ok(0);
    }

    EXEC_START.remove(&pid).ok();

    let min_dur = min_duration_ns.load();
    if min_dur != 0 && duration_ns < min_dur {
        return Ok(0);
    }

    let mut e = Event {
        pid: 0,
        ppid: 0,
        exit_code: 0,
        _pad: 0,
        duration_ns: 0,
        comm: [0u8; TASK_COMM_LEN],
        filename: [0u8; MAX_FILENAME_LEN],
        exit_event: 0,
    };

    // SAFETY: bpf_get_current_task is an unsafe BPF helper
    let task = unsafe { bpf_get_current_task() } as *const u8;

    e.exit_event = 1;
    e.duration_ns = duration_ns;
    e.pid = pid;

    // BPF_CORE_READ(task, real_parent, tgid)
    // SAFETY: reading real_parent pointer from task struct
    let real_parent = unsafe {
        bpf_probe_read_kernel::<u64>(task.add(2504) as *const u64)
    }
    .unwrap_or(0);

    // SAFETY: reading tgid from real_parent
    let ppid = unsafe {
        bpf_probe_read_kernel::<i32>((real_parent as *const u8).add(2492) as *const i32)
    }
    .unwrap_or(0);

    e.ppid = ppid;

    // BPF_CORE_READ(task, exit_code) >> 8 & 0xff
    // SAFETY: reading exit_code from task struct
    let exit_code_raw = unsafe {
        bpf_probe_read_kernel::<u32>(task.add(2388) as *const u32)
    }
    .unwrap_or(0);
    e.exit_code = (exit_code_raw >> 8) & 0xff;

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    e.comm = comm;

    PERF_BUFFER.output(&ctx, &e, 0);

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
