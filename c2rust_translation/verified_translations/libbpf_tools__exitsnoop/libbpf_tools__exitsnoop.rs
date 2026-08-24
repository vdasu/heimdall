#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::Global;

const TASK_COMM_LEN: usize = 16;
const EXIT_CODE_OFFSET: usize = 2388;
const START_TIME_OFFSET: usize = 2832;
const REAL_PARENT_OFFSET: usize = 2504;
const TGID_OFFSET: usize = 2492;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    start_time: u64,
    exit_time: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    sig: u32,
    exit_code: i32,
    comm: [u8; TASK_COMM_LEN],
    _pad: [u8; 4],
}

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".rodata"]
static filter_cg: Global<u8> = Global::new(0);

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".rodata"]
static target_pid: Global<u32> = Global::new(0);

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".rodata"]
static trace_failed_only: Global<u8> = Global::new(0);

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".rodata"]
static trace_by_process: Global<u8> = Global::new(1);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_process_exit(ctx: TracePointContext) -> i32 {
    match try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_process_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let targ = target_pid.load();
    if targ != 0 && targ != pid {
        return Ok(0);
    }

    if trace_by_process.load() == 1 && pid != tid {
        return Ok(0);
    }

    // SAFETY: getting current task pointer
    let task = unsafe { bpf_get_current_task() } as usize;

    // SAFETY: reading exit_code from task_struct
    let exit_code: i32 = unsafe {
        bpf_probe_read_kernel((task + EXIT_CODE_OFFSET) as *const i32)
    }?;

    if trace_failed_only.load() == 1 && exit_code == 0 {
        return Ok(0);
    }

    // SAFETY: reading start_time from task_struct
    let start_time: u64 = unsafe {
        bpf_probe_read_kernel((task + START_TIME_OFFSET) as *const u64)
    }?;

    // SAFETY: getting current time in nanoseconds
    let exit_time = unsafe { bpf_ktime_get_ns() };

    // SAFETY: reading real_parent pointer from task_struct
    let real_parent: usize = unsafe {
        bpf_probe_read_kernel((task + REAL_PARENT_OFFSET) as *const usize)
    }?;

    // SAFETY: reading tgid from real_parent task_struct for ppid
    let ppid: u32 = unsafe {
        bpf_probe_read_kernel((real_parent + TGID_OFFSET) as *const u32)
    }?;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    let event = Event {
        start_time,
        exit_time,
        pid,
        tid,
        ppid,
        sig: (exit_code & 0xff) as u32,
        exit_code: exit_code >> 8,
        comm,
        _pad: [0; 4],
    };

    EVENTS.output(&ctx, &event, 0);

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
