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
use aya_ebpf::EbpfContext;
use aya_ebpf::cty::c_long;
use aya_ebpf::Global;

const TASK_COMM_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 127;

const REAL_PARENT_OFF: usize = 2456;
const TGID_OFF: usize = 2340;
const EXIT_CODE_OFF: usize = 2408;

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

#[tracepoint]
pub fn handle_exec(ctx: TracePointContext) -> i32 {
    match try_handle_exec(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_exec(ctx: TracePointContext) -> Result<i32, c_long> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = EXEC_START.insert(&pid, &ts, 0);

    if min_duration_ns.load() != 0 {
        return Ok(0);
    }

    // SAFETY: bpf_get_current_task is an unsafe binding
    let task = unsafe { bpf_get_current_task() } as *const u8;

    let mut e = Event {
        pid,
        ppid: 0,
        exit_code: 0,
        _pad: 0,
        duration_ns: 0,
        comm: [0u8; TASK_COMM_LEN],
        filename: [0u8; MAX_FILENAME_LEN],
        exit_event: 0,
    };

    e.comm = bpf_get_current_comm()?;

    // SAFETY: computing pointer to real_parent field in task_struct
    let real_parent_ptr = unsafe { task.add(REAL_PARENT_OFF) } as *const *const u8;
    // SAFETY: reading real_parent pointer from task_struct
    let parent = unsafe { bpf_probe_read_kernel(real_parent_ptr) }?;
    // SAFETY: computing pointer to tgid field in parent task_struct
    let tgid_ptr = unsafe { parent.add(TGID_OFF) } as *const i32;
    // SAFETY: reading tgid from parent task_struct
    e.ppid = unsafe { bpf_probe_read_kernel(tgid_ptr) }?;

    // SAFETY: reading __data_loc_filename field from tracepoint context
    let data_loc: u32 = unsafe { ctx.read_at(8) }?;
    let fname_off = (data_loc & 0xFFFF) as usize;

    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: computing filename address within tracepoint data
    let fname_src = unsafe { ctx_ptr.add(fname_off) };
    // SAFETY: reading filename string from kernel memory
    unsafe { bpf_probe_read_kernel_str_bytes(fname_src, &mut e.filename) }?;

    PERF_BUFFER.output(&ctx, &e, 0);
    Ok(0)
}

#[tracepoint]
pub fn handle_exit(ctx: TracePointContext) -> i32 {
    match try_handle_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_exit(ctx: TracePointContext) -> Result<i32, c_long> {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as i32;
    let tid = id as u32;

    if pid as u32 != tid {
        return Ok(0);
    }

    let mut duration_ns: u64 = 0;
    // SAFETY: HashMap::get requires unsafe
    let start_ts = unsafe { EXEC_START.get(&pid) };
    if let Some(ts_ref) = start_ts {
        // SAFETY: bpf_ktime_get_ns is an unsafe binding
        duration_ns = unsafe { bpf_ktime_get_ns() } - *ts_ref;
    } else if min_duration_ns.load() != 0 {
        return Ok(0);
    }
    let _ = EXEC_START.remove(&pid);

    let min_dur = min_duration_ns.load();
    if min_dur != 0 && duration_ns < min_dur {
        return Ok(0);
    }

    // SAFETY: bpf_get_current_task is an unsafe binding
    let task = unsafe { bpf_get_current_task() } as *const u8;

    let mut e = Event {
        pid,
        ppid: 0,
        exit_code: 0,
        _pad: 0,
        duration_ns,
        comm: [0u8; TASK_COMM_LEN],
        filename: [0u8; MAX_FILENAME_LEN],
        exit_event: 1,
    };

    // SAFETY: computing pointer to real_parent field in task_struct
    let real_parent_ptr = unsafe { task.add(REAL_PARENT_OFF) } as *const *const u8;
    // SAFETY: reading real_parent pointer from task_struct
    let parent = unsafe { bpf_probe_read_kernel(real_parent_ptr) }?;
    // SAFETY: computing pointer to tgid field in parent task_struct
    let tgid_ptr = unsafe { parent.add(TGID_OFF) } as *const i32;
    // SAFETY: reading tgid from parent task_struct
    e.ppid = unsafe { bpf_probe_read_kernel(tgid_ptr) }?;

    // SAFETY: computing pointer to exit_code field in task_struct
    let exit_code_ptr = unsafe { task.add(EXIT_CODE_OFF) } as *const u32;
    // SAFETY: reading exit_code from task_struct
    let exit_code_raw = unsafe { bpf_probe_read_kernel(exit_code_ptr) }?;
    e.exit_code = (exit_code_raw >> 8) & 0xff;

    e.comm = bpf_get_current_comm()?;

    PERF_BUFFER.output(&ctx, &e, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
