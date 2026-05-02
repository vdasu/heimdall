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
use aya_ebpf::{EbpfContext, Global};

const TASK_COMM_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 127;

#[repr(C)]
struct event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    duration_ns: u64,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; MAX_FILENAME_LEN],
    exit_event: u8,
}

#[no_mangle]
static min_duration_ns: Global<u64> = Global::new(0);

#[map(name = "exec_start")]
static EXEC_START: HashMap<i32, u64> = HashMap::with_max_entries(8192, 0);

#[map(name = "rb")]
static RB: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn handle_exec(ctx: TracePointContext) -> u32 {
    match try_handle_exec(&ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_handle_exec(ctx: &TracePointContext) -> Result<i32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    // SAFETY: reading kernel monotonic time
    let ts = unsafe { bpf_ktime_get_ns() };

    EXEC_START.insert(&pid, &ts, 0).ok();

    if min_duration_ns.load() != 0 {
        return Ok(0);
    }

    // SAFETY: calling bpf_get_current_task to get task struct pointer
    let task = unsafe { bpf_get_current_task() } as u64;

    let task_ptr = task as *const u8;
    // SAFETY: computing address of real_parent field in task_struct
    let real_parent_addr = unsafe { task_ptr.add(2504) };
    // SAFETY: reading task->real_parent pointer via probe_read_kernel
    let real_parent: u64 =
        unsafe { bpf_probe_read_kernel(real_parent_addr as *const u64) }.unwrap_or(0);

    let rp_ptr = real_parent as *const u8;
    // SAFETY: computing address of tgid field in parent task_struct
    let tgid_addr = unsafe { rp_ptr.add(2492) };
    // SAFETY: reading real_parent->tgid via probe_read_kernel
    let ppid: i32 = unsafe { bpf_probe_read_kernel(tgid_addr as *const i32) }.unwrap_or(0);

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    let ctx_base = ctx.as_ptr() as *const u8;
    // SAFETY: computing pointer to __data_loc_filename at offset 8 in context
    let fname_off_ptr = unsafe { ctx_base.add(8) };
    // SAFETY: reading __data_loc_filename u32 from tracepoint context
    let fname_off_raw = unsafe { core::ptr::read(fname_off_ptr as *const u32) };
    let fname_off = (fname_off_raw & 0xFFFF) as usize;
    // SAFETY: computing filename source address in tracepoint data
    let fname_src = unsafe { ctx_base.add(fname_off) };

    let mut entry = match RB.reserve::<event>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    // SAFETY: zero-initializing reserved ringbuf memory to prevent stale data leaks
    unsafe {
        core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, 0u8, core::mem::size_of::<event>())
    };

    let e = entry.as_mut_ptr();

    // SAFETY: writing exit_event field to valid ringbuf entry
    unsafe { (*e).exit_event = 0 };
    // SAFETY: writing pid field to valid ringbuf entry
    unsafe { (*e).pid = pid };
    // SAFETY: writing ppid field to valid ringbuf entry
    unsafe { (*e).ppid = ppid };
    // SAFETY: writing comm field to valid ringbuf entry
    unsafe { (*e).comm = comm };

    // SAFETY: getting mutable reference to filename field in ringbuf entry
    let filename_slice = unsafe { &mut (*e).filename };
    // SAFETY: reading filename string from tracepoint data
    if unsafe { bpf_probe_read_kernel_str_bytes(fname_src, filename_slice) }.is_err() {
        entry.discard(0);
        return Ok(0);
    }

    entry.submit(0);
    Ok(0)
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    match try_handle_exit(&ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_handle_exit(_ctx: &TracePointContext) -> Result<i32, i64> {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as i32;
    let tid = id as u32;

    if pid as u32 != tid {
        return Ok(0);
    }

    let mut duration_ns: u64 = 0;

    match EXEC_START.get_ptr(&pid) {
        Some(start_ts_ptr) => {
            // SAFETY: dereferencing valid map pointer from BPF lookup
            let ts_val = unsafe { *start_ts_ptr };
            // SAFETY: reading kernel monotonic time
            let now = unsafe { bpf_ktime_get_ns() };
            duration_ns = now - ts_val;
        }
        None => {
            if min_duration_ns.load() != 0 {
                return Ok(0);
            }
        }
    }

    EXEC_START.remove(&pid).ok();

    if min_duration_ns.load() != 0 && duration_ns < min_duration_ns.load() {
        return Ok(0);
    }

    // SAFETY: calling bpf_get_current_task to get task struct pointer
    let task = unsafe { bpf_get_current_task() } as u64;

    let task_ptr = task as *const u8;
    // SAFETY: computing address of real_parent field in task_struct
    let real_parent_addr = unsafe { task_ptr.add(2504) };
    // SAFETY: reading task->real_parent pointer via probe_read_kernel
    let real_parent: u64 =
        unsafe { bpf_probe_read_kernel(real_parent_addr as *const u64) }.unwrap_or(0);

    let rp_ptr = real_parent as *const u8;
    // SAFETY: computing address of tgid field in parent task_struct
    let tgid_addr = unsafe { rp_ptr.add(2492) };
    // SAFETY: reading real_parent->tgid via probe_read_kernel
    let ppid: i32 = unsafe { bpf_probe_read_kernel(tgid_addr as *const i32) }.unwrap_or(0);

    // SAFETY: computing address of exit_code field in task_struct
    let exit_code_addr = unsafe { task_ptr.add(2388) };
    // SAFETY: reading task->exit_code via probe_read_kernel
    let exit_code_raw: u32 =
        unsafe { bpf_probe_read_kernel(exit_code_addr as *const u32) }.unwrap_or(0);
    let exit_code = (exit_code_raw >> 8) & 0xff;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    let mut entry = match RB.reserve::<event>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    // SAFETY: zero-initializing reserved ringbuf memory to prevent stale data leaks
    unsafe {
        core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, 0u8, core::mem::size_of::<event>())
    };

    let e = entry.as_mut_ptr();

    // SAFETY: writing exit_event field to valid ringbuf entry
    unsafe { (*e).exit_event = 1 };
    // SAFETY: writing duration_ns field to valid ringbuf entry
    unsafe { (*e).duration_ns = duration_ns };
    // SAFETY: writing pid field to valid ringbuf entry
    unsafe { (*e).pid = pid };
    // SAFETY: writing ppid field to valid ringbuf entry
    unsafe { (*e).ppid = ppid };
    // SAFETY: writing exit_code field to valid ringbuf entry
    unsafe { (*e).exit_code = exit_code };
    // SAFETY: writing comm field to valid ringbuf entry
    unsafe { (*e).comm = comm };

    entry.submit(0);
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
