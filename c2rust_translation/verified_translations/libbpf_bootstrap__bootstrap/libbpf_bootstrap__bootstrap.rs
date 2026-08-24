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

const TASK_COMM_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 127;

#[repr(C)]
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

#[map(name = "rb")]
static RB: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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

    if let Some(mut entry) = RB.reserve::<Event>(0) {
        let event_ptr = entry.as_mut_ptr();
        // SAFETY: zero-initialize the reserved ring buffer memory
        unsafe {
            core::ptr::write_bytes(event_ptr as *mut u8, 0u8, core::mem::size_of::<Event>());
        }

        // SAFETY: bpf_get_current_task is an unsafe BPF helper
        let task = unsafe { bpf_get_current_task() } as *const u8;

        // SAFETY: writing exit_event to reserved entry
        unsafe { (*event_ptr).exit_event = 0 };
        // SAFETY: writing pid to reserved entry
        unsafe { (*event_ptr).pid = pid };

        // SAFETY: reading real_parent pointer from task struct at offset 2504
        let real_parent = unsafe {
            bpf_probe_read_kernel::<u64>(task.add(2504) as *const u64)
        }
        .unwrap_or(0);

        // SAFETY: reading tgid from real_parent at offset 2492
        let ppid = unsafe {
            bpf_probe_read_kernel::<i32>((real_parent as *const u8).add(2492) as *const i32)
        }
        .unwrap_or(0);

        // SAFETY: writing ppid to reserved entry
        unsafe { (*event_ptr).ppid = ppid };

        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        // SAFETY: writing comm to reserved entry
        unsafe { (*event_ptr).comm = comm };

        // SAFETY: reading __data_loc_filename from tracepoint context at offset 8
        let fname_off_raw: u32 = match unsafe { ctx.read_at(8) } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };
        let fname_off = (fname_off_raw & 0xFFFF) as usize;

        let ctx_ptr = ctx.as_ptr() as *const u8;

        // SAFETY: computing address of filename field in reserved entry
        let filename_ptr = unsafe { core::ptr::addr_of_mut!((*event_ptr).filename) as *mut u8 };
        // SAFETY: creating mutable slice for probe read destination
        let filename_dst =
            unsafe { core::slice::from_raw_parts_mut(filename_ptr, MAX_FILENAME_LEN) };

        // SAFETY: reading NUL-terminated filename string from tracepoint context
        match unsafe { bpf_probe_read_kernel_str_bytes(ctx_ptr.add(fname_off), filename_dst) } {
            Ok(_) => {}
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        }

        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(ctx: TracePointContext) -> i32 {
    match try_handle_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_exit(_ctx: TracePointContext) -> Result<i32, i64> {
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

    if let Some(mut entry) = RB.reserve::<Event>(0) {
        let event_ptr = entry.as_mut_ptr();
        // SAFETY: zero-initialize the reserved ring buffer memory
        unsafe {
            core::ptr::write_bytes(event_ptr as *mut u8, 0u8, core::mem::size_of::<Event>());
        }

        // SAFETY: bpf_get_current_task is an unsafe BPF helper
        let task = unsafe { bpf_get_current_task() } as *const u8;

        // SAFETY: writing exit_event to reserved entry
        unsafe { (*event_ptr).exit_event = 1 };
        // SAFETY: writing duration_ns to reserved entry
        unsafe { (*event_ptr).duration_ns = duration_ns };
        // SAFETY: writing pid to reserved entry
        unsafe { (*event_ptr).pid = pid };

        // SAFETY: reading real_parent pointer from task struct at offset 2504
        let real_parent = unsafe {
            bpf_probe_read_kernel::<u64>(task.add(2504) as *const u64)
        }
        .unwrap_or(0);

        // SAFETY: reading tgid from real_parent at offset 2492
        let ppid = unsafe {
            bpf_probe_read_kernel::<i32>((real_parent as *const u8).add(2492) as *const i32)
        }
        .unwrap_or(0);

        // SAFETY: writing ppid to reserved entry
        unsafe { (*event_ptr).ppid = ppid };

        // SAFETY: reading exit_code from task struct at offset 2388
        let exit_code_raw = unsafe {
            bpf_probe_read_kernel::<u32>(task.add(2388) as *const u32)
        }
        .unwrap_or(0);
        let exit_code = (exit_code_raw >> 8) & 0xff;
        // SAFETY: writing exit_code to reserved entry
        unsafe { (*event_ptr).exit_code = exit_code };

        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        // SAFETY: writing comm to reserved entry
        unsafe { (*event_ptr).comm = comm };

        entry.submit(0);
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
