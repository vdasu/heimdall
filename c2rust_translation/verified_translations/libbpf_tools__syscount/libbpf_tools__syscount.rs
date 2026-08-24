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
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_ENTRIES: u32 = 8192;
const TASK_COMM_LEN: usize = 16;
const GROUP_LEADER_OFFSET: usize = 2464;
const COMM_OFFSET_IN_TASK: usize = 3032;

#[repr(C)]
#[derive(Copy, Clone)]
struct DataT {
    count: u64,
    total_ns: u64,
    comm: [u8; TASK_COMM_LEN],
}

#[no_mangle]
static filter_cg: Global<bool> = Global::new(false);

#[no_mangle]
static count_by_process: Global<bool> = Global::new(false);

#[no_mangle]
static measure_latency: Global<bool> = Global::new(false);

#[no_mangle]
static filter_failed: Global<bool> = Global::new(false);

#[no_mangle]
static filter_errno: Global<i32> = Global::new(0);

#[no_mangle]
static filter_pid: Global<i32> = Global::new(0);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "data")]
static DATA: HashMap<u32, DataT> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn save_proc_name(val: *mut DataT) {
    // SAFETY: getting current task pointer
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let gl_src = task.wrapping_add(GROUP_LEADER_OFFSET) as *const *const u8;
    // SAFETY: reading group_leader from task_struct
    let group_leader: *const u8 = match unsafe { bpf_probe_read_kernel(gl_src) } {
        Ok(gl) => gl,
        Err(_) => return,
    };
    let comm_src = group_leader.wrapping_add(COMM_OFFSET_IN_TASK) as *const [u8; 16];
    // SAFETY: reading comm from group_leader task_struct
    let comm: [u8; 16] = match unsafe { bpf_probe_read_kernel(comm_src) } {
        Ok(c) => c,
        Err(_) => return,
    };
    // SAFETY: writing comm to valid map entry
    unsafe { (*val).comm = comm };
}

#[tracepoint]
pub fn sys_enter(_ctx: TracePointContext) -> i32 {
    match try_sys_enter(_ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter(_ctx: TracePointContext) -> Result<i32, i64> {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as i32;
    let tid = id as u32;

    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    if filter_pid.load() != 0 && pid != filter_pid.load() {
        return Ok(0);
    }

    // SAFETY: getting kernel timestamp
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&tid, &ts, 0);
    Ok(0)
}

#[tracepoint]
pub fn sys_exit(ctx: TracePointContext) -> i32 {
    match try_sys_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_exit(ctx: TracePointContext) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as i32;
    let tid = id as u32;

    // SAFETY: reading syscall id at offset 8 from tracepoint context
    let syscall_id: i64 = unsafe { ctx.read_at(8)? };

    if syscall_id == -1 {
        return Ok(0);
    }

    if filter_pid.load() != 0 && pid != filter_pid.load() {
        return Ok(0);
    }

    if filter_failed.load() {
        // SAFETY: reading syscall return value at offset 16 from tracepoint context
        let ret_val: i64 = unsafe { ctx.read_at(16)? };
        if ret_val >= 0 {
            return Ok(0);
        }
    }

    let fe = filter_errno.load();
    if fe != 0 {
        // SAFETY: reading syscall return value at offset 16 from tracepoint context
        let ret_val: i64 = unsafe { ctx.read_at(16)? };
        if ret_val != -(fe as i64) {
            return Ok(0);
        }
    }

    let mut lat: u64 = 0;
    if measure_latency.load() {
        // SAFETY: looking up start timestamp from map
        let start_ts = match unsafe { START.get(&tid) } {
            Some(ts) => *ts,
            None => return Ok(0),
        };
        // SAFETY: getting kernel timestamp
        lat = unsafe { bpf_ktime_get_ns() } - start_ts;
    }

    let key: u32 = if count_by_process.load() {
        pid as u32
    } else {
        syscall_id as u32
    };

    let zero = DataT {
        count: 0,
        total_ns: 0,
        comm: [0u8; TASK_COMM_LEN],
    };

    // bpf_map_lookup_or_try_init equivalent
    let val_ptr: Option<*mut DataT> = match DATA.get_ptr_mut(&key) {
        Some(ptr) => Some(ptr),
        None => {
            match DATA.insert(&key, &zero, 1) {
                Ok(()) => {}
                Err(e) if e == -17 => {}
                Err(_) => return Ok(0),
            }
            DATA.get_ptr_mut(&key)
        }
    };

    if let Some(ptr) = val_ptr {
        let count_ptr = ptr as *mut u64;
        // SAFETY: creating atomic from valid map pointer for count field
        let counter = unsafe { AtomicU64::from_ptr(count_ptr) };
        counter.fetch_add(1, Ordering::Relaxed);

        if count_by_process.load() {
            save_proc_name(ptr);
        }

        if measure_latency.load() {
            let total_ns_ptr = (ptr as *mut u8).wrapping_add(8) as *mut u64;
            // SAFETY: creating atomic from valid map pointer for total_ns field
            let atomic_ns = unsafe { AtomicU64::from_ptr(total_ns_ptr) };
            atomic_ns.fetch_add(lat, Ordering::Relaxed);
        }
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
