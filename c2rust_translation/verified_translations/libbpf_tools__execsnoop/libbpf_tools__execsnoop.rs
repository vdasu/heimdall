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
use aya_ebpf::Global;

const ARGSIZE: usize = 128;
const TASK_COMM_LEN: usize = 16;
const TOTAL_MAX_ARGS: usize = 60;
const DEFAULT_MAXARGS: i32 = 20;
const FULL_MAX_ARGS_ARR: usize = TOTAL_MAX_ARGS * ARGSIZE;
const INVALID_UID: u32 = 0xFFFFFFFF;
const LAST_ARG: usize = FULL_MAX_ARGS_ARR - ARGSIZE;

const BASE_EVENT_SIZE: usize = 40;
const OFF_TASK_REAL_PARENT: usize = 2504;
const OFF_TASK_TGID: usize = 2492;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: i32,
    ppid: i32,
    uid: u32,
    retval: i32,
    args_count: i32,
    args_size: u32,
    comm: [u8; TASK_COMM_LEN],
    args: [u8; FULL_MAX_ARGS_ARR],
}

#[no_mangle]
static filter_cg: Global<u8> = Global::new(0);
#[no_mangle]
static ignore_failed: Global<u8> = Global::new(1);
#[no_mangle]
static targ_uid: Global<u32> = Global::new(INVALID_UID);
#[no_mangle]
static max_args: Global<i32> = Global::new(DEFAULT_MAXARGS);

static EMPTY_EVENT: Event = Event {
    pid: 0,
    ppid: 0,
    uid: 0,
    retval: 0,
    args_count: 0,
    args_size: 0,
    comm: [0; TASK_COMM_LEN],
    args: [0; FULL_MAX_ARGS_ARR],
};

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "execs")]
static EXECS: HashMap<i32, Event> = HashMap::with_max_entries(10240, 0);

#[map(name = "events")]
static EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

#[inline(always)]
fn lookup_execs(pid: &i32) -> Option<*mut Event> {
    EXECS.get_ptr_mut(pid)
}

#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn tracepoint__syscalls__sys_enter_execve(ctx: TracePointContext) -> i32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;

    // SAFETY: advancing to argv field at offset 24
    let argv_ptr = unsafe { ctx_ptr.add(24) };
    // SAFETY: reading argv pointer from tracepoint context
    let argv: u64 = unsafe { *(argv_ptr as *const u64) };

    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let tu = targ_uid.load();
    if tu != INVALID_UID && tu != uid {
        return Ok(0);
    }

    let id = bpf_get_current_pid_tgid();
    let pid = id as i32;
    let tgid = (id >> 32) as i32;

    if EXECS.insert(&pid, &EMPTY_EVENT, 1).is_err() {
        return Ok(0);
    }

    let event = match lookup_execs(&pid) {
        Some(p) => p,
        None => return Ok(0),
    };

    // SAFETY: writing uid to event
    unsafe { (*event).uid = uid };
    // SAFETY: writing pid (=tgid) to event
    unsafe { (*event).pid = tgid };

    // SAFETY: getting current task pointer
    let task = unsafe { bpf_get_current_task() } as *const u8;
    // SAFETY: reading real_parent from task_struct
    let real_parent: u64 = unsafe {
        bpf_probe_read_kernel(task.add(OFF_TASK_REAL_PARENT) as *const u64)?
    };
    // SAFETY: reading tgid from parent task_struct
    let ppid: i32 = unsafe {
        bpf_probe_read_kernel((real_parent as *const u8).add(OFF_TASK_TGID) as *const i32)?
    };

    // SAFETY: writing args_size = 0
    unsafe { (*event).args_size = 0 };
    // SAFETY: writing args_count = 0
    unsafe { (*event).args_count = 0 };
    // SAFETY: writing ppid
    unsafe { (*event).ppid = ppid };

    // SAFETY: advancing to filename field at offset 16
    let arg0_ptr = unsafe { ctx_ptr.add(16) };
    // SAFETY: reading filename pointer from tracepoint context
    let arg0: u64 = unsafe { *(arg0_ptr as *const u64) };

    // SAFETY: getting pointer to args buffer in map entry
    let args_base = unsafe { (*event).args.as_mut_ptr() };
    // SAFETY: creating destination slice for first arg
    let dest = unsafe { core::slice::from_raw_parts_mut(args_base, ARGSIZE) };
    // SAFETY: reading user string for first arg
    let result = unsafe { bpf_probe_read_user_str_bytes(arg0 as *const u8, dest) };
    let ret_len = match result {
        Ok(s) => s.len() as u32 + 1,
        Err(_) => return Ok(0),
    };

    if ret_len <= ARGSIZE as u32 {
        // SAFETY: reading current args_size
        let cs = unsafe { (*event).args_size };
        // SAFETY: writing updated args_size
        unsafe { (*event).args_size = cs + ret_len };
    } else {
        // SAFETY: writing null terminator for oversized return
        unsafe { *args_base = 0 };
        // SAFETY: reading current args_size
        let cs = unsafe { (*event).args_size };
        // SAFETY: writing args_size += 1
        unsafe { (*event).args_size = cs + 1 };
    }

    // SAFETY: reading current args_count
    let cc = unsafe { (*event).args_count };
    // SAFETY: writing args_count += 1
    unsafe { (*event).args_count = cc + 1 };

    for i in 1..TOTAL_MAX_ARGS {
        let ma = max_args.load();
        if (i as i32) >= ma {
            break;
        }

        // SAFETY: calculating pointer to argv[i]
        let arg_addr = unsafe { (argv as *const u64).add(i) };
        // SAFETY: reading argument pointer from user argv array
        let argp: u64 = unsafe { bpf_probe_read_user(arg_addr)? };

        // SAFETY: reading current args_size for bounds check
        let current_size = unsafe { (*event).args_size } as usize;
        if current_size > LAST_ARG {
            return Ok(0);
        }

        // SAFETY: getting args buffer base pointer
        let args_ptr = unsafe { (*event).args.as_mut_ptr() };
        // SAFETY: advancing to current write offset
        let dest_ptr = unsafe { args_ptr.add(current_size) };
        // SAFETY: creating destination slice for this arg
        let dest = unsafe { core::slice::from_raw_parts_mut(dest_ptr, ARGSIZE) };
        // SAFETY: reading user string for this argument
        let str_result = unsafe { bpf_probe_read_user_str_bytes(argp as *const u8, dest) };
        let str_len = match str_result {
            Ok(s) => s.len() as u32 + 1,
            Err(_) => return Ok(0),
        };

        // SAFETY: reading args_count
        let cc = unsafe { (*event).args_count };
        // SAFETY: writing args_count += 1
        unsafe { (*event).args_count = cc + 1 };

        // SAFETY: reading args_size
        let cs = unsafe { (*event).args_size };
        // SAFETY: writing updated args_size
        unsafe { (*event).args_size = cs + str_len };
    }

    let ma = max_args.load();
    // SAFETY: calculating pointer to argv[max_args]
    let final_arg_addr = unsafe { (argv as *const u64).add(ma as usize) };
    // SAFETY: reading argument pointer at argv[max_args]
    let _extra: u64 = unsafe { bpf_probe_read_user(final_arg_addr)? };

    // SAFETY: reading args_count
    let cc = unsafe { (*event).args_count };
    // SAFETY: writing args_count += 1
    unsafe { (*event).args_count = cc + 1 };

    Ok(0)
}

#[tracepoint(name = "sys_exit_execve", category = "syscalls")]
pub fn tracepoint__syscalls__sys_exit_execve(ctx: TracePointContext) -> i32 {
    match try_sys_exit_execve(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_exit_execve(ctx: TracePointContext) -> Result<i32, i64> {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let tu = targ_uid.load();
    if tu != INVALID_UID && tu != uid {
        return Ok(0);
    }

    let id = bpf_get_current_pid_tgid();
    let pid = id as i32;

    let event = match lookup_execs(&pid) {
        Some(p) => p,
        None => return Ok(0),
    };

    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: advancing to ret field at offset 16
    let ret_ptr = unsafe { ctx_ptr.add(16) };
    // SAFETY: reading return value from tracepoint context
    let ret_val: i64 = unsafe { *(ret_ptr as *const i64) };

    if ignore_failed.load() == 1 && (ret_val as i32) < 0 {
        EXECS.remove(&pid).ok();
        return Ok(0);
    }

    // SAFETY: writing retval to event
    unsafe { (*event).retval = ret_val as i32 };

    if let Ok(comm) = bpf_get_current_comm() {
        // SAFETY: writing comm to event
        unsafe { (*event).comm = comm };
    }

    // SAFETY: reading args_size for size check
    let args_size = unsafe { (*event).args_size };
    if args_size <= FULL_MAX_ARGS_ARR as u32 {
        let event_len = BASE_EVENT_SIZE + args_size as usize;
        // SAFETY: creating byte slice over event for variable-size perf output
        let event_bytes = unsafe { core::slice::from_raw_parts(event as *const u8, event_len) };
        EVENTS.output(&ctx, event_bytes, 0);
    }

    EXECS.remove(&pid).ok();

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
