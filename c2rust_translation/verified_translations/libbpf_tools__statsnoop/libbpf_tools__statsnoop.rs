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

const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;
const NAME_MAX: usize = 255;
const INVALID_FD: i32 = -1;

const SYS_STATFS: u32 = 1;
const SYS_NEWSTAT: u32 = 2;
const SYS_STATX: u32 = 3;
const SYS_NEWFSTAT: u32 = 4;
const SYS_NEWFSTATAT: u32 = 5;
const SYS_NEWLSTAT: u32 = 6;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    ts_ns: u64,
    pid: u32,
    sys_type: u32,
    ret: i32,
    comm: [u8; TASK_COMM_LEN],
    fd: i32,
    dirfd: i32,
    pathname: [u8; NAME_MAX],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Value {
    fd: i32,
    dirfd: i32,
    pathname: u64,
    sys_type: u32,
}

#[no_mangle]
static target_pid: Global<u32> = Global::new(0);

#[no_mangle]
static trace_failed_only: Global<u8> = Global::new(0);

#[map(name = "values")]
static VALUES: HashMap<u32, Value> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn probe_entry(sys_type: u32, fd: i32, dirfd: i32, pathname: u64) -> i32 {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;
    let tid = id as u32;

    if pathname == 0 && fd == INVALID_FD && dirfd == INVALID_FD {
        return 0;
    }

    let targ_pid = target_pid.load();
    if targ_pid != 0 && targ_pid != pid {
        return 0;
    }

    let value = Value {
        fd,
        dirfd,
        pathname,
        sys_type,
    };

    let _ = VALUES.insert(&tid, &value, 0);
    0
}

#[inline(always)]
fn probe_return(ctx: &TracePointContext, ret: i32) -> i32 {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;
    let tid = id as u32;

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let val_ref = match unsafe { VALUES.get(&tid) } {
        Some(r) => r,
        None => return 0,
    };
    let val = *val_ref;

    if trace_failed_only.load() != 0 && ret >= 0 {
        let _ = VALUES.remove(&tid);
        return 0;
    }

    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    let ts_ns = unsafe { bpf_ktime_get_ns() };

    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let mut event = Event {
        ts_ns,
        pid,
        sys_type: val.sys_type,
        ret,
        comm,
        fd: val.fd,
        dirfd: val.dirfd,
        pathname: [0u8; NAME_MAX],
    };

    if val.pathname != 0 {
        // SAFETY: reading user string from user-space pointer stored in map
        unsafe {
            bpf_probe_read_user_str_bytes(val.pathname as *const u8, &mut event.pathname)
        }
        .unwrap_or(&[]);
    }

    EVENTS.output(ctx, &event, 0);
    let _ = VALUES.remove(&tid);
    0
}

#[tracepoint]
pub fn handle_statfs_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading args[0] (pathname) from tracepoint context
    let pathname: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(SYS_STATFS, INVALID_FD, INVALID_FD, pathname)
}

#[tracepoint]
pub fn handle_statfs_return(ctx: TracePointContext) -> i32 {
    // SAFETY: reading ret from tracepoint context
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_return(&ctx, ret as i32)
}

#[tracepoint]
pub fn handle_newstat_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading args[0] (pathname) from tracepoint context
    let pathname: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(SYS_NEWSTAT, INVALID_FD, INVALID_FD, pathname)
}

#[tracepoint]
pub fn handle_newstat_return(ctx: TracePointContext) -> i32 {
    // SAFETY: reading ret from tracepoint context
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_return(&ctx, ret as i32)
}

#[tracepoint]
pub fn handle_statx_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading args[0] (dirfd) from tracepoint context
    let arg0: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading args[1] (pathname) from tracepoint context
    let pathname: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(SYS_STATX, INVALID_FD, arg0 as i32, pathname)
}

#[tracepoint]
pub fn handle_statx_return(ctx: TracePointContext) -> i32 {
    // SAFETY: reading ret from tracepoint context
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_return(&ctx, ret as i32)
}

#[tracepoint]
pub fn handle_newfstat_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading args[0] (fd) from tracepoint context
    let arg0: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(SYS_NEWFSTAT, arg0 as i32, INVALID_FD, 0)
}

#[tracepoint]
pub fn handle_newfstat_return(ctx: TracePointContext) -> i32 {
    // SAFETY: reading ret from tracepoint context
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_return(&ctx, ret as i32)
}

#[tracepoint]
pub fn handle_newfstatat_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading args[0] (dirfd) from tracepoint context
    let arg0: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading args[1] (pathname) from tracepoint context
    let pathname: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(SYS_NEWFSTATAT, INVALID_FD, arg0 as i32, pathname)
}

#[tracepoint]
pub fn handle_newfstatat_return(ctx: TracePointContext) -> i32 {
    // SAFETY: reading ret from tracepoint context
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_return(&ctx, ret as i32)
}

#[tracepoint]
pub fn handle_newlstat_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading args[0] (pathname) from tracepoint context
    let pathname: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(SYS_NEWLSTAT, INVALID_FD, INVALID_FD, pathname)
}

#[tracepoint]
pub fn handle_newlstat_return(ctx: TracePointContext) -> i32 {
    // SAFETY: reading ret from tracepoint context
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_return(&ctx, ret as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
