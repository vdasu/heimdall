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
use aya_ebpf::cty::*;
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

const INVALID_UID: u32 = 0xFFFFFFFF;
const NAME_MAX: usize = 255;
const MAX_PATH_DEPTH: usize = 32;
const O_CREAT: i32 = 0o100;
const O_TMPFILE: i32 = 0o20200000;
const MAX_EVENT_SIZE: usize = 10240;
const RINGBUF_SIZE: u32 = 1024 * 256;
const FULL_PATH_SIZE: usize = NAME_MAX * MAX_PATH_DEPTH;
const EVENT_SIZE: usize = 8232;
const BPF_F_USER_STACK: u64 = 256;

#[repr(C)]
#[derive(Copy, Clone)]
struct ArgsT {
    fname: u64,
    flags: i32,
    mode: u32,
}

#[repr(C)]
struct EventBuf {
    _data: [u8; EVENT_SIZE],
}

#[map(name = "heap")]
static HEAP: PerCpuArray<[u8; MAX_EVENT_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE, 0);

#[map(name = "start")]
static START: HashMap<u32, ArgsT> = HashMap::with_max_entries(10240, 0);

#[no_mangle]
static targ_pid: Global<i32> = Global::new(0);

#[no_mangle]
static targ_tgid: Global<i32> = Global::new(0);

#[no_mangle]
static targ_uid: Global<u32> = Global::new(0);

#[no_mangle]
static targ_failed: Global<u8> = Global::new(0);

#[no_mangle]
static full_path: Global<u8> = Global::new(0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[inline(always)]
fn trace_allowed(tgid: u32, pid: u32) -> bool {
    let t_tgid = targ_tgid.load();
    if t_tgid != 0 && t_tgid as u32 != tgid {
        return false;
    }
    let t_pid = targ_pid.load();
    if t_pid != 0 && t_pid as u32 != pid {
        return false;
    }
    let t_uid = targ_uid.load();
    if t_uid != INVALID_UID {
        let uid = bpf_get_current_uid_gid() as u32;
        if t_uid != uid {
            return false;
        }
    }
    true
}

#[inline(always)]
fn trace_exit(ctx: &TracePointContext) -> Result<i32, i64> {
    let pid = bpf_get_current_pid_tgid() as u32;

    // SAFETY: HashMap::get is pub unsafe fn
    let ap = match unsafe { START.get(&pid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint at offset 16
    let ret_raw = unsafe { *((c + 16) as *const u64) };
    let ret = ret_raw as i32;

    let tf = targ_failed.load();
    if tf != 0 && ret >= 0 {
        START.remove(&pid).ok();
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<EventBuf>(0) {
        // SAFETY: zero-initializing reserved ringbuf memory to prevent stale data leaks
        unsafe {
            core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, 0u8, core::mem::size_of::<EventBuf>());
        }
        let evt = entry.as_mut_ptr() as usize;

        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        // SAFETY: writing pid (tgid) to ringbuf entry at offset 8
        unsafe { *((evt + 8) as *mut u32) = tgid };

        let uid = bpf_get_current_uid_gid() as u32;
        // SAFETY: writing uid to ringbuf entry at offset 12
        unsafe { *((evt + 12) as *mut u32) = uid };

        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => {
                entry.discard(0);
                START.remove(&pid).ok();
                return Ok(0);
            }
        };
        // SAFETY: writing comm to ringbuf entry at offset 48
        unsafe { *((evt + 48) as *mut [u8; 16]) = comm };

        // SAFETY: creating dst slice for fname read into ringbuf at offset 64
        let dst = unsafe {
            core::slice::from_raw_parts_mut((evt + 64) as *mut u8, FULL_PATH_SIZE)
        };
        match unsafe { bpf_probe_read_user_str_bytes(ap.fname as *const u8, dst) } {
            Ok(_) => {}
            Err(_) => {
                entry.discard(0);
                START.remove(&pid).ok();
                return Ok(0);
            }
        };

        // SAFETY: writing fname.depth = 0 at offset 8224
        unsafe { *((evt + 8224) as *mut u32) = 0 };

        // SAFETY: writing flags to ringbuf entry at offset 20
        unsafe { *((evt + 20) as *mut i32) = ap.flags };

        if (ap.flags & O_CREAT != 0) || ((ap.flags & O_TMPFILE) == O_TMPFILE) {
            // SAFETY: writing mode to ringbuf entry at offset 24
            unsafe { *((evt + 24) as *mut u32) = ap.mode };
        } else {
            // SAFETY: writing mode=0 to ringbuf entry at offset 24
            unsafe { *((evt + 24) as *mut u32) = 0 };
        }

        // SAFETY: writing ret to ringbuf entry at offset 16
        unsafe { *((evt + 16) as *mut i32) = ret };

        let mut stack_buf: [u64; 3] = [0u64; 3];
        // SAFETY: calling bpf_get_stack to read user stack frames
        unsafe {
            bpf_get_stack(
                ctx.as_ptr() as *mut c_void,
                stack_buf.as_mut_ptr() as *mut c_void,
                24,
                BPF_F_USER_STACK,
            );
        }
        // SAFETY: writing callers[0] to ringbuf entry at offset 32
        unsafe { *((evt + 32) as *mut u64) = stack_buf[1] };
        // SAFETY: writing callers[1] to ringbuf entry at offset 40
        unsafe { *((evt + 40) as *mut u64) = stack_buf[2] };

        let fp = full_path.load();
        if fp != 0 {
            // SAFETY: reading first byte of fname.pathes at offset 64
            let first_byte = unsafe { *((evt + 64) as *const u8) };
            if first_byte != b'/' {
                // bpf_getcwd would be called here - requires CO-RE, not reachable with full_path=0
            }
        }

        entry.submit(0);
    }

    START.remove(&pid).ok();
    Ok(0)
}

// ===== sys_enter_open =====

#[tracepoint(category = "syscalls", name = "sys_enter_open")]
pub fn tracepoint__syscalls__sys_enter_open(ctx: TracePointContext) -> i32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_open(ctx: TracePointContext) -> Result<i32, i64> {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    if trace_allowed(tgid, pid) {
        let c = ctx.as_ptr() as usize;
        // SAFETY: reading args[0] (fname) from tracepoint context
        let fname = unsafe { *((c + 16) as *const u64) };
        // SAFETY: reading args[1] (flags) from tracepoint context
        let flags = unsafe { *((c + 24) as *const u64) } as i32;
        // SAFETY: reading args[2] (mode) from tracepoint context
        let mode = unsafe { *((c + 32) as *const u64) } as u32;

        let args = ArgsT { fname, flags, mode };
        START.insert(&pid, &args, 0).ok();
    }
    Ok(0)
}

// ===== sys_enter_openat =====

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn tracepoint__syscalls__sys_enter_openat(ctx: TracePointContext) -> i32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<i32, i64> {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    if trace_allowed(tgid, pid) {
        let c = ctx.as_ptr() as usize;
        // SAFETY: reading args[1] (fname) from tracepoint context
        let fname = unsafe { *((c + 24) as *const u64) };
        // SAFETY: reading args[2] (flags) from tracepoint context
        let flags = unsafe { *((c + 32) as *const u64) } as i32;
        // SAFETY: reading args[3] (mode) from tracepoint context
        let mode = unsafe { *((c + 40) as *const u64) } as u32;

        let args = ArgsT { fname, flags, mode };
        START.insert(&pid, &args, 0).ok();
    }
    Ok(0)
}

// ===== sys_enter_openat2 =====

#[tracepoint(category = "syscalls", name = "sys_enter_openat2")]
pub fn tracepoint__syscalls__sys_enter_openat2(ctx: TracePointContext) -> i32 {
    match try_sys_enter_openat2(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_openat2(ctx: TracePointContext) -> Result<i32, i64> {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    if trace_allowed(tgid, pid) {
        let c = ctx.as_ptr() as usize;
        // SAFETY: reading args[1] (fname) from tracepoint context
        let fname = unsafe { *((c + 24) as *const u64) };
        // SAFETY: reading args[2] (how_ptr) from tracepoint context
        let how_ptr = unsafe { *((c + 32) as *const u64) };

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }

        let how = match unsafe { bpf_probe_read_user(how_ptr as *const OpenHow) } {
            Ok(h) => h,
            Err(_) => return Ok(0),
        };

        let args = ArgsT {
            fname,
            flags: how.flags as i32,
            mode: how.mode as u32,
        };
        START.insert(&pid, &args, 0).ok();
    }
    Ok(0)
}

// ===== sys_exit_open =====

#[tracepoint(category = "syscalls", name = "sys_exit_open")]
pub fn tracepoint__syscalls__sys_exit_open(ctx: TracePointContext) -> i32 {
    match trace_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// ===== sys_exit_openat =====

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
pub fn tracepoint__syscalls__sys_exit_openat(ctx: TracePointContext) -> i32 {
    match trace_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// ===== sys_exit_openat2 =====

#[tracepoint(category = "syscalls", name = "sys_exit_openat2")]
pub fn tracepoint__syscalls__sys_exit_openat2(ctx: TracePointContext) -> i32 {
    match trace_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}
