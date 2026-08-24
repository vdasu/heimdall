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
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;
const HOST_LEN: usize = 80;

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    time: u64,
    pid: u32,
    comm: [u8; TASK_COMM_LEN],
    host: [u8; HOST_LEN],
    _pad: [u8; 4],
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

#[map(name = "starts")]
static STARTS: HashMap<u32, Event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[uprobe]
pub fn handle_entry(ctx: ProbeContext) -> i32 {
    match try_handle_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_entry(ctx: ProbeContext) -> Result<i32, i64> {
    let parm1: u64 = ctx.arg(0).ok_or(1i64)?;
    if parm1 == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let targ_pid = target_pid.load();
    if targ_pid != 0 && targ_pid as u32 != pid {
        return Ok(0);
    }

    let mut event = Event {
        time: 0,
        pid: 0,
        comm: [0u8; TASK_COMM_LEN],
        host: [0u8; HOST_LEN],
        _pad: [0u8; 4],
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    event.time = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.comm = bpf_get_current_comm()?;
    // SAFETY: reading NUL-terminated string from user space
    unsafe { bpf_probe_read_user_str_bytes(parm1 as *const u8, &mut event.host) }?;

    STARTS.insert(&tid, &event, 0).ok();
    Ok(0)
}

#[uretprobe]
pub fn handle_return(ctx: RetProbeContext) -> i32 {
    match try_handle_return(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle_return(ctx: RetProbeContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let eventp = match unsafe { STARTS.get(&tid) } {
        Some(e) => e,
        None => return Ok(0),
    };

    let mut event = *eventp;
    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    event.time = unsafe { bpf_ktime_get_ns() } - event.time;

    EVENTS.output(&ctx, &event, 0);
    STARTS.remove(&tid).ok();
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
