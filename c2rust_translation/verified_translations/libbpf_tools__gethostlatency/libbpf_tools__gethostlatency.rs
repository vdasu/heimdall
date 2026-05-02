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
const HOST_LEN: usize = 80;

#[repr(C)]
#[derive(Clone, Copy)]
struct event {
    time: u64,
    pid: u32,
    comm: [u8; TASK_COMM_LEN],
    host: [u8; HOST_LEN],
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

#[map(name = "starts")]
static STARTS: HashMap<u32, event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<event> = PerfEventArray::new(0);

fn probe_entry(ctx: &ProbeContext) -> Result<i32, i32> {
    let parm1: u64 = ctx.arg(0).ok_or(0i32)?;
    if parm1 == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let tp = target_pid.load();
    if tp != 0 && tp as u32 != pid {
        return Ok(0);
    }

    let mut ev = event {
        time: 0,
        pid: 0,
        comm: [0u8; TASK_COMM_LEN],
        host: [0u8; HOST_LEN],
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    ev.time = unsafe { bpf_ktime_get_ns() };
    ev.pid = pid;
    ev.comm = bpf_get_current_comm().map_err(|_| 0i32)?;
    // SAFETY: reading user-space memory via BPF helper
    ev.host = unsafe { bpf_probe_read_user(parm1 as *const [u8; HOST_LEN]) }.map_err(|_| 0i32)?;

    STARTS.insert(&tid, &ev, 0).map_err(|_| 0i32)?;

    Ok(0)
}

fn probe_return(ctx: &RetProbeContext) -> Result<i32, i32> {
    let tid = bpf_get_current_pid_tgid() as u32;

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let event_ref = match unsafe { STARTS.get(&tid) } {
        Some(r) => r,
        None => return Ok(0),
    };
    let mut ev = *event_ref;

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    ev.time = unsafe { bpf_ktime_get_ns() } - ev.time;

    EVENTS.output(ctx, &ev, 0);
    STARTS.remove(&tid).map_err(|_| 0i32)?;

    Ok(0)
}

#[uprobe]
pub fn handle_entry(ctx: ProbeContext) -> u32 {
    match probe_entry(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[uretprobe]
pub fn handle_return(ctx: RetProbeContext) -> u32 {
    match probe_return(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
