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

const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct start_req_t {
    ts: u64,
    data_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct who_t {
    pid: u32,
    name: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct info_t {
    pid: u32,
    rwflag: i32,
    major: i32,
    minor: i32,
    name: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct val_t {
    bytes: u64,
    us: u64,
    io: u32,
}

#[no_mangle]
static target_pid: Global<u32> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u64, start_req_t> = HashMap::with_max_entries(10240, 0);

#[map(name = "whobyreq")]
static WHOBYREQ: HashMap<u64, who_t> = HashMap::with_max_entries(10240, 0);

#[map(name = "counts")]
static COUNTS: HashMap<info_t, val_t> = HashMap::with_max_entries(10240, 0);

#[inline(always)]
fn trace_start(req: u64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let tpid = target_pid.load();
    if tpid != 0 && tpid != pid {
        return 0;
    }

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let who = who_t { pid, name: comm };
    WHOBYREQ.insert(&req, &who, 0).ok();

    0
}

#[inline(always)]
fn trace_done(req: u64) -> i32 {
    match try_trace_done(req) {
        Ok(()) => {}
        Err(_) => {}
    }
    START.remove(&req).ok();
    WHOBYREQ.remove(&req).ok();
    0
}

#[inline(always)]
fn try_trace_done(req: u64) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let tpid = target_pid.load();
    if tpid != 0 && tpid != pid {
        return Ok(());
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let startp = match unsafe { START.get(&req) } {
        Some(s) => *s,
        None => return Ok(()),
    };

    // SAFETY: reading system time for delta calculation
    let now = unsafe { bpf_ktime_get_ns() };
    let delta_us = (now - startp.ts) / 1000;

    // SAFETY: reading cmd_flags at offset 24 from kernel request struct
    let cmd_flags: u32 = unsafe { bpf_probe_read_kernel((req + 24) as *const u32) }?;

    // SAFETY: reading rq_disk pointer at offset 8 from kernel request struct
    let disk: u64 = unsafe { bpf_probe_read_kernel((req + 8) as *const u64) }?;

    // SAFETY: reading major field from kernel gendisk struct
    let major: i32 = unsafe { bpf_probe_read_kernel(disk as *const i32) }?;

    // SAFETY: reading first_minor at offset 4 from kernel gendisk struct
    let minor: i32 = unsafe { bpf_probe_read_kernel((disk + 4) as *const i32) }?;

    let rwflag: i32 = if (cmd_flags & 0xFF) == 1 { 1 } else { 0 };

    let mut info = info_t {
        pid: 0,
        rwflag,
        major,
        minor,
        name: [0u8; TASK_COMM_LEN],
    };

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    if let Some(whop) = unsafe { WHOBYREQ.get(&req) } {
        info.pid = whop.pid;
        info.name = whop.name;
    }

    let zero = val_t { bytes: 0, us: 0, io: 0 };

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let valp = match unsafe { COUNTS.get(&info) } {
        Some(v) => Some(*v),
        None => {
            match COUNTS.insert(&info, &zero, 1) {
                Ok(()) => {}
                Err(-17) => {}
                Err(_) => return Ok(()),
            }
            // SAFETY: second lookup after insert attempt
            unsafe { COUNTS.get(&info) }.map(|v| *v)
        }
    };

    if let Some(mut val) = valp {
        val.us += delta_us;
        val.bytes += startp.data_len;
        val.io += 1;
        COUNTS.insert(&info, &val, 0).ok();
    }

    Ok(())
}

#[kprobe(function = "blk_mq_start_request")]
pub fn blk_mq_start_request(ctx: ProbeContext) -> u32 {
    match try_blk_mq_start_request(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_blk_mq_start_request(ctx: ProbeContext) -> Result<u32, i64> {
    let req: u64 = ctx.arg(0).ok_or(1i64)?;

    // SAFETY: reading system time for timestamp
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: reading __data_len at offset 44 from kernel request struct
    let data_len_u32: u32 = unsafe { bpf_probe_read_kernel((req + 44) as *const u32) }?;

    let start_req = start_req_t {
        ts,
        data_len: data_len_u32 as u64,
    };
    START.insert(&req, &start_req, 0).ok();

    Ok(0)
}

#[kprobe(function = "blk_account_io_start")]
pub fn blk_account_io_start(ctx: ProbeContext) -> u32 {
    let req: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_start(req) as u32
}

#[kprobe(function = "blk_account_io_done")]
pub fn blk_account_io_done(ctx: ProbeContext) -> u32 {
    let req: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_done(req) as u32
}

#[kprobe(function = "__blk_account_io_start")]
pub fn __blk_account_io_start(ctx: ProbeContext) -> u32 {
    let req: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_start(req) as u32
}

#[kprobe(function = "__blk_account_io_done")]
pub fn __blk_account_io_done(ctx: ProbeContext) -> u32 {
    let req: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_done(req) as u32
}

#[btf_tracepoint(function = "block_io_start")]
pub fn block_io_start(ctx: BtfTracePointContext) -> i32 {
    let req: u64 = ctx.arg(0);
    trace_start(req)
}

#[btf_tracepoint(function = "block_io_done")]
pub fn block_io_done(ctx: BtfTracePointContext) -> i32 {
    let req: u64 = ctx.arg(0);
    trace_done(req)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
