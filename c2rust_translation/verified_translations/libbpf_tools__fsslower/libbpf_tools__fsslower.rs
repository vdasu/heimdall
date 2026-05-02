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

const MAX_ENTRIES: u32 = 8192;
const FILE_NAME_LEN: usize = 32;
const TASK_COMM_LEN: usize = 16;

const F_READ: u32 = 0;
const F_WRITE: u32 = 1;
const F_OPEN: u32 = 2;
const F_FSYNC: u32 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
struct Data {
    ts: u64,
    start: i64,
    end: i64,
    fp: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    delta_us: u64,
    end_ns: u64,
    offset: i64,
    size: i64,
    pid: i32,
    op: u32,
    file: [u8; FILE_NAME_LEN],
    task: [u8; TASK_COMM_LEN],
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

#[no_mangle]
static min_lat_ns: Global<u64> = Global::new(0);

#[map(name = "starts")]
static STARTS: HashMap<u32, Data> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn probe_entry(fp: u64, start: i64, end: i64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if fp == 0 {
        return 0;
    }

    let tpid = target_pid.load();
    if tpid != 0 && tpid != pid as i32 {
        return 0;
    }

    // SAFETY: calling bpf_ktime_get_ns
    let ts = unsafe { bpf_ktime_get_ns() };

    let data = Data { ts, start, end, fp };
    let _ = STARTS.insert(&tid, &data, 0);
    0
}

#[inline(always)]
fn probe_exit<C: EbpfContext>(ctx: &C, op: u32, size: i64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let tpid = target_pid.load();
    if tpid != 0 && tpid != pid as i32 {
        return 0;
    }

    // SAFETY: HashMap::get is unsafe in aya-ebpf
    let datap = match unsafe { STARTS.get(&tid) } {
        Some(d) => *d,
        None => return 0,
    };

    let _ = STARTS.remove(&tid);

    // SAFETY: calling bpf_ktime_get_ns
    let end_ns = unsafe { bpf_ktime_get_ns() };
    let delta_ns = end_ns - datap.ts;

    let mlns = min_lat_ns.load();
    if delta_ns <= mlns {
        return 0;
    }

    let ev_size = if op != F_FSYNC { size } else { datap.end - datap.start };

    let mut event = Event {
        delta_us: delta_ns / 1000,
        end_ns,
        offset: datap.start,
        size: ev_size,
        pid: pid as i32,
        op,
        file: [0u8; FILE_NAME_LEN],
        task: [0u8; TASK_COMM_LEN],
    };

    let fp = datap.fp;
    // BPF_CORE_READ(fp, f_path.dentry) - offset 160
    let dentry: u64 = match unsafe { bpf_probe_read_kernel((fp + 160) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // BPF_CORE_READ(dentry, d_name.name) - offset 40
    let file_name: u64 = match unsafe { bpf_probe_read_kernel((dentry + 40) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    match unsafe { bpf_probe_read_kernel_str_bytes(file_name as *const u8, &mut event.file) } {
        Ok(_) => {}
        Err(_) => return 0,
    };
    event.task = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    EVENTS.output(ctx, &event, 0);
    0
}

// ==================== kprobe entries ====================

#[kprobe(function = "dummy_file_read")]
pub fn file_read_entry(ctx: ProbeContext) -> u32 {
    match try_file_read_entry(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_file_read_entry(ctx: ProbeContext) -> Result<i32, i64> {
    let iocb: u64 = ctx.arg(0).ok_or(1i64)?;
    // SAFETY: BPF_CORE_READ(iocb, ki_filp) at offset 0
    let fp: u64 = unsafe { bpf_probe_read_kernel(iocb as *const u64) }?;
    // SAFETY: BPF_CORE_READ(iocb, ki_pos) at offset 8
    let start: i64 = unsafe { bpf_probe_read_kernel((iocb + 8) as *const i64) }?;
    Ok(probe_entry(fp, start, 0))
}

#[kretprobe(function = "dummy_file_read")]
pub fn file_read_exit(ctx: RetProbeContext) -> u32 {
    let ret = ctx.ret::<i64>();
    probe_exit(&ctx, F_READ, ret) as u32
}

#[kprobe(function = "dummy_file_write")]
pub fn file_write_entry(ctx: ProbeContext) -> u32 {
    match try_file_write_entry(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_file_write_entry(ctx: ProbeContext) -> Result<i32, i64> {
    let iocb: u64 = ctx.arg(0).ok_or(1i64)?;
    // SAFETY: BPF_CORE_READ(iocb, ki_filp) at offset 0
    let fp: u64 = unsafe { bpf_probe_read_kernel(iocb as *const u64) }?;
    // SAFETY: BPF_CORE_READ(iocb, ki_pos) at offset 8
    let start: i64 = unsafe { bpf_probe_read_kernel((iocb + 8) as *const i64) }?;
    Ok(probe_entry(fp, start, 0))
}

#[kretprobe(function = "dummy_file_write")]
pub fn file_write_exit(ctx: RetProbeContext) -> u32 {
    let ret = ctx.ret::<i64>();
    probe_exit(&ctx, F_WRITE, ret) as u32
}

#[kprobe(function = "dummy_file_open")]
pub fn file_open_entry(ctx: ProbeContext) -> u32 {
    let file: u64 = ctx.arg::<u64>(1).unwrap_or(0);
    probe_entry(file, 0, 0) as u32
}

#[kretprobe(function = "dummy_file_open")]
pub fn file_open_exit(ctx: RetProbeContext) -> u32 {
    probe_exit(&ctx, F_OPEN, 0) as u32
}

#[kprobe(function = "dummy_file_sync")]
pub fn file_sync_entry(ctx: ProbeContext) -> u32 {
    let file: u64 = ctx.arg::<u64>(0).unwrap_or(0);
    let start: i64 = ctx.arg::<i64>(1).unwrap_or(0);
    let end: i64 = ctx.arg::<i64>(2).unwrap_or(0);
    probe_entry(file, start, end) as u32
}

#[kretprobe(function = "dummy_file_sync")]
pub fn file_sync_exit(ctx: RetProbeContext) -> u32 {
    probe_exit(&ctx, F_FSYNC, 0) as u32
}

// ==================== fentry entries ====================

#[fentry(function = "dummy_file_read")]
pub fn file_read_fentry(ctx: FEntryContext) -> i32 {
    let iocb: u64 = ctx.arg(0);
    // SAFETY: direct kernel pointer read for iocb->ki_filp (offset 0)
    let fp: u64 = unsafe { core::ptr::read_volatile(iocb as *const u64) };
    // SAFETY: direct kernel pointer read for iocb->ki_pos (offset 8)
    let start: i64 = unsafe { core::ptr::read_volatile((iocb + 8) as *const i64) };
    probe_entry(fp, start, 0)
}

#[fexit(function = "dummy_file_read")]
pub fn file_read_fexit(ctx: FExitContext) -> i32 {
    let ret: i64 = ctx.arg(2);
    probe_exit(&ctx, F_READ, ret)
}

#[fentry(function = "dummy_file_write")]
pub fn file_write_fentry(ctx: FEntryContext) -> i32 {
    let iocb: u64 = ctx.arg(0);
    // SAFETY: direct kernel pointer read for iocb->ki_filp (offset 0)
    let fp: u64 = unsafe { core::ptr::read_volatile(iocb as *const u64) };
    // SAFETY: direct kernel pointer read for iocb->ki_pos (offset 8)
    let start: i64 = unsafe { core::ptr::read_volatile((iocb + 8) as *const i64) };
    probe_entry(fp, start, 0)
}

#[fexit(function = "dummy_file_write")]
pub fn file_write_fexit(ctx: FExitContext) -> i32 {
    let ret: i64 = ctx.arg(2);
    probe_exit(&ctx, F_WRITE, ret)
}

#[fentry(function = "dummy_file_open")]
pub fn file_open_fentry(ctx: FEntryContext) -> i32 {
    let file: u64 = ctx.arg(1);
    probe_entry(file, 0, 0)
}

#[fexit(function = "dummy_file_open")]
pub fn file_open_fexit(ctx: FExitContext) -> i32 {
    probe_exit(&ctx, F_OPEN, 0)
}

#[fentry(function = "dummy_file_sync")]
pub fn file_sync_fentry(ctx: FEntryContext) -> i32 {
    let file: u64 = ctx.arg(0);
    let start: i64 = ctx.arg(1);
    let end: i64 = ctx.arg(2);
    probe_entry(file, start, end)
}

#[fexit(function = "dummy_file_sync")]
pub fn file_sync_fexit(ctx: FExitContext) -> i32 {
    probe_exit(&ctx, F_FSYNC, 0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
