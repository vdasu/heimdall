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
const MINORBITS: u32 = 20;
const KERNEL_VERSION_5_10_137: u32 = 330377;

#[no_mangle]
static filter_cg: Global<u8> = Global::new(0);
#[no_mangle]
static targ_queued: Global<u8> = Global::new(0);
#[no_mangle]
static filter_dev: Global<u8> = Global::new(0);
#[no_mangle]
static targ_dev: Global<u32> = Global::new(0);
#[no_mangle]
static min_ns: Global<u64> = Global::new(0);

#[no_mangle]
#[link_section = ".kconfig"]
static LINUX_KERNEL_VERSION: Global<u32> = Global::new(0);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "infobyreq")]
static INFOBYREQ: HashMap<u64, Piddata> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "start")]
static START: HashMap<u64, Stage> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[repr(C)]
#[derive(Copy, Clone)]
struct Piddata {
    comm: [u8; 16],
    pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Stage {
    insert: u64,
    issue: u64,
    dev: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    comm: [u8; 16],
    delta: u64,
    qdelta: u64,
    ts: u64,
    sector: u64,
    len: u32,
    pid: u32,
    cmd_flags: u32,
    dev: u32,
}

#[inline(always)]
fn check_cgroup_filter() -> bool {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => true,
            _ => false,
        }
    } else {
        true
    }
}

#[inline(always)]
fn trace_pid(rq: u64) -> i32 {
    let id = bpf_get_current_pid_tgid();
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let piddata = Piddata {
        comm,
        pid: (id >> 32) as u32,
    };
    INFOBYREQ.insert(&rq, &piddata, 0).ok();
    0
}

#[inline(always)]
fn trace_rq_start(rq: u64, insert: bool) -> i32 {
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let existing = unsafe { START.get(&rq) };

    if let Some(stage_ref) = existing {
        let mut stage = *stage_ref;
        if insert {
            stage.insert = ts;
        } else {
            stage.issue = ts;
        }
        START.insert(&rq, &stage, 0).ok();
    } else {
        // SAFETY: reading rq->rq_disk at offset 8
        let disk_ptr: u64 = unsafe {
            bpf_probe_read_kernel((rq as *const u8).add(8) as *const u64)
        }
        .unwrap_or(0);

        let dev = if disk_ptr != 0 {
            // SAFETY: reading disk->major at offset 0
            let major: u32 = unsafe {
                bpf_probe_read_kernel(disk_ptr as *const u32)
            }
            .unwrap_or(0);
            // SAFETY: reading disk->first_minor at offset 4
            let first_minor: u32 = unsafe {
                bpf_probe_read_kernel((disk_ptr as *const u8).add(4) as *const u32)
            }
            .unwrap_or(0);
            (major << MINORBITS) | first_minor
        } else {
            0u32
        };

        if filter_dev.load() == 1 && targ_dev.load() != dev {
            return 0;
        }

        let mut stage = Stage {
            insert: 0,
            issue: 0,
            dev,
            _pad: 0,
        };
        if insert {
            stage.insert = ts;
        } else {
            stage.issue = ts;
        }
        START.insert(&rq, &stage, 0).ok();
    }
    0
}

// --- Entry points ---

#[fentry(function = "blk_account_io_start")]
pub fn blk_account_io_start(ctx: FEntryContext) -> i32 {
    if !check_cgroup_filter() {
        return 0;
    }
    let rq: u64 = ctx.arg(0);
    trace_pid(rq)
}

#[btf_tracepoint(function = "block_io_start")]
pub fn block_io_start(ctx: BtfTracePointContext) -> i32 {
    if !check_cgroup_filter() {
        return 0;
    }
    let rq: u64 = ctx.arg(0);
    trace_pid(rq)
}

#[kprobe(function = "blk_account_io_merge_bio")]
pub fn blk_account_io_merge_bio(ctx: ProbeContext) -> u32 {
    if !check_cgroup_filter() {
        return 0;
    }
    let rq: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    trace_pid(rq) as u32
}

#[btf_tracepoint(function = "block_rq_insert")]
pub fn block_rq_insert(ctx: BtfTracePointContext) -> i32 {
    if !check_cgroup_filter() {
        return 0;
    }
    let kver = LINUX_KERNEL_VERSION.load();
    let rq: u64 = if kver >= KERNEL_VERSION_5_10_137 {
        ctx.arg(0)
    } else {
        ctx.arg(1)
    };
    trace_rq_start(rq, true)
}

#[btf_tracepoint(function = "block_rq_issue")]
pub fn block_rq_issue(ctx: BtfTracePointContext) -> i32 {
    if !check_cgroup_filter() {
        return 0;
    }
    let kver = LINUX_KERNEL_VERSION.load();
    let rq: u64 = if kver >= KERNEL_VERSION_5_10_137 {
        ctx.arg(0)
    } else {
        ctx.arg(1)
    };
    trace_rq_start(rq, false)
}

#[btf_tracepoint(function = "block_rq_complete")]
pub fn block_rq_complete(ctx: BtfTracePointContext) -> i32 {
    try_block_rq_complete(&ctx)
}

fn try_block_rq_complete(ctx: &BtfTracePointContext) -> i32 {
    if !check_cgroup_filter() {
        return 0;
    }

    let rq: u64 = ctx.arg(0);
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let stage_ref = match unsafe { START.get(&rq) } {
        Some(s) => s,
        None => return 0,
    };
    let stage = *stage_ref;

    let delta = ts.wrapping_sub(stage.issue);
    if (delta as i64) < 0 || delta < min_ns.load() {
        START.remove(&rq).ok();
        INFOBYREQ.remove(&rq).ok();
        return 0;
    }

    let mut event = Event {
        comm: [0u8; 16],
        delta: 0,
        qdelta: 0,
        ts: 0,
        sector: 0,
        len: 0,
        pid: 0,
        cmd_flags: 0,
        dev: 0,
    };

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    match unsafe { INFOBYREQ.get(&rq) } {
        Some(piddata_ref) => {
            event.comm = piddata_ref.comm;
            event.pid = piddata_ref.pid;
        }
        None => {
            event.comm[0] = b'?';
        }
    }

    event.delta = delta;

    if targ_queued.load() == 1 {
        // SAFETY: reading rq->q at offset 0
        let q: u64 = unsafe {
            bpf_probe_read_kernel(rq as *const u64)
        }
        .unwrap_or(0);
        // SAFETY: reading q->elevator at offset 8
        let elevator: u64 = unsafe {
            bpf_probe_read_kernel((q as *const u8).add(8) as *const u64)
        }
        .unwrap_or(0);
        if elevator != 0 {
            if stage.insert == 0 {
                event.qdelta = !0u64;
            } else {
                event.qdelta = stage.issue.wrapping_sub(stage.insert);
            }
        }
    }

    event.ts = ts;

    // SAFETY: reading rq->__sector at offset 48
    event.sector = unsafe {
        bpf_probe_read_kernel((rq as *const u8).add(48) as *const u64)
    }
    .unwrap_or(0);

    // SAFETY: reading rq->__data_len at offset 44
    event.len = unsafe {
        bpf_probe_read_kernel((rq as *const u8).add(44) as *const u32)
    }
    .unwrap_or(0);

    // SAFETY: reading rq->cmd_flags at offset 24
    event.cmd_flags = unsafe {
        bpf_probe_read_kernel((rq as *const u8).add(24) as *const u32)
    }
    .unwrap_or(0);

    event.dev = stage.dev;

    EVENTS.output(ctx, &event, 0);

    START.remove(&rq).ok();
    INFOBYREQ.remove(&rq).ok();
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
