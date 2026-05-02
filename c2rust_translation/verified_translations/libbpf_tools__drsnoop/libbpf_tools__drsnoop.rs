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
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    task: [u8; TASK_COMM_LEN],
    delta_ns: u64,
    nr_reclaimed: u64,
    nr_free_pages: u64,
    pid: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Piddata {
    ts: u64,
    nr_free_pages: u64,
}

#[no_mangle]
static targ_pid: Global<i32> = Global::new(0);

#[no_mangle]
static targ_tgid: Global<i32> = Global::new(0);

#[no_mangle]
static vm_zone_stat_kaddr: Global<u64> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u32, Piddata> = HashMap::with_max_entries(8192, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn handle_direct_reclaim_begin() -> i32 {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    let target_tgid = targ_tgid.load() as u32;
    if target_tgid != 0 && target_tgid != tgid {
        return 0;
    }
    let target_pid = targ_pid.load() as u32;
    if target_pid != 0 && target_pid != pid {
        return 0;
    }

    let mut piddata = Piddata { ts: 0, nr_free_pages: 0 };
    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    piddata.ts = unsafe { bpf_ktime_get_ns() };

    let kaddr = vm_zone_stat_kaddr.load();
    if kaddr != 0 {
        // SAFETY: reading kernel memory at loader-provided address
        piddata.nr_free_pages = unsafe {
            bpf_probe_read_kernel(kaddr as *const u64)
        }
        .unwrap_or(0);
    }

    let _ = START.insert(&pid, &piddata, 0);
    0
}

#[inline(always)]
fn handle_direct_reclaim_end<C: EbpfContext>(ctx: &C, nr_reclaimed: u64) -> i32 {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    let target_tgid = targ_tgid.load() as u32;
    if target_tgid != 0 && target_tgid != tgid {
        return 0;
    }
    let target_pid = targ_pid.load() as u32;
    if target_pid != 0 && target_pid != pid {
        return 0;
    }

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let piddatap = match unsafe { START.get(&pid) } {
        Some(p) => p,
        None => return 0,
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    let now = unsafe { bpf_ktime_get_ns() };
    let delta_ns = now as i64 - piddatap.ts as i64;
    let nr_free_pages = piddatap.nr_free_pages;

    if delta_ns >= 0 {
        let event = Event {
            task: bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]),
            delta_ns: delta_ns as u64,
            nr_reclaimed,
            nr_free_pages,
            pid: pid as i32,
        };
        EVENTS.output(ctx, &event, 0);
    }

    let _ = START.remove(&pid);
    0
}

#[btf_tracepoint(function = "mm_vmscan_direct_reclaim_begin")]
pub fn direct_reclaim_begin_btf(_ctx: BtfTracePointContext) -> i32 {
    handle_direct_reclaim_begin()
}

#[btf_tracepoint(function = "mm_vmscan_direct_reclaim_end")]
pub fn direct_reclaim_end_btf(ctx: BtfTracePointContext) -> i32 {
    let nr_reclaimed: u64 = ctx.arg(0);
    handle_direct_reclaim_end(&ctx, nr_reclaimed)
}

#[raw_tracepoint(tracepoint = "mm_vmscan_direct_reclaim_begin")]
pub fn direct_reclaim_begin(_ctx: RawTracePointContext) -> i32 {
    handle_direct_reclaim_begin()
}

#[raw_tracepoint(tracepoint = "mm_vmscan_direct_reclaim_end")]
pub fn direct_reclaim_end(ctx: RawTracePointContext) -> i32 {
    let nr_reclaimed: u64 = ctx.arg(0);
    handle_direct_reclaim_end(&ctx, nr_reclaimed)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
