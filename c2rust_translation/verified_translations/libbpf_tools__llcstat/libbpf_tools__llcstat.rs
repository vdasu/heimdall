#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::PerfEventContext;
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct LlcstatValueInfo {
    ref_count: u64,
    miss: u64,
    comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LlcstatKeyInfo {
    cpu: u32,
    pid: u32,
    tid: u32,
}

#[no_mangle]
static targ_per_thread: Global<bool> = Global::new(false);

#[map(name = "infos")]
static INFOS: HashMap<LlcstatKeyInfo, LlcstatValueInfo> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn trace_event(sample_period: u64, miss: bool) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: bpf_get_smp_processor_id is an unsafe binding
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let pid = (pid_tgid >> 32) as u32;
    let per_thread = targ_per_thread.load();
    let tid = if per_thread {
        pid_tgid as u32
    } else {
        pid
    };

    let key = LlcstatKeyInfo { cpu, pid, tid };

    // SAFETY: HashMap::get is declared unsafe in aya-ebpf
    let mut val = match unsafe { INFOS.get(&key) } {
        Some(v) => *v,
        None => LlcstatValueInfo {
            ref_count: 0,
            miss: 0,
            comm: [0u8; TASK_COMM_LEN],
        },
    };

    if miss {
        val.miss += sample_period;
    } else {
        val.ref_count += sample_period;
    }

    val.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
    let _ = INFOS.insert(&key, &val, 0);

    0
}

#[perf_event]
pub fn on_cache_miss(ctx: PerfEventContext) -> u32 {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    let sp_ptr = ctx_ptr.wrapping_add(168) as *const u64;
    // SAFETY: reading sample_period from bpf_perf_event_data at offset 168
    let sample_period = unsafe { *sp_ptr };
    trace_event(sample_period, true) as u32
}

#[perf_event]
pub fn on_cache_ref(ctx: PerfEventContext) -> u32 {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    let sp_ptr = ctx_ptr.wrapping_add(168) as *const u64;
    // SAFETY: reading sample_period from bpf_perf_event_data at offset 168
    let sample_period = unsafe { *sp_ptr };
    trace_event(sample_period, false) as u32
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
