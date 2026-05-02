#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::Global;

#[repr(C)]
#[derive(Copy, Clone)]
struct DataT {
    cpu: u32,
    pid: u32,
    ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BpfUsdtArgSpec {
    val_off: u64,
    arg_type: u32,
    reg_off: i16,
    arg_signed: u8,
    arg_bitshift: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BpfUsdtSpec {
    args: [BpfUsdtArgSpec; 12],
    usdt_cookie: u64,
    arg_cnt: i16,
    _pad: [u8; 6],
}

#[map(name = "__bpf_usdt_specs")]
static USDT_SPECS: Array<BpfUsdtSpec> = Array::with_max_entries(256, 0);

#[map(name = "__bpf_usdt_ip_to_spec_id")]
static USDT_IP_TO_SPEC_ID: HashMap<i64, u32> = HashMap::with_max_entries(256, 0);

#[map(name = "data_map")]
static DATA_MAP: HashMap<u32, DataT> = HashMap::with_max_entries(100, 0);

#[map(name = "perf_map")]
static PERF_MAP: PerfEventArray<DataT> = PerfEventArray::new(0);

#[no_mangle]
#[link_section = ".data"]
static time: Global<u32> = Global::new(0);

#[inline(always)]
fn gc_start() -> i32 {
    // SAFETY: bpf_get_smp_processor_id is an unsafe BPF helper
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    let data = DataT { cpu, pid, ts };
    let _ = DATA_MAP.insert(&pid, &data, 0);
    0
}

#[inline(always)]
fn gc_end(ctx: &ProbeContext) -> i32 {
    // SAFETY: bpf_get_smp_processor_id is an unsafe BPF helper
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut data = DataT { cpu, pid, ts };

    // SAFETY: HashMap::get requires unsafe
    let p = match unsafe { DATA_MAP.get(&pid) } {
        Some(v) => v,
        None => return 0,
    };

    let val = data.ts.wrapping_sub(p.ts) as u32;
    if val > time.load() {
        data.ts = val as u64;
        PERF_MAP.output(ctx, &data, 0);
    }
    let _ = DATA_MAP.remove(&pid);
    0
}

#[uprobe]
pub fn handle_gc_start(_ctx: ProbeContext) -> i32 {
    gc_start()
}

#[uprobe]
pub fn handle_gc_end(ctx: ProbeContext) -> i32 {
    gc_end(&ctx)
}

#[uprobe]
pub fn handle_mem_pool_gc_start(_ctx: ProbeContext) -> i32 {
    gc_start()
}

#[uprobe]
pub fn handle_mem_pool_gc_end(ctx: ProbeContext) -> i32 {
    gc_end(&ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
