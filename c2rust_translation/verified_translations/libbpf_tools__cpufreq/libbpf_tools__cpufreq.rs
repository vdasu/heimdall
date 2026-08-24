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

const MAX_ENTRIES: u32 = 1024;
const MAX_CPU_NR: u32 = 128;
const MAX_SLOTS: usize = 26;
const TASK_COMM_LEN: usize = 16;
const HIST_STEP_SIZE: u32 = 200;

#[repr(C)]
#[derive(Copy, Clone)]
struct Hkey {
    comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
}

#[no_mangle]
#[link_section = ".bss"]
static mut freqs_mhz: [u32; MAX_CPU_NR as usize] = [0u32; MAX_CPU_NR as usize];

#[no_mangle]
#[link_section = ".bss"]
static mut syswide: Hist = Hist { slots: [0u32; MAX_SLOTS] };

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".bss"]
static zero: Hist = Hist { slots: [0u32; MAX_SLOTS] };

#[allow(non_upper_case_globals)]
#[no_mangle]
#[link_section = ".bss"]
static filter_cg: Global<u8> = Global::new(0);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "hists")]
static HISTS: HashMap<Hkey, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[btf_tracepoint(function = "cpu_frequency")]
pub fn cpu_frequency(ctx: BtfTracePointContext) -> i32 {
    match try_cpu_frequency(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_cpu_frequency(ctx: BtfTracePointContext) -> Result<i32, i64> {
    if filter_cg.load() != 0 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let state: u32 = ctx.arg(0);
    let cpu_id: u32 = ctx.arg(1);

    if cpu_id >= MAX_CPU_NR {
        return Ok(0);
    }

    let cpu_id = cpu_id & (MAX_CPU_NR - 1);

    let ptr = core::ptr::addr_of_mut!(freqs_mhz) as *mut u32;
    // SAFETY: cpu_id < MAX_CPU_NR, pointer within freqs_mhz bounds
    let slot_ptr = unsafe { ptr.add(cpu_id as usize) };
    // SAFETY: writing frequency to BSS global
    unsafe { core::ptr::write_volatile(slot_ptr, state / 1000) };

    Ok(0)
}

#[perf_event]
pub fn do_sample(ctx: PerfEventContext) -> u32 {
    match try_do_sample(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_do_sample(_ctx: PerfEventContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: calling BPF helper to get CPU ID
    let cpu: u64 = unsafe { bpf_get_smp_processor_id() } as u64;

    if filter_cg.load() != 0 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    if cpu >= MAX_CPU_NR as u64 {
        return Ok(0);
    }
    let cpu = cpu & (MAX_CPU_NR as u64 - 1);

    let ptr = core::ptr::addr_of!(freqs_mhz) as *const u32;
    // SAFETY: cpu < MAX_CPU_NR, pointer within freqs_mhz bounds
    let slot_ptr = unsafe { ptr.add(cpu as usize) };
    // SAFETY: reading frequency from BSS global
    let freq_mhz = unsafe { core::ptr::read_volatile(slot_ptr) };
    if freq_mhz == 0 {
        return Ok(0);
    }

    let mut slot = (freq_mhz / HIST_STEP_SIZE) as u64;
    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    let syswide_base = core::ptr::addr_of_mut!(syswide) as *mut u32;
    // SAFETY: slot < MAX_SLOTS, within syswide.slots bounds
    let syswide_slot_ptr = unsafe { syswide_base.add(slot as usize) };
    // SAFETY: creating atomic from valid BSS global pointer
    let syswide_atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(syswide_slot_ptr) };
    syswide_atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    if pid == 0 {
        return Ok(0);
    }

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    let hkey = Hkey { comm };

    let hist_ptr = match HISTS.get_ptr_mut(&hkey) {
        Some(p) => p,
        None => {
            let _ = HISTS.insert(&hkey, &zero, 1u64);
            match HISTS.get_ptr_mut(&hkey) {
                Some(p) => p,
                None => return Ok(0),
            }
        }
    };

    let hist_base = hist_ptr as *mut u32;
    // SAFETY: slot < MAX_SLOTS, within hist.slots bounds
    let hist_slot_ptr = unsafe { hist_base.add(slot as usize) };
    // SAFETY: creating atomic from valid map pointer
    let hist_atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(hist_slot_ptr) };
    hist_atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
