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

const MAX_ENTRIES: u32 = 256;
const MAX_SLOTS: usize = 20;

#[repr(C)]
#[derive(Copy, Clone)]
struct IrqKey {
    name: [u8; 32],
    cpu: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Info {
    count: u64,
    total_time: u64,
    max_time: u64,
    slots: [u32; MAX_SLOTS],
}

#[allow(non_upper_case_globals)]
#[no_mangle]
static filter_cg: aya_ebpf::Global<bool> = aya_ebpf::Global::new(false);

#[allow(non_upper_case_globals)]
#[no_mangle]
static targ_dist: aya_ebpf::Global<bool> = aya_ebpf::Global::new(false);

#[allow(non_upper_case_globals)]
#[no_mangle]
static targ_ns: aya_ebpf::Global<bool> = aya_ebpf::Global::new(false);

#[allow(non_upper_case_globals)]
#[no_mangle]
static cpu: aya_ebpf::Global<bool> = aya_ebpf::Global::new(false);

#[allow(non_upper_case_globals)]
#[no_mangle]
static targ_cpu: aya_ebpf::Global<i32> = aya_ebpf::Global::new(-1);

#[no_mangle]
#[link_section = ".bss"]
static zero: Info = Info {
    count: 0,
    total_time: 0,
    max_time: 0,
    slots: [0; MAX_SLOTS],
};

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "start")]
static START: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "infos")]
static INFOS: HashMap<IrqKey, Info> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn is_target_cpu() -> bool {
    let tc = targ_cpu.load();
    if tc < 0 {
        return true;
    }
    // SAFETY: bpf_get_smp_processor_id is an unsafe BPF helper binding
    tc == unsafe { bpf_get_smp_processor_id() } as i32
}

#[inline(always)]
fn log2_u32(mut v: u32) -> u64 {
    let mut r: u32 = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let mut shift: u32 = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    r |= shift;
    shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;
    shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r |= shift;
    r |= v >> 1;
    r as u64
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi) + 32
    } else {
        log2_u32(v as u32)
    }
}

#[inline(always)]
fn try_handle_entry() -> Result<i32, i32> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }
    if !is_target_cpu() {
        return Ok(0);
    }

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    let ts = unsafe { bpf_ktime_get_ns() };
    let key: u32 = 0;

    if let Some(ptr) = START.get_ptr_mut(key) {
        // SAFETY: writing timestamp to percpu array entry
        unsafe { *ptr = ts };
    }

    Ok(0)
}

#[inline(always)]
fn try_handle_exit(action: u64) -> Result<i32, i32> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }
    if !is_target_cpu() {
        return Ok(0);
    }

    let key: u32 = 0;
    let tsp = match START.get_ptr(key) {
        Some(ptr) => {
            // SAFETY: reading timestamp from percpu array entry
            unsafe { *ptr }
        }
        None => return Ok(0),
    };

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut delta = ts - tsp;
    if !targ_ns.load() {
        delta /= 1000u64;
    }

    let mut ikey = IrqKey { name: [0u8; 32], cpu: 0 };

    // SAFETY: reading name pointer from kernel irqaction struct at offset 80
    let name_ptr = match unsafe { bpf_probe_read_kernel::<u64>((action as *const u8).wrapping_add(80) as *const u64) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    // SAFETY: reading kernel string into ikey.name buffer
    match unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, &mut ikey.name) } {
        Ok(_) => {}
        Err(_) => return Ok(0),
    }

    if cpu.load() {
        // SAFETY: bpf_get_smp_processor_id is an unsafe BPF helper binding
        ikey.cpu = unsafe { bpf_get_smp_processor_id() };
    }

    // bpf_map_lookup_or_try_init pattern (stack-copy)
    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let info_ref = match unsafe { INFOS.get(&ikey) } {
        Some(r) => r,
        None => {
            match INFOS.insert(&ikey, &zero, 1) {
                Ok(()) => {}
                Err(e) => {
                    if e != -17 {
                        return Ok(0);
                    }
                }
            }
            // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
            match unsafe { INFOS.get(&ikey) } {
                Some(r) => r,
                None => return Ok(0),
            }
        }
    };

    let mut info = *info_ref;
    info.count += 1;

    if !targ_dist.load() {
        info.total_time += delta;
        if delta > info.max_time {
            info.max_time = delta;
        }
    } else {
        let mut slot = log2l(delta);
        if slot >= MAX_SLOTS as u64 {
            slot = (MAX_SLOTS - 1) as u64;
        }
        info.slots[slot as usize] += 1;
    }

    let _ = INFOS.insert(&ikey, &info, 0);

    Ok(0)
}

#[raw_tracepoint(tracepoint = "irq_handler_entry")]
pub fn irq_handler_entry(_ctx: RawTracePointContext) -> i32 {
    match try_handle_entry() {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "irq_handler_entry")]
pub fn irq_handler_entry_btf(_ctx: BtfTracePointContext) -> i32 {
    match try_handle_entry() {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[raw_tracepoint(tracepoint = "irq_handler_exit")]
pub fn irq_handler_exit(ctx: RawTracePointContext) -> i32 {
    // SAFETY: reading args[1] (action pointer) from raw tracepoint context
    let action = unsafe { *((ctx.as_ptr() as *const u64).add(1)) };
    match try_handle_exit(action) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "irq_handler_exit")]
pub fn irq_handler_exit_btf(ctx: BtfTracePointContext) -> i32 {
    // SAFETY: reading args[1] (action pointer) from btf tracepoint context
    let action = unsafe { *((ctx.as_ptr() as *const u64).add(1)) };
    match try_handle_exit(action) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
