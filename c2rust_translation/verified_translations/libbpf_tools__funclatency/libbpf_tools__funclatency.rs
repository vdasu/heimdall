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


const MAX_PIDS: u32 = 102400;
const MAX_SLOTS: u64 = 25;

#[allow(non_upper_case_globals)]
#[no_mangle]
static targ_tgid: aya_ebpf::Global<i32> = aya_ebpf::Global::new(0);

#[allow(non_upper_case_globals)]
#[no_mangle]
static units: aya_ebpf::Global<i32> = aya_ebpf::Global::new(0);

#[allow(non_upper_case_globals)]
#[no_mangle]
static filter_cg: aya_ebpf::Global<bool> = aya_ebpf::Global::new(false);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "starts")]
static STARTS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_PIDS, 0);

#[no_mangle]
#[link_section = ".bss"]
static mut hist: [u32; 25] = [0u32; 25];

#[inline(always)]
fn log2(v: u32) -> u64 {
    let mut v = v;
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
    let hi: u32 = (v >> 32) as u32;
    if hi != 0 {
        log2(hi) + 32
    } else {
        log2(v as u32)
    }
}

#[inline(always)]
fn do_entry() {
    let fcg = filter_cg.load();
    if fcg {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return,
        }
    }

    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let pid = id as u32;

    let target = targ_tgid.load();
    if target != 0 && target as u32 != tgid {
        return;
    }

    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    let nsec = unsafe { bpf_ktime_get_ns() };
    let _ = STARTS.insert(&pid, &nsec, 0);
}

#[inline(always)]
fn do_exit() {
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper binding
    let nsec = unsafe { bpf_ktime_get_ns() };
    let id = bpf_get_current_pid_tgid();
    let pid = id as u32;

    let fcg = filter_cg.load();
    if fcg {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return,
        }
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let start_val = match unsafe { STARTS.get(&pid) } {
        Some(v) => *v,
        None => return,
    };

    let mut delta = nsec - start_val;

    let u = units.load();
    match u {
        1 => delta /= 1000,
        2 => delta /= 1000000,
        _ => {}
    }

    let mut slot = log2l(delta);
    if slot >= MAX_SLOTS {
        slot = MAX_SLOTS - 1;
    }

    let idx = slot as usize;
    let base = core::ptr::addr_of_mut!(hist) as *mut u32;
    // SAFETY: pointer arithmetic within hist bounds (idx < MAX_SLOTS = 25)
    let elem_ptr = unsafe { base.add(idx) };
    // SAFETY: creating atomic from valid aligned BSS pointer
    let counter = unsafe { core::sync::atomic::AtomicU32::from_ptr(elem_ptr) };
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let _ = STARTS.remove(&pid);
}

#[fentry(function = "dummy_fentry")]
pub fn dummy_fentry(_ctx: FEntryContext) -> i32 {
    do_entry();
    0
}

#[fexit(function = "dummy_fexit")]
pub fn dummy_fexit(_ctx: FExitContext) -> i32 {
    do_exit();
    0
}

#[kprobe]
pub fn dummy_kprobe(_ctx: ProbeContext) -> u32 {
    do_entry();
    0
}

#[kretprobe]
pub fn dummy_kretprobe(_ctx: RetProbeContext) -> u32 {
    do_exit();
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
