#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::perf_event;
use aya_ebpf::helpers::{bpf_get_current_task, bpf_get_smp_processor_id, bpf_probe_read_kernel};
use aya_ebpf::programs::PerfEventContext;
use aya_ebpf::Global;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

const MAX_CPU_NR: usize = 128;
const MAX_SLOTS: usize = 32;

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    slots: [u32; MAX_SLOTS],
}

#[repr(transparent)]
struct BssGlobal<T>(UnsafeCell<T>);

// SAFETY: eBPF programs have single-threaded per-CPU execution
unsafe impl<T> Sync for BssGlobal<T> {}

impl<T> BssGlobal<T> {
    const fn new(val: T) -> Self {
        BssGlobal(UnsafeCell::new(val))
    }

    fn as_mut_ptr(&self) -> *mut T {
        self.0.get()
    }
}

#[no_mangle]
static targ_per_cpu: Global<u8> = Global::new(0);

#[no_mangle]
static targ_host: Global<u8> = Global::new(0);

#[no_mangle]
static hists: BssGlobal<[Hist; MAX_CPU_NR]> = BssGlobal::new([Hist { slots: [0u32; MAX_SLOTS] }; MAX_CPU_NR]);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[perf_event]
pub fn do_sample(_ctx: PerfEventContext) -> u32 {
    match try_do_sample() {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_do_sample() -> Result<u32, i64> {
    // SAFETY: calling BPF helper to get current task pointer
    let task = unsafe { bpf_get_current_task() } as usize;

    let slot: u64;

    if targ_host.load() != 0 {
        let cfs_rq_ptr = (task + 280) as *const u64;
        // SAFETY: reading task->se.cfs_rq from kernel task struct
        let cfs_rq = unsafe { bpf_probe_read_kernel(cfs_rq_ptr) }?;

        let rq_ptr = (cfs_rq as usize + 312) as *const u64;
        // SAFETY: reading cfs_rq->rq from kernel struct
        let rq = unsafe { bpf_probe_read_kernel(rq_ptr) }?;

        let nr_running_ptr = (rq as usize + 4) as *const u32;
        // SAFETY: reading rq->nr_running from kernel struct
        let nr_running: u32 = unsafe { bpf_probe_read_kernel(nr_running_ptr) }?;
        slot = nr_running as u64;
    } else {
        let cfs_rq_ptr = (task + 280) as *const u64;
        // SAFETY: reading task->se.cfs_rq from kernel task struct
        let cfs_rq = unsafe { bpf_probe_read_kernel(cfs_rq_ptr) }?;

        let nr_ptr = cfs_rq as *const u32;
        // SAFETY: reading nr_running from cfs_rq struct
        let nr: u32 = unsafe { bpf_probe_read_kernel(nr_ptr) }?;
        slot = (nr & 0xff) as u64;
    }

    let mut slot = slot;
    if slot > 0 {
        slot -= 1;
    }

    let mut cpu: u32 = 0;
    let per_cpu = targ_per_cpu.load();

    if per_cpu != 0 {
        // SAFETY: calling BPF helper to get current CPU id
        cpu = unsafe { bpf_get_smp_processor_id() };
        if cpu >= MAX_CPU_NR as u32 {
            return Ok(0);
        }
    }

    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    let base = hists.as_mut_ptr() as *mut u32;
    let idx = cpu as usize * MAX_SLOTS + slot as usize;
    let slot_ptr = base.wrapping_add(idx);

    if per_cpu != 0 {
        // SAFETY: reading current value from BSS global slot
        let val = unsafe { core::ptr::read(slot_ptr) };
        // SAFETY: writing incremented value to BSS global slot
        unsafe { core::ptr::write(slot_ptr, val + 1) };
    } else {
        // SAFETY: creating atomic from aligned BSS global pointer
        let atomic = unsafe { AtomicU32::from_ptr(slot_ptr) };
        atomic.fetch_add(1, Ordering::Relaxed);
    }

    Ok(0)
}
