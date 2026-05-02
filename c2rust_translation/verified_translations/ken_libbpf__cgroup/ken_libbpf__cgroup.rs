#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;

#[map(name = "cgroup_sched_migrations_total")]
static CGROUP_SCHED_MIGRATIONS_TOTAL: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);

#[inline(always)]
fn increment_map(key: &u64, increment: u64) -> u64 {
    // SAFETY: looking up key in BPF LRU hash map
    let count = unsafe { CGROUP_SCHED_MIGRATIONS_TOTAL.get(key) };
    if count.is_none() {
        let zero: u64 = 0;
        let _ = CGROUP_SCHED_MIGRATIONS_TOTAL.insert(key, &zero, 1); // BPF_NOEXIST
        // SAFETY: looking up key in BPF LRU hash map after insert
        let count2 = unsafe { CGROUP_SCHED_MIGRATIONS_TOTAL.get(key) };
        if let Some(v) = count2 {
            let ptr = v as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map pointer for atomic increment
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            // SAFETY: reading final value from valid map pointer
            return unsafe { *ptr };
        }
        return 0;
    }
    if let Some(v) = count {
        let ptr = v as *const u64 as *mut u64;
        // SAFETY: creating atomic from valid map pointer for atomic increment
        let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
        atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
        // SAFETY: reading final value from valid map pointer
        return unsafe { *ptr };
    }
    0
}

#[btf_tracepoint(function = "sched_migrate_task")]
pub fn sched_migrate_task(ctx: BtfTracePointContext) -> i32 {
    match try_sched_migrate_task(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_migrate_task(_ctx: BtfTracePointContext) -> Result<i32, i32> {
    // SAFETY: calling BPF helper to get current cgroup id
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    increment_map(&cgroup_id, 1);
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
