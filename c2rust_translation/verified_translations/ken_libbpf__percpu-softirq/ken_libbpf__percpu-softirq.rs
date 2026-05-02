#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;

#[map(name = "softirqs_total")]
static SOFTIRQS_TOTAL: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(10, 0);

#[btf_tracepoint(function = "softirq_entry")]
pub fn softirq_entry(ctx: BtfTracePointContext) -> i32 {
    let vec_nr: u32 = ctx.arg(0);
    increment_map(&vec_nr);
    0
}

fn increment_map(key: &u32) {
    let mut ptr = SOFTIRQS_TOTAL.get_ptr_mut(key);
    if ptr.is_none() {
        let _ = SOFTIRQS_TOTAL.insert(key, &0u64, 1);
        ptr = SOFTIRQS_TOTAL.get_ptr_mut(key);
        if ptr.is_none() {
            return;
        }
    }
    if let Some(p) = ptr {
        // SAFETY: creating atomic from valid map pointer returned by BPF lookup
        let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) };
        counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
