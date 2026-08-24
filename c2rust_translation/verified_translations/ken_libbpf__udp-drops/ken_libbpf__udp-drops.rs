#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;

const UPPER_PORT_BOUND: u16 = 32768;

#[map(name = "udp_fail_queue_rcv_skbs_total")]
static UDP_FAIL_QUEUE_RCV_SKBS_TOTAL: HashMap<u16, u64> = HashMap::with_max_entries(32768, 0);

#[inline(always)]
fn increment_map(key: &u16, increment: u64) {
    // SAFETY: looking up key in valid BPF hash map
    let lookup = unsafe { UDP_FAIL_QUEUE_RCV_SKBS_TOTAL.get(key) };
    match lookup {
        Some(count) => {
            let ptr = count as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map value pointer returned by map lookup
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = UDP_FAIL_QUEUE_RCV_SKBS_TOTAL.insert(key, &zero, 1); // BPF_NOEXIST
            // SAFETY: looking up key in valid BPF hash map after insert
            let lookup2 = unsafe { UDP_FAIL_QUEUE_RCV_SKBS_TOTAL.get(key) };
            if let Some(count) = lookup2 {
                let ptr = count as *const u64 as *mut u64;
                // SAFETY: creating atomic from valid map value pointer returned by map lookup
                let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
                atomic.fetch_add(increment, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[btf_tracepoint(function = "udp_fail_queue_rcv_skb")]
pub fn udp_fail_queue_rcv_skb(ctx: BtfTracePointContext) -> i32 {
    let sk: u64 = ctx.arg(1);
    // SAFETY: reading sk->__sk_common.skc_num (u16) at offset 14 from valid sock pointer
    let mut lport: u16 = unsafe { *((sk + 14) as *const u16) };

    if lport >= UPPER_PORT_BOUND {
        lport = 0;
    }

    increment_map(&lport, 1);

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
