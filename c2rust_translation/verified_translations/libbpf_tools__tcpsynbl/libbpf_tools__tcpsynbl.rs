#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;

const MAX_SLOTS: usize = 32;
const MAX_ENTRIES: u32 = 65536;

#[repr(C)]
struct Hist {
    slots: [u32; MAX_SLOTS],
}

#[no_mangle]
#[link_section = ".bss"]
static zero: Hist = Hist {
    slots: [0u32; MAX_SLOTS],
};

#[map(name = "hists")]
static HISTS: HashMap<u64, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn log2(v: u32) -> u64 {
    let mut v = v;
    let mut r: u32 = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let shift: u32 = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    r |= shift;
    let shift: u32 = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;
    let shift: u32 = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r |= shift;
    r |= v >> 1;
    r as u64
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2(hi) + 32
    } else {
        log2(v as u32)
    }
}

#[inline(always)]
fn do_entry(sk: *const u8) -> i32 {
    // BPF_CORE_READ(sk, sk_max_ack_backlog)
    // SAFETY: reading kernel struct field via probe_read
    let max_backlog: u32 = match unsafe { bpf_probe_read_kernel(sk as *const u32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let max_backlog = max_backlog as u64;

    // BPF_CORE_READ(sk, sk_ack_backlog)
    // SAFETY: reading kernel struct field via probe_read
    let backlog: u32 = match unsafe { bpf_probe_read_kernel(sk as *const u32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let backlog = backlog as u64;

    // bpf_map_lookup_or_try_init(&hists, &max_backlog, &zero)
    let histp: *mut Hist = match HISTS.get_ptr_mut(&max_backlog) {
        Some(p) => p,
        None => {
            match HISTS.insert(&max_backlog, &zero, 1) {
                Ok(()) => {}
                Err(e) => {
                    if e != -17 {
                        return 0;
                    }
                }
            }
            match HISTS.get_ptr_mut(&max_backlog) {
                Some(p) => p,
                None => return 0,
            }
        }
    };

    let mut slot = log2l(backlog);
    if slot >= MAX_SLOTS as u64 {
        slot = MAX_SLOTS as u64 - 1;
    }

    // __sync_fetch_and_add(&histp->slots[slot], 1)
    // SAFETY: computing pointer to slots[slot] within valid map value
    let slot_ptr = unsafe { (histp as *mut u8).add(slot as usize * 4) } as *mut u32;
    // SAFETY: creating atomic from valid map pointer
    let atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(slot_ptr) };
    atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    0
}

#[kprobe(function = "tcp_v4_syn_recv_sock")]
pub fn tcp_v4_syn_recv_kprobe(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    do_entry(sk as *const u8) as u32
}

#[kprobe(function = "tcp_v6_syn_recv_sock")]
pub fn tcp_v6_syn_recv_kprobe(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    do_entry(sk as *const u8) as u32
}

#[fentry(function = "tcp_v4_syn_recv_sock")]
pub fn tcp_v4_syn_recv(ctx: FEntryContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    do_entry(sk as *const u8)
}

#[fentry(function = "tcp_v6_syn_recv_sock")]
pub fn tcp_v6_syn_recv(ctx: FEntryContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    do_entry(sk as *const u8)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
