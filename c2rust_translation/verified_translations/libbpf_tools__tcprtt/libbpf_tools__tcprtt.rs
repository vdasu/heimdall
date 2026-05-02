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
use aya_ebpf::cty::*;
use aya_ebpf::Global;

const MAX_SLOTS: usize = 27;
const IPV6_LEN: usize = 16;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const MAX_ENTRIES: u32 = 10240;
const BPF_NOEXIST: u64 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
struct HistKey {
    family: u16,
    addr: [u8; IPV6_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hist {
    latency: u64,
    cnt: u64,
    slots: [u32; MAX_SLOTS],
}

#[map(name = "hists")]
static HISTS: HashMap<HistKey, Hist> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
#[link_section = ".bss"]
static zero: Hist = Hist {
    latency: 0,
    cnt: 0,
    slots: [0u32; MAX_SLOTS],
};

#[no_mangle]
static targ_laddr_hist: Global<u8> = Global::new(0);
#[no_mangle]
static targ_raddr_hist: Global<u8> = Global::new(0);
#[no_mangle]
static targ_show_ext: Global<u8> = Global::new(0);
#[no_mangle]
static targ_sport: Global<u16> = Global::new(0);
#[no_mangle]
static targ_dport: Global<u16> = Global::new(0);
#[no_mangle]
static targ_saddr: Global<u32> = Global::new(0);
#[no_mangle]
static targ_daddr: Global<u32> = Global::new(0);
#[no_mangle]
static targ_saddr_v6: Global<[u8; 16]> = Global::new([0u8; 16]);
#[no_mangle]
static targ_daddr_v6: Global<[u8; 16]> = Global::new([0u8; 16]);
#[no_mangle]
static targ_ms: Global<u8> = Global::new(0);

#[inline(always)]
fn log2(v: u32) -> u64 {
    let mut v = v;
    let r = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    let mut r = r | shift;
    let shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;
    let shift = ((v > 0x3) as u32) << 1;
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
fn ipv6_is_not_zero(addr: &[u8; IPV6_LEN]) -> bool {
    let mut i = 0;
    while i < IPV6_LEN {
        if addr[i] != 0 {
            return true;
        }
        i += 1;
    }
    false
}

#[inline(always)]
fn ipv6_are_different(a: &[u8; IPV6_LEN], b: &[u8; IPV6_LEN]) -> bool {
    let mut i = 0;
    while i < IPV6_LEN {
        if a[i] != b[i] {
            return true;
        }
        i += 1;
    }
    false
}

#[inline(always)]
fn handle_tcp_rcv_established(sk: *const c_void) -> Result<i32, i32> {
    let sport_cfg = targ_sport.load();
    if sport_cfg != 0 {
        let field_ptr = (sk as *const u8).wrapping_add(14) as *const u16;
        // SAFETY: reading inet_sport from kernel sock via probe_read
        let inet_sport: u16 = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or(0);
        if sport_cfg != inet_sport {
            return Ok(0);
        }
    }

    let dport_cfg = targ_dport.load();
    if dport_cfg != 0 {
        let field_ptr = (sk as *const u8).wrapping_add(12) as *const u16;
        // SAFETY: reading skc_dport from kernel sock via probe_read
        let skc_dport: u16 = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or(0);
        if dport_cfg != skc_dport {
            return Ok(0);
        }
    }

    let mut key = HistKey {
        family: 0,
        addr: [0u8; IPV6_LEN],
    };

    let family_ptr = (sk as *const u8).wrapping_add(16) as *const u16;
    // SAFETY: reading skc_family from kernel sock via probe_read
    key.family = unsafe { bpf_probe_read_kernel(family_ptr) }.unwrap_or(0);

    match key.family {
        AF_INET => {
            let saddr_v6_cfg = targ_saddr_v6.load();
            let daddr_v6_cfg = targ_daddr_v6.load();
            if ipv6_is_not_zero(&saddr_v6_cfg) || ipv6_is_not_zero(&daddr_v6_cfg) {
                return Ok(0);
            }

            let saddr_cfg = targ_saddr.load();
            if saddr_cfg != 0 {
                let field_ptr = (sk as *const u8).wrapping_add(204) as *const u32;
                // SAFETY: reading inet_saddr from kernel inet_sock via probe_read
                let inet_saddr: u32 = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or(0);
                if saddr_cfg != inet_saddr {
                    return Ok(0);
                }
            }

            let daddr_cfg = targ_daddr.load();
            if daddr_cfg != 0 {
                let field_ptr = sk as *const u32;
                // SAFETY: reading skc_daddr from kernel sock via probe_read
                let skc_daddr: u32 = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or(0);
                if daddr_cfg != skc_daddr {
                    return Ok(0);
                }
            }
        }
        AF_INET6 => {
            let saddr_cfg = targ_saddr.load();
            let daddr_cfg = targ_daddr.load();
            if saddr_cfg != 0 || daddr_cfg != 0 {
                return Ok(0);
            }

            let saddr_v6_cfg = targ_saddr_v6.load();
            if ipv6_is_not_zero(&saddr_v6_cfg) {
                let pinet6_ptr = (sk as *const u8).wrapping_add(208) as *const u64;
                // SAFETY: reading pinet6 pointer from kernel inet_sock
                let pinet6: u64 = unsafe { bpf_probe_read_kernel(pinet6_ptr) }.unwrap_or(0);
                let saddr_ptr = pinet6 as *const [u8; 16];
                // SAFETY: reading IPv6 source address from pinet6 struct
                let saddr_v6: [u8; 16] = unsafe { bpf_probe_read_kernel(saddr_ptr) }.unwrap_or([0u8; 16]);
                if ipv6_are_different(&saddr_v6_cfg, &saddr_v6) {
                    return Ok(0);
                }
            }

            let daddr_v6_cfg = targ_daddr_v6.load();
            if ipv6_is_not_zero(&daddr_v6_cfg) {
                let field_ptr = (sk as *const u8).wrapping_add(40) as *const [u8; 16];
                // SAFETY: reading IPv6 dest address from kernel sock
                let skc_v6_daddr: [u8; 16] = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or([0u8; 16]);
                if ipv6_are_different(&daddr_v6_cfg, &skc_v6_daddr) {
                    return Ok(0);
                }
            }
        }
        _ => return Ok(0),
    }

    let laddr_hist = targ_laddr_hist.load();
    let raddr_hist = targ_raddr_hist.load();

    if laddr_hist != 0 {
        if key.family == AF_INET6 {
            let pinet6_ptr = (sk as *const u8).wrapping_add(208) as *const u64;
            // SAFETY: reading pinet6 pointer from kernel inet_sock
            let pinet6: u64 = unsafe { bpf_probe_read_kernel(pinet6_ptr) }.unwrap_or(0);
            let saddr_ptr = pinet6 as *const [u8; 16];
            // SAFETY: reading IPv6 source address from pinet6
            key.addr = unsafe { bpf_probe_read_kernel(saddr_ptr) }.unwrap_or([0u8; 16]);
        } else {
            let field_ptr = (sk as *const u8).wrapping_add(204) as *const u32;
            // SAFETY: reading inet_saddr for local address histogram
            let saddr: u32 = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or(0);
            let bytes = saddr.to_ne_bytes();
            key.addr[0] = bytes[0];
            key.addr[1] = bytes[1];
            key.addr[2] = bytes[2];
            key.addr[3] = bytes[3];
        }
    } else if raddr_hist != 0 {
        if key.family == AF_INET6 {
            let field_ptr = (sk as *const u8).wrapping_add(40) as *const [u8; 16];
            // SAFETY: reading IPv6 dest address for remote histogram
            key.addr = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or([0u8; 16]);
        } else {
            let field_ptr = sk as *const u32;
            // SAFETY: reading skc_daddr for remote address histogram
            let daddr: u32 = unsafe { bpf_probe_read_kernel(field_ptr) }.unwrap_or(0);
            let bytes = daddr.to_ne_bytes();
            key.addr[0] = bytes[0];
            key.addr[1] = bytes[1];
            key.addr[2] = bytes[2];
            key.addr[3] = bytes[3];
        }
    } else {
        key.family = 0;
    }

    // bpf_map_lookup_or_try_init pattern
    let histp: *mut Hist = match HISTS.get_ptr_mut(&key) {
        Some(p) => p,
        None => {
            if let Err(e) = HISTS.insert(&key, &zero, BPF_NOEXIST) {
                if e != -17 {
                    return Ok(0);
                }
            }
            match HISTS.get_ptr_mut(&key) {
                Some(p) => p,
                None => return Ok(0),
            }
        }
    };

    let srtt_ptr = (sk as *const u8).wrapping_add(300) as *const u32;
    // SAFETY: reading srtt_us from kernel tcp_sock via probe_read
    let mut srtt: u32 = unsafe { bpf_probe_read_kernel(srtt_ptr) }.unwrap_or(0);
    srtt >>= 3;

    if targ_ms.load() != 0 {
        srtt /= 1000;
    }

    let mut slot = log2l(srtt as u64);
    if slot >= MAX_SLOTS as u64 {
        slot = MAX_SLOTS as u64 - 1;
    }

    let slots_offset = core::mem::offset_of!(Hist, slots) + slot as usize * core::mem::size_of::<u32>();
    let slot_ptr = (histp as *mut u8).wrapping_add(slots_offset) as *mut u32;
    // SAFETY: creating atomic from valid map pointer for in-place add
    let atomic_slot = unsafe { core::sync::atomic::AtomicU32::from_ptr(slot_ptr) };
    atomic_slot.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    if targ_show_ext.load() != 0 {
        let lat_offset = core::mem::offset_of!(Hist, latency);
        let lat_ptr = (histp as *mut u8).wrapping_add(lat_offset) as *mut u64;
        // SAFETY: creating atomic from valid map pointer for latency sum
        let atomic_lat = unsafe { core::sync::atomic::AtomicU64::from_ptr(lat_ptr) };
        atomic_lat.fetch_add(srtt as u64, core::sync::atomic::Ordering::Relaxed);

        let cnt_offset = core::mem::offset_of!(Hist, cnt);
        let cnt_ptr = (histp as *mut u8).wrapping_add(cnt_offset) as *mut u64;
        // SAFETY: creating atomic from valid map pointer for cnt increment
        let atomic_cnt = unsafe { core::sync::atomic::AtomicU64::from_ptr(cnt_ptr) };
        atomic_cnt.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    Ok(0)
}

#[fentry(function = "tcp_rcv_established")]
pub fn tcp_rcv(ctx: FEntryContext) -> i32 {
    match try_tcp_rcv(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_rcv(ctx: FEntryContext) -> Result<i32, i32> {
    let sk: *const c_void = ctx.arg(0);
    handle_tcp_rcv_established(sk)
}

#[kprobe(function = "tcp_rcv_established")]
pub fn tcp_rcv_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_rcv_kprobe(ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

fn try_tcp_rcv_kprobe(ctx: ProbeContext) -> Result<i32, i32> {
    let sk: *const c_void = ctx.arg(0).ok_or(0i32)?;
    handle_tcp_rcv_established(sk)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
