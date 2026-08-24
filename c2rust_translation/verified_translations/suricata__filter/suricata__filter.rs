#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuHashMap;

// Protocol constants
const ETH_P_IP: u16 = 0x0800;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
const ETH_HLEN: u32 = 14;
const VLAN_HLEN: u32 = 4;

// __sk_buff field offsets
const SKB_CB0: usize = 48;
const SKB_DATA: usize = 76;
const SKB_DATA_END: usize = 80;

// iphdr field offsets
const IPH_SADDR: u32 = 12;
const IPH_DADDR: u32 = 16;

// Return values matching C's 32-bit int returns
const RET_DROP: i64 = 0;
const RET_ACCEPT: i64 = 0xFFFF_FFFF; // -1 as u32 zero-extended to i64

#[map(name = "ipv4_drop")]
static IPV4_DROP: PerCpuHashMap<u32, u32> = PerCpuHashMap::with_max_entries(32768, 0);

/// Read a big-endian u16 from packet data (matches load_half / LD_ABS semantics).
/// Returns 0 if out of bounds.
#[inline(always)]
fn pkt_load_half(data: usize, data_end: usize, offset: u32) -> u16 {
    let off = offset as usize;
    if data + off + 2 <= data_end {
        // SAFETY: bounds checked above
        u16::from_be(unsafe { *((data + off) as *const u16) })
    } else {
        0
    }
}

/// Read a big-endian u32 from packet data (matches load_word / LD_ABS semantics).
/// Returns 0 if out of bounds.
#[inline(always)]
fn pkt_load_word(data: usize, data_end: usize, offset: u32) -> u32 {
    let off = offset as usize;
    if data + off + 4 <= data_end {
        // SAFETY: bounds checked above
        u32::from_be(unsafe { *((data + off) as *const u32) })
    } else {
        0
    }
}

#[inline(always)]
fn ipv4_filter(data: usize, data_end: usize, nhoff: u32) -> i64 {
    // load_word(skb, nhoff + offsetof(struct iphdr, saddr))
    let mut ip = pkt_load_word(data, data_end, nhoff + IPH_SADDR);

    if let Some(ptr) = IPV4_DROP.get_ptr_mut(&ip) {
        // SAFETY: reading from valid map pointer
        let v = unsafe { *ptr };
        // SAFETY: writing incremented value to valid map pointer
        unsafe { *ptr = v + 1 };
        return RET_DROP;
    }

    // load_word(skb, nhoff + offsetof(struct iphdr, daddr))
    ip = pkt_load_word(data, data_end, nhoff + IPH_DADDR);

    if let Some(ptr) = IPV4_DROP.get_ptr_mut(&ip) {
        // SAFETY: reading from valid map pointer
        let v = unsafe { *ptr };
        // SAFETY: writing incremented value to valid map pointer
        unsafe { *ptr = v + 1 };
        return RET_DROP;
    }

    RET_ACCEPT
}

#[no_mangle]
#[link_section = "filter"]
pub fn hashfilter(ctx: *mut ()) -> i64 {
    let skb = ctx as *const u8;

    // SAFETY: reading __sk_buff.data at offset 76
    let data = unsafe { *((skb as usize + SKB_DATA) as *const u32) } as usize;
    // SAFETY: reading __sk_buff.data_end at offset 80
    let data_end = unsafe { *((skb as usize + SKB_DATA_END) as *const u32) } as usize;

    let mut nhoff: u32 = ETH_HLEN;

    // load_half(skb, offsetof(struct ethhdr, h_proto))
    let mut proto = pkt_load_half(data, data_end, 12);

    if proto == ETH_P_8021AD || proto == ETH_P_8021Q {
        // load_half(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto))
        proto = pkt_load_half(data, data_end, nhoff + 2);
        nhoff += VLAN_HLEN;
    }

    // skb->cb[0] = nhoff
    // SAFETY: writing to __sk_buff.cb[0] at offset 48
    unsafe { *((skb as usize + SKB_CB0) as *mut u32) = nhoff };

    match proto {
        ETH_P_IP => ipv4_filter(data, data_end, nhoff),
        _ => RET_ACCEPT,
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
