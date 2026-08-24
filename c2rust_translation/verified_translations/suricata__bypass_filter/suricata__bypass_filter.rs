#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuHashMap;
use aya_ebpf::cty::*;

const ETH_HLEN: u32 = 14;
const ETH_P_IP: u32 = 0x0800;
const ETH_P_IPV6: u32 = 0x86DD;
const ETH_P_8021AD: u32 = 0x88A8;
const ETH_P_8021Q: u32 = 0x8100;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

const IPHDR_PROTOCOL: u32 = 9;
const IPHDR_SADDR: u32 = 12;
const IPHDR_DADDR: u32 = 16;
const IPV6HDR_NEXTHDR: u32 = 6;
const IPV6HDR_SADDR: u32 = 8;
const IPV6HDR_DADDR: u32 = 24;
const ETHHDR_H_PROTO: u32 = 12;
const VLAN_HDR_TCI: u32 = 0;
const VLAN_HDR_PROTO: u32 = 2;
const VLAN_HDR_SIZE: u32 = 4;

const SKB_LEN_OFF: usize = 0;
const SKB_VLAN_TCI_OFF: usize = 24;
const SKB_CB0_OFF: usize = 48;
const SKB_DATA_OFF: usize = 76;
const SKB_DATA_END_OFF: usize = 80;

#[repr(C)]
#[derive(Copy, Clone)]
struct FlowV4Keys {
    src: u32,
    dst: u32,
    ports: u32,
    ip_proto_vlan0: u16,
    vlan1: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FlowV6Keys {
    src: [u32; 4],
    dst: [u32; 4],
    ports: u32,
    ip_proto_vlan0: u16,
    vlan1: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Pair {
    packets: u64,
    bytes: u64,
}

#[map(name = "flow_table_v4")]
static FLOW_TABLE_V4: PerCpuHashMap<FlowV4Keys, Pair> = PerCpuHashMap::with_max_entries(32768, 0);

#[map(name = "flow_table_v6")]
static FLOW_TABLE_V6: PerCpuHashMap<FlowV6Keys, Pair> = PerCpuHashMap::with_max_entries(32768, 0);

#[inline(always)]
fn get_data(skb: *const u8) -> (usize, usize) {
    // SAFETY: reading data pointer from __sk_buff at offset 76
    let data = (unsafe { *(skb.add(SKB_DATA_OFF) as *const u32) }) as usize;
    // SAFETY: reading data_end pointer from __sk_buff at offset 80
    let data_end = (unsafe { *(skb.add(SKB_DATA_END_OFF) as *const u32) }) as usize;
    (data, data_end)
}

#[inline(always)]
fn pkt_byte(skb: *const u8, off: u32) -> u32 {
    let (data, data_end) = get_data(skb);
    let off = off as usize;
    if data + off + 1 > data_end {
        return 0;
    }
    // SAFETY: bounds checked above, reading single byte from packet data
    (unsafe { *((data + off) as *const u8) }) as u32
}

#[inline(always)]
fn pkt_half(skb: *const u8, off: u32) -> u32 {
    let (data, data_end) = get_data(skb);
    let off = off as usize;
    if data + off + 2 > data_end {
        return 0;
    }
    // SAFETY: bounds checked above
    let b0 = (unsafe { *((data + off) as *const u8) }) as u32;
    // SAFETY: bounds checked above
    let b1 = (unsafe { *((data + off + 1) as *const u8) }) as u32;
    (b0 << 8) | b1
}

#[inline(always)]
fn pkt_word(skb: *const u8, off: u32) -> u32 {
    let (data, data_end) = get_data(skb);
    let off = off as usize;
    if data + off + 4 > data_end {
        return 0;
    }
    // SAFETY: bounds checked above
    let b0 = (unsafe { *((data + off) as *const u8) }) as u32;
    // SAFETY: bounds checked above
    let b1 = (unsafe { *((data + off + 1) as *const u8) }) as u32;
    // SAFETY: bounds checked above
    let b2 = (unsafe { *((data + off + 2) as *const u8) }) as u32;
    // SAFETY: bounds checked above
    let b3 = (unsafe { *((data + off + 3) as *const u8) }) as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

#[inline(always)]
fn ipv4_filter(skb: *const u8, nhoff: u32, vlan0: u16, vlan1: u16, skb_len: u32) -> c_int {
    let ip_proto = pkt_byte(skb, nhoff + IPHDR_PROTOCOL);
    let ip_proto_bit: u16 = match ip_proto {
        IPPROTO_TCP => 1,
        IPPROTO_UDP => 0,
        _ => return -1,
    };

    let src = pkt_word(skb, nhoff + IPHDR_SADDR);
    let dst = pkt_word(skb, nhoff + IPHDR_DADDR);

    let verlen = pkt_byte(skb, nhoff);
    let port_nhoff = nhoff + ((verlen & 0xF) << 2);
    let ports = pkt_word(skb, port_nhoff);
    let swapped_ports = (ports >> 16) | (ports << 16);

    let ip_proto_vlan0 = ip_proto_bit | ((vlan0 & 0x7FFF) << 1);

    let tuple = FlowV4Keys {
        src,
        dst,
        ports: swapped_ports,
        ip_proto_vlan0,
        vlan1,
    };

    // SAFETY: PerCpuHashMap::get is pub unsafe fn in aya-ebpf
    match unsafe { FLOW_TABLE_V4.get(&tuple) } {
        Some(value) => {
            let mut v = *value;
            v.packets += 1;
            v.bytes += skb_len as u64;
            FLOW_TABLE_V4.insert(&tuple, &v, 0).ok();
            0
        }
        None => -1,
    }
}

#[inline(always)]
fn ipv6_filter(skb: *const u8, nhoff: u32, vlan0: u16, vlan1: u16, skb_len: u32) -> c_int {
    let nhdr = pkt_byte(skb, nhoff + IPV6HDR_NEXTHDR);
    let ip_proto_bit: u16 = match nhdr {
        IPPROTO_TCP => 1,
        IPPROTO_UDP => 0,
        _ => return -1,
    };

    let src = [
        pkt_word(skb, nhoff + IPV6HDR_SADDR),
        pkt_word(skb, nhoff + IPV6HDR_SADDR + 4),
        pkt_word(skb, nhoff + IPV6HDR_SADDR + 8),
        pkt_word(skb, nhoff + IPV6HDR_SADDR + 12),
    ];
    let dst = [
        pkt_word(skb, nhoff + IPV6HDR_DADDR),
        pkt_word(skb, nhoff + IPV6HDR_DADDR + 4),
        pkt_word(skb, nhoff + IPV6HDR_DADDR + 8),
        pkt_word(skb, nhoff + IPV6HDR_DADDR + 12),
    ];

    let ports = pkt_word(skb, nhoff + 40);
    let swapped_ports = (ports >> 16) | (ports << 16);

    let ip_proto_vlan0 = ip_proto_bit | ((vlan0 & 0x7FFF) << 1);

    let tuple = FlowV6Keys {
        src,
        dst,
        ports: swapped_ports,
        ip_proto_vlan0,
        vlan1,
    };

    // SAFETY: PerCpuHashMap::get is pub unsafe fn in aya-ebpf
    match unsafe { FLOW_TABLE_V6.get(&tuple) } {
        Some(value) => {
            let mut v = *value;
            v.packets += 1;
            v.bytes += skb_len as u64;
            FLOW_TABLE_V6.insert(&tuple, &v, 0).ok();
            0
        }
        None => -1,
    }
}

#[no_mangle]
#[link_section = "classifier"]
pub extern "C" fn hashfilter(ctx: *mut c_void) -> c_int {
    let skb = ctx as *const u8;

    let proto = pkt_half(skb, ETHHDR_H_PROTO);

    // SAFETY: reading vlan_tci from __sk_buff at offset 24
    let vlan_tci = unsafe { *(skb.add(SKB_VLAN_TCI_OFF) as *const u32) };
    let vlan0: u16 = (vlan_tci & 0x0fff) as u16;
    let mut vlan1: u16 = 0;
    let mut nhoff: u32 = ETH_HLEN;

    let proto = if proto == ETH_P_8021AD || proto == ETH_P_8021Q {
        let new_proto = pkt_half(skb, nhoff + VLAN_HDR_PROTO);
        vlan1 = (pkt_half(skb, nhoff + VLAN_HDR_TCI) & 0x0fff) as u16;
        nhoff += VLAN_HDR_SIZE;
        new_proto
    } else {
        proto
    };

    // SAFETY: writing nhoff to __sk_buff cb[0] at offset 48
    unsafe { *((ctx as *mut u8).add(SKB_CB0_OFF) as *mut u32) = nhoff };

    // SAFETY: reading len from __sk_buff at offset 0
    let skb_len = unsafe { *(skb.add(SKB_LEN_OFF) as *const u32) };

    match proto {
        ETH_P_IP => ipv4_filter(skb, nhoff, vlan0, vlan1, skb_len),
        ETH_P_IPV6 => ipv6_filter(skb, nhoff, vlan0, vlan1, skb_len),
        _ => -1,
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
