#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;
const XDP_PASS: u32 = 2;

#[repr(C)]
struct PacketKey {
    eth_type: u16,
    proto: u16,
    port: u16,
}

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct IpHdr {
    _bitfield1: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct Ipv6Hdr {
    _bitfield_and_flow: [u8; 4],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    _flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[map(name = "xdp_incoming_packets_total")]
static XDP_INCOMING_PACKETS_TOTAL: LruHashMap<PacketKey, u64> =
    LruHashMap::with_max_entries(1024, 0);

#[inline(always)]
fn increment_map(map: &LruHashMap<PacketKey, u64>, key: &PacketKey) {
    let ptr = map.get_ptr_mut(key);
    if ptr.is_none() {
        let zero: u64 = 0;
        let _ = map.insert(key, &zero, 1); // BPF_NOEXIST
        if let Some(p) = map.get_ptr_mut(key) {
            // SAFETY: creating atomic from valid map pointer
            let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) };
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        return;
    }
    if let Some(p) = ptr {
        // SAFETY: creating atomic from valid map pointer
        let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) };
        counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

fn try_trace_lo(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let mut key = PacketKey { eth_type: 0, proto: 0, port: 0 };
    let mut cursor = data;

    // Parse ethernet header
    if cursor + core::mem::size_of::<EthHdr>() > data_end {
        return Ok(XDP_PASS);
    }
    let eth_hdr = cursor as *const EthHdr;
    // SAFETY: bounds checked above
    let h_proto = unsafe { (*eth_hdr).h_proto };
    cursor += core::mem::size_of::<EthHdr>();

    key.eth_type = u16::from_be(h_proto);

    if h_proto == ETH_P_IP.to_be() {
        // Parse IPv4 header
        if cursor + core::mem::size_of::<IpHdr>() > data_end {
            return Ok(XDP_PASS);
        }
        let ip_hdr = cursor as *const IpHdr;
        // SAFETY: bounds checked above
        key.proto = unsafe { (*ip_hdr).protocol } as u16;
        cursor += core::mem::size_of::<IpHdr>();
    } else if h_proto == ETH_P_IPV6.to_be() {
        // Parse IPv6 header
        if cursor + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return Ok(XDP_PASS);
        }
        let ipv6_hdr = cursor as *const Ipv6Hdr;
        // SAFETY: bounds checked above
        key.proto = unsafe { (*ipv6_hdr).nexthdr } as u16;
        cursor += core::mem::size_of::<Ipv6Hdr>();
    }

    if key.proto == IPPROTO_TCP {
        // Parse TCP header
        if cursor + core::mem::size_of::<TcpHdr>() > data_end {
            return Ok(XDP_PASS);
        }
        let tcp_hdr = cursor as *const TcpHdr;
        // SAFETY: bounds checked above
        key.port = u16::from_be(unsafe { (*tcp_hdr).dest });
    } else if key.proto == IPPROTO_UDP {
        // Parse UDP header
        if cursor + core::mem::size_of::<UdpHdr>() > data_end {
            return Ok(XDP_PASS);
        }
        let udp_hdr = cursor as *const UdpHdr;
        // SAFETY: bounds checked above
        key.port = u16::from_be(unsafe { (*udp_hdr).dest });
    }

    // Skip ephemeral port range
    if key.port >= 32768 {
        return Ok(XDP_PASS);
    }

    increment_map(&XDP_INCOMING_PACKETS_TOTAL, &key);

    Ok(XDP_PASS)
}

#[xdp]
pub fn trace_lo(ctx: XdpContext) -> u32 {
    match try_trace_lo(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
