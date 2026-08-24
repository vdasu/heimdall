#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::EbpfContext;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

// sk_buff field offsets (from compiled C binary)
const SKB_PROTOCOL: usize = 180;
const SKB_TRANSPORT_HEADER: usize = 182;
const SKB_NETWORK_HEADER: usize = 184;
const SKB_MAC_HEADER: usize = 186;
const SKB_HEAD: usize = 200;

#[repr(C)]
#[derive(Copy, Clone)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IpHdr {
    _vihl: u8,
    _tos: u8,
    _tot_len: u16,
    _id: u16,
    _frag_off: u16,
    _ttl: u8,
    protocol: u8,
    _check: u16,
    _saddr: u32,
    _daddr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv6Hdr {
    _priority_flow: [u8; 4],
    _payload_len: u16,
    nexthdr: u8,
    _hop_limit: u8,
    _saddr: [u8; 16],
    _daddr: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpHdr {
    _source: u16,
    dest: u16,
    _seq: u32,
    _ack_seq: u32,
    _flags: u16,
    _window: u16,
    _check: u16,
    _urg_ptr: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UdpHdr {
    _source: u16,
    dest: u16,
    _len: u16,
    _check: u16,
}

#[repr(C)]
struct KfreeSkbKey {
    eth_proto: u16,
    ip_proto: u16,
    port: u16,
    reason: u16,
}

#[map(name = "kfree_skb_total")]
static KFREE_SKB_TOTAL: HashMap<KfreeSkbKey, u64> = HashMap::with_max_entries(10240, 0);

#[btf_tracepoint(function = "kfree_skb")]
pub fn kfree_skb(ctx: BtfTracePointContext) -> i32 {
    match try_kfree_skb(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_kfree_skb(ctx: BtfTracePointContext) -> Result<i32, i64> {
    // tp_btf context: args are u64 array at ctx pointer
    // arg[0] = skb, arg[1] = location, arg[2] = reason
    let ctx_ptr = ctx.as_ptr() as *const u64;

    // SAFETY: reading arg[0] (skb pointer) from tp_btf context
    let skb = unsafe { *ctx_ptr } as usize;

    // SAFETY: reading skb->mac_header (u16 at offset 186)
    let mac_header: u16 = unsafe { *((skb + SKB_MAC_HEADER) as *const u16) };

    // skb_mac_header_was_set check
    if mac_header == 0xFFFF {
        return Ok(0);
    }

    // SAFETY: reading arg[2] (reason) from tp_btf context
    let reason = unsafe { *ctx_ptr.add(2) } as u16;

    // SAFETY: reading skb->head (u64 pointer at offset 200)
    let head: u64 = unsafe { *((skb + SKB_HEAD) as *const u64) };

    // SAFETY: reading skb->mac_header again for address computation
    let mac_hdr_off: u16 = unsafe { *((skb + SKB_MAC_HEADER) as *const u16) };

    // Read ethernet header
    let eth_src = (head as usize + mac_hdr_off as usize) as *const EthHdr;
    // SAFETY: reading ethernet header from packet memory
    let eth_hdr: EthHdr = unsafe { bpf_probe_read_kernel(eth_src)? };

    let eth_proto = u16::from_be(eth_hdr.h_proto);

    if eth_proto == 0 {
        // SAFETY: reading skb->protocol (u16 at offset 180)
        let protocol: u16 = unsafe { *((skb + SKB_PROTOCOL) as *const u16) };
        if protocol == 0 {
            return Ok(0);
        }
    }

    let mut ip_proto: u16 = 0;

    match eth_proto {
        ETH_P_IP => {
            // SAFETY: reading skb->head for IP header
            let h: u64 = unsafe { *((skb + SKB_HEAD) as *const u64) };
            // SAFETY: reading skb->network_header (u16 at offset 184)
            let net_hdr: u16 = unsafe { *((skb + SKB_NETWORK_HEADER) as *const u16) };
            let ip_src = (h as usize + net_hdr as usize) as *const IpHdr;
            // SAFETY: reading IP header from packet memory
            let ip_hdr: IpHdr = unsafe { bpf_probe_read_kernel(ip_src)? };
            ip_proto = ip_hdr.protocol as u16;
        }
        ETH_P_IPV6 => {
            // SAFETY: reading skb->head for IPv6 header
            let h: u64 = unsafe { *((skb + SKB_HEAD) as *const u64) };
            // SAFETY: reading skb->network_header (u16 at offset 184)
            let net_hdr: u16 = unsafe { *((skb + SKB_NETWORK_HEADER) as *const u16) };
            let ipv6_src = (h as usize + net_hdr as usize) as *const Ipv6Hdr;
            // SAFETY: reading IPv6 header from packet memory
            let ipv6_hdr: Ipv6Hdr = unsafe { bpf_probe_read_kernel(ipv6_src)? };
            ip_proto = ipv6_hdr.nexthdr as u16;
        }
        _ => {}
    }

    // SAFETY: reading skb->transport_header (u16 at offset 182)
    let transport_header: u16 = unsafe { *((skb + SKB_TRANSPORT_HEADER) as *const u16) };

    // skb_transport_header_was_set check
    if transport_header == 0xFFFF {
        return Ok(0);
    }

    let mut port: u16 = 0;

    match ip_proto {
        IPPROTO_TCP => {
            // SAFETY: reading skb->head for TCP header
            let h: u64 = unsafe { *((skb + SKB_HEAD) as *const u64) };
            // SAFETY: reading skb->transport_header (u16 at offset 182)
            let th: u16 = unsafe { *((skb + SKB_TRANSPORT_HEADER) as *const u16) };
            let tcp_src = (h as usize + th as usize) as *const TcpHdr;
            // SAFETY: reading TCP header from packet memory
            let tcp_hdr: TcpHdr = unsafe { bpf_probe_read_kernel(tcp_src)? };
            port = u16::from_be(tcp_hdr.dest);
        }
        IPPROTO_UDP => {
            // SAFETY: reading skb->head for UDP header
            let h: u64 = unsafe { *((skb + SKB_HEAD) as *const u64) };
            // SAFETY: reading skb->transport_header (u16 at offset 182)
            let th: u16 = unsafe { *((skb + SKB_TRANSPORT_HEADER) as *const u16) };
            let udp_src = (h as usize + th as usize) as *const UdpHdr;
            // SAFETY: reading UDP header from packet memory
            let udp_hdr: UdpHdr = unsafe { bpf_probe_read_kernel(udp_src)? };
            port = u16::from_be(udp_hdr.dest);
        }
        _ => {}
    }

    let key = KfreeSkbKey {
        eth_proto,
        ip_proto,
        port,
        reason,
    };

    increment_map(&key);

    Ok(0)
}

fn increment_map(key: &KfreeSkbKey) {
    // SAFETY: map lookup is safe for valid key reference
    let lookup = unsafe { KFREE_SKB_TOTAL.get(key) };
    match lookup {
        Some(count) => {
            let ptr = count as *const u64 as *mut u64;
            // SAFETY: creating atomic from valid map value pointer
            let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
            atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            let zero: u64 = 0;
            let _ = KFREE_SKB_TOTAL.insert(key, &zero, 1); // BPF_NOEXIST
            // SAFETY: map lookup is safe for valid key reference
            if let Some(count) = unsafe { KFREE_SKB_TOTAL.get(key) } {
                let ptr = count as *const u64 as *mut u64;
                // SAFETY: creating atomic from valid map value pointer
                let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
                atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
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
