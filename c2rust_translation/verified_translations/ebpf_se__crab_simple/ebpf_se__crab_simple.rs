#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::cty::*;
use aya_ebpf::bindings::xdp_action;

const MAX_TARGET_COUNT: u32 = 64;
const VLAN_MAX_DEPTH: usize = 4;
const REDIR_OPT_TYPE: u8 = 42;
const MAX_OPT_WORDS: usize = 10;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
const IPPROTO_TCP: u8 = 6;
const ETH_ALEN: usize = 6;

#[repr(C, packed)]
struct EthHdr {
    h_dest: [u8; ETH_ALEN],
    h_source: [u8; ETH_ALEN],
    h_proto: u16, // big-endian
}

#[repr(C, packed)]
struct VlanHdr {
    h_vlan_tci: u16,
    h_vlan_encapsulated_proto: u16,
}

#[repr(C)]
struct IpHdr {
    // First byte: version(4) + ihl(4)
    ver_ihl: u8,
    tos: u8,
    tot_len: u16, // big-endian
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    // data offset (4 bits) + reserved (4 bits)
    doff_reserved: u8,
    // flags byte: CWR ECE URG ACK PSH RST SYN FIN
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C, packed)]
struct EthAddr {
    addr: [u8; ETH_ALEN],
}

#[repr(C, packed)]
struct RedirOpt {
    opt_type: u8,
    size: u8,
    ip: u32,
    nop: u16,
}

#[repr(C, packed)]
struct Ipv4PsdHeader {
    src_addr: u32,
    dst_addr: u32,
    zero: u8,
    proto: u8,
    len: u16,
}

#[map(name = "targets_map")]
static TARGETS_MAP: Array<u32> = Array::with_max_entries(MAX_TARGET_COUNT, 0);

#[map(name = "macs_map")]
static MACS_MAP: HashMap<u32, EthAddr> = HashMap::with_max_entries(MAX_TARGET_COUNT, 0);

#[map(name = "targets_count")]
static TARGETS_COUNT: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "cpu_rr_idx")]
static CPU_RR_IDX: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

const IP_HDR_SIZE: usize = core::mem::size_of::<IpHdr>(); // 20
const ETH_HDR_SIZE: usize = core::mem::size_of::<EthHdr>(); // 14
const TCP_HDR_SIZE: usize = core::mem::size_of::<TcpHdr>(); // 20
const VLAN_HDR_SIZE: usize = core::mem::size_of::<VlanHdr>(); // 4
const REDIR_OPT_SIZE: usize = core::mem::size_of::<RedirOpt>(); // 8

#[inline(always)]
fn proto_is_vlan(h_proto: u16) -> bool {
    h_proto == (ETH_P_8021Q as u16).to_be() || h_proto == (ETH_P_8021AD as u16).to_be()
}

/// Returns (new_pos, h_proto) or None on error.
/// h_proto is in network byte order.
#[inline(always)]
fn parse_ethhdr(pos: usize, data_end: usize) -> Option<(usize, u16, usize)> {
    let eth = pos;
    if eth + ETH_HDR_SIZE > data_end {
        return None;
    }
    let eth_ptr = eth as *const EthHdr;
    // SAFETY: bounds checked above
    let h_proto = unsafe { (*eth_ptr).h_proto };
    let mut new_pos = eth + ETH_HDR_SIZE;
    let mut proto = h_proto;

    // Unrolled VLAN parsing loop
    let mut i = 0;
    while i < VLAN_MAX_DEPTH {
        if !proto_is_vlan(proto) {
            break;
        }
        if new_pos + VLAN_HDR_SIZE > data_end {
            break;
        }
        let vlh = new_pos as *const VlanHdr;
        // SAFETY: bounds checked above
        proto = unsafe { (*vlh).h_vlan_encapsulated_proto };
        new_pos += VLAN_HDR_SIZE;
        i += 1;
    }

    Some((new_pos, proto, eth))
}

/// Returns (new_pos, protocol, iphdr_ptr) or None
#[inline(always)]
fn parse_iphdr(pos: usize, data_end: usize) -> Option<(usize, u8, usize)> {
    if pos + IP_HDR_SIZE > data_end {
        return None;
    }
    let iph = pos as *const IpHdr;
    // SAFETY: bounds checked above
    let ver_ihl = unsafe { (*iph).ver_ihl };
    let ihl = (ver_ihl & 0x0F) as usize;
    let hdrsize = ihl * 4;
    if hdrsize < IP_HDR_SIZE {
        return None;
    }
    if pos + hdrsize > data_end {
        return None;
    }
    // SAFETY: bounds checked above
    let protocol = unsafe { (*iph).protocol };
    Some((pos + hdrsize, protocol, pos))
}

/// Returns (new_pos, tcp_hdr_ptr) or None
#[inline(always)]
fn parse_tcphdr(pos: usize, data_end: usize) -> Option<(usize, usize)> {
    if pos + TCP_HDR_SIZE > data_end {
        return None;
    }
    let h = pos as *const TcpHdr;
    // SAFETY: bounds checked above
    let doff = unsafe { (*h).doff_reserved } >> 4;
    let len = (doff as usize) * 4;
    if len < TCP_HDR_SIZE {
        return None;
    }
    if pos + len > data_end {
        return None;
    }
    Some((pos + len, pos))
}

#[inline(always)]
fn csum_reduce_helper(csum: u32) -> u16 {
    let mut c = csum;
    c = ((c & 0xffff0000) >> 16) + (c & 0xffff);
    c = ((c & 0xffff0000) >> 16) + (c & 0xffff);
    c as u16
}

#[inline(always)]
fn get_target_idx_rr() -> i32 {
    let key: u32 = 0;
    let count_ptr = TARGETS_COUNT.get_ptr(key);
    if count_ptr.is_none() {
        return 0;
    }
    let count_ptr = count_ptr.unwrap();
    // SAFETY: pointer from map lookup is valid
    let count = unsafe { *count_ptr };

    let rr_ptr = CPU_RR_IDX.get_ptr_mut(key);
    if rr_ptr.is_none() {
        return 0;
    }
    let rr_ptr = rr_ptr.unwrap();
    // SAFETY: pointer from map lookup is valid
    let rr_val = unsafe { *rr_ptr };

    // SAFETY: writing incremented value back to map
    unsafe { *rr_ptr = rr_val.wrapping_add(1) };

    if count == 0 {
        return rr_val as i32;
    }
    (rr_val % count) as i32
}

/// Gets target IP address. Returns 0 on success, -1 on failure.
#[inline(always)]
fn get_target(daddr: &mut u32) -> i32 {
    let key = get_target_idx_rr() as u32;
    let target_ptr = TARGETS_MAP.get_ptr(key);
    if target_ptr.is_none() {
        return -1;
    }
    // SAFETY: pointer from map lookup is valid
    *daddr = unsafe { *target_ptr.unwrap() };
    0
}

/// Updates MAC addresses. Returns 0 on success, -1 on failure.
#[inline(always)]
fn update_macs(dst_ip: &u32, ethh: *mut EthHdr) -> i32 {
    // SAFETY: reading h_dest to copy to h_source
    let h_dest = unsafe { (*ethh).h_dest };
    // SAFETY: writing h_source with old h_dest
    unsafe { (*ethh).h_source = h_dest };

    // SAFETY: looking up MAC address from hash map
    let target = unsafe { MACS_MAP.get(dst_ip) };
    if let Some(mac) = target {
        // SAFETY: writing h_dest with looked-up MAC
        unsafe { (*ethh).h_dest = mac.addr };
        0
    } else {
        -1
    }
}

#[inline(always)]
fn handle_syn(ctx: &XdpContext, ethh_ptr: usize, iph_ptr: usize, tcph_ptr: usize) -> u32 {
    let data_end = ctx.data_end();

    // Copy old headers
    if ethh_ptr + ETH_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked
    let ethh_old: EthHdr = unsafe { core::ptr::read_unaligned(ethh_ptr as *const EthHdr) };

    if iph_ptr + IP_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked
    let iph_old: IpHdr = unsafe { core::ptr::read_unaligned(iph_ptr as *const IpHdr) };
    let iph_old_daddr = iph_old.daddr;

    if tcph_ptr + TCP_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked
    let tcph_old: TcpHdr = unsafe { core::ptr::read_unaligned(tcph_ptr as *const TcpHdr) };

    // Adjust head to make room for redir_opt
    let delta = 0i32 - (REDIR_OPT_SIZE as i32);
    // SAFETY: calling BPF helper to adjust XDP head
    let ret = unsafe { bpf_xdp_adjust_head(ctx.ctx, delta) };
    if ret != 0 {
        return xdp_action::XDP_ABORTED;
    }

    // Re-read data/data_end after adjust_head
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Rewrite eth header
    let ethh = data;
    if ethh + ETH_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked, writing copied eth header
    unsafe { core::ptr::write_unaligned(ethh as *mut EthHdr, ethh_old) };

    // Rewrite IP header
    let iph = ethh + ETH_HDR_SIZE;
    if iph + IP_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked, writing copied ip header
    unsafe { core::ptr::write_unaligned(iph as *mut IpHdr, iph_old) };

    let iph_mut = iph as *mut IpHdr;

    // Fix IP total length
    // SAFETY: reading tot_len from written header
    let old_tot_len = unsafe { (*iph_mut).tot_len };
    let new_tot_len = (u16::from_be(old_tot_len) + REDIR_OPT_SIZE as u16).to_be();
    // SAFETY: writing updated tot_len
    unsafe { (*iph_mut).tot_len = new_tot_len };

    // Change destination address
    // SAFETY: reading daddr to pass to get_target
    let daddr_ptr = unsafe { &mut (*iph_mut).daddr };
    if get_target(daddr_ptr) != 0 {
        return xdp_action::XDP_ABORTED;
    }

    // Update MACs
    // SAFETY: reading daddr for MAC lookup
    let daddr_val = unsafe { (*iph_mut).daddr };
    if update_macs(&daddr_val, ethh as *mut EthHdr) != 0 {
        return xdp_action::XDP_ABORTED;
    }

    // Fix IP checksum
    // SAFETY: writing check = 0
    unsafe { (*iph_mut).check = 0 };

    let ip_size = IP_HDR_SIZE as u32;
    // SAFETY: calling bpf_csum_diff to compute IP checksum
    let ip_csum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            iph as *mut u32,
            ip_size,
            0,
        )
    };
    let ip_check = !csum_reduce_helper(ip_csum as u32);
    // SAFETY: writing computed IP checksum
    unsafe { (*iph_mut).check = ip_check };

    // TCP header
    let tcph = iph + IP_HDR_SIZE;
    if tcph + TCP_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked, writing copied tcp header
    unsafe { core::ptr::write_unaligned(tcph as *mut TcpHdr, tcph_old) };

    let tcph_mut = tcph as *mut TcpHdr;

    // Update doff: add sizeof(redir_opt)/4 = 2
    // SAFETY: reading doff_reserved
    let old_doff_res = unsafe { (*tcph_mut).doff_reserved };
    let old_doff = old_doff_res >> 4;
    let new_doff = old_doff + (REDIR_OPT_SIZE as u8 / 4);
    // SAFETY: writing new doff_reserved
    unsafe { (*tcph_mut).doff_reserved = (new_doff << 4) | (old_doff_res & 0x0F) };

    // Write redir_opt after TCP header
    let ptr = tcph + TCP_HDR_SIZE;
    if ptr + REDIR_OPT_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    let ropt = RedirOpt {
        opt_type: REDIR_OPT_TYPE,
        size: 6,
        ip: iph_old_daddr,
        nop: 0x0101u16,
    };
    // SAFETY: bounds checked, writing redir_opt
    unsafe { core::ptr::write_unaligned(ptr as *mut RedirOpt, ropt) };

    // Fix TCP checksum
    // SAFETY: writing check = 0
    unsafe { (*tcph_mut).check = 0 };

    // Compute checksum over TCP header + redir_opt
    let tcp_plus_ropt_size = (TCP_HDR_SIZE + REDIR_OPT_SIZE) as u32;
    // SAFETY: calling bpf_csum_diff for TCP+redir_opt
    let mut csum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            tcph as *mut u32,
            tcp_plus_ropt_size,
            0,
        )
    } as u32;

    // Checksum remaining TCP options
    let mut opt_addr = ptr + REDIR_OPT_SIZE;
    let mut i = 0;
    while i < MAX_OPT_WORDS {
        if opt_addr + 4 > data_end {
            break;
        }
        // SAFETY: calling bpf_csum_diff for option word
        let diff = unsafe {
            bpf_csum_diff(
                core::ptr::null_mut(),
                0,
                opt_addr as *mut u32,
                4,
                csum,
            )
        };
        csum = diff as u32;
        opt_addr += 4;
        i += 1;
    }

    csum = csum_reduce_helper(csum) as u32;

    // Pseudo header
    // SAFETY: reading saddr and daddr for pseudo header
    let saddr = unsafe { (*iph_mut).saddr };
    // SAFETY: reading daddr for pseudo header
    let daddr = unsafe { (*iph_mut).daddr };
    // SAFETY: reading tot_len for pseudo header
    let tot_len = unsafe { (*iph_mut).tot_len };

    let mut psdh = Ipv4PsdHeader {
        src_addr: saddr,
        dst_addr: daddr,
        zero: 0,
        proto: IPPROTO_TCP,
        len: (u16::from_be(tot_len) - IP_HDR_SIZE as u16).to_be(),
    };

    let psdh_size = core::mem::size_of::<Ipv4PsdHeader>() as u32;
    // SAFETY: calling bpf_csum_diff for pseudo header
    let psdh_csum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            &mut psdh as *mut Ipv4PsdHeader as *mut u32,
            psdh_size,
            csum,
        )
    };

    let tcp_check = !csum_reduce_helper(psdh_csum as u32);
    // SAFETY: writing computed TCP checksum
    unsafe { (*tcph_mut).check = tcp_check };

    xdp_action::XDP_TX
}

#[xdp]
pub fn xdp_prog_simple(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse ethernet header
    let parsed = parse_ethhdr(data, data_end);
    if parsed.is_none() {
        return xdp_action::XDP_PASS;
    }
    let (pos, nh_type, ethh_ptr) = parsed.unwrap();

    if nh_type != (ETH_P_IP as u16).to_be() {
        return xdp_action::XDP_PASS;
    }

    // Parse IP header
    let parsed = parse_iphdr(pos, data_end);
    if parsed.is_none() {
        return xdp_action::XDP_PASS;
    }
    let (pos, ip_type, iph_ptr) = parsed.unwrap();

    if ip_type != IPPROTO_TCP {
        return xdp_action::XDP_PASS;
    }

    // Parse TCP header
    let parsed = parse_tcphdr(pos, data_end);
    if parsed.is_none() {
        return xdp_action::XDP_ABORTED;
    }
    let (_pos, tcph_ptr) = parsed.unwrap();

    // Check flags
    let tcph = tcph_ptr as *const TcpHdr;
    if tcph_ptr + TCP_HDR_SIZE > data_end {
        return xdp_action::XDP_ABORTED;
    }
    // SAFETY: bounds checked above
    let flags = unsafe { (*tcph).flags };

    // ACK=0x10, RST=0x04, SYN=0x02
    let ack = (flags & 0x10) != 0;
    let rst = (flags & 0x04) != 0;
    let syn = (flags & 0x02) != 0;

    if ack || rst {
        return xdp_action::XDP_PASS;
    }

    if syn {
        return handle_syn(&ctx, ethh_ptr, iph_ptr, tcph_ptr);
    }

    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
