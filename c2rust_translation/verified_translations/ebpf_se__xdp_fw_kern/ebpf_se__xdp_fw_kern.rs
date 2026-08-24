#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{DevMap, HashMap};
use aya_ebpf::programs::XdpContext;

const A_PORT: u8 = 6;
const B_PORT: u8 = 7;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[repr(C)]
#[derive(Clone, Copy)]
struct FlowCtxTableKey {
    ip_proto: u16,
    l4_src: u16,
    l4_dst: u16,
    // 2 bytes padding (u32 alignment)
    ip_src: u32,
    ip_dst: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FlowCtxTableLeaf {
    out_port: u8,
    // 1 byte padding (u16 alignment)
    in_port: u16,
}

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct IpHdr {
    version_ihl: u8,
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
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[map(name = "tx_port")]
static TX_PORT: DevMap = DevMap::with_max_entries(10, 0);

#[map(name = "flow_ctx_table")]
static FLOW_CTX_TABLE: HashMap<FlowCtxTableKey, FlowCtxTableLeaf> =
    HashMap::with_max_entries(1024, 0);

#[inline(always)]
fn biflow(key: &mut FlowCtxTableKey) {
    if key.ip_src > key.ip_dst {
        let swap = key.ip_src;
        key.ip_src = key.ip_dst;
        key.ip_dst = swap;
    }
    if key.l4_src > key.l4_dst {
        let swap = key.l4_src;
        key.l4_src = key.l4_dst;
        key.l4_dst = swap;
    }
}

#[xdp]
pub fn xdp_fw_prog(ctx: XdpContext) -> u32 {
    match try_xdp_fw_prog(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_xdp_fw_prog(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse ethernet header
    if data + core::mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    // SAFETY: bounds checked above
    let h_proto = unsafe { (*(data as *const EthHdr)).h_proto };

    // SAFETY: reading ingress_ifindex from valid xdp_md context
    let ingress_ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    if u16::from_be(h_proto) != ETH_P_IP {
        return Ok(xdp_action::XDP_DROP);
    }

    // Parse IP header
    let ip_off = core::mem::size_of::<EthHdr>();
    if data + ip_off + core::mem::size_of::<IpHdr>() > data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    let ip_ptr = (data + ip_off) as *const IpHdr;
    // SAFETY: bounds checked above
    let protocol = unsafe { (*ip_ptr).protocol };

    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_DROP);
    }

    // Parse L4 header
    let l4_off = ip_off + core::mem::size_of::<IpHdr>();
    if data + l4_off + core::mem::size_of::<UdpHdr>() > data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    let l4_ptr = (data + l4_off) as *const UdpHdr;

    // Build flow key - zero-init to ensure padding bytes are zero
    // SAFETY: FlowCtxTableKey is repr(C) POD type, zero is valid
    let mut flow_key: FlowCtxTableKey = unsafe { core::mem::zeroed() };
    flow_key.ip_proto = protocol as u16;
    // SAFETY: reading saddr from bounds-checked IP header
    flow_key.ip_src = unsafe { (*ip_ptr).saddr };
    // SAFETY: reading daddr from bounds-checked IP header
    flow_key.ip_dst = unsafe { (*ip_ptr).daddr };
    // SAFETY: reading source from bounds-checked UDP header
    flow_key.l4_src = unsafe { (*l4_ptr).source };
    // SAFETY: reading dest from bounds-checked UDP header
    flow_key.l4_dst = unsafe { (*l4_ptr).dest };

    biflow(&mut flow_key);

    if ingress_ifindex == B_PORT as u32 {
        // SAFETY: flow_key is valid and properly initialized
        let flow_leaf = unsafe { FLOW_CTX_TABLE.get(&flow_key) };
        if let Some(leaf) = flow_leaf {
            let out_port = leaf.out_port;
            let ret = TX_PORT.redirect(out_port as u32, 0);
            return Ok(ret.unwrap_or_else(|e| e));
        } else {
            return Ok(xdp_action::XDP_DROP);
        }
    } else {
        // SAFETY: flow_key is valid and properly initialized
        let flow_leaf = unsafe { FLOW_CTX_TABLE.get(&flow_key) };
        if flow_leaf.is_none() {
            // SAFETY: FlowCtxTableLeaf is repr(C) POD type, zero is valid
            let mut new_flow: FlowCtxTableLeaf = unsafe { core::mem::zeroed() };
            new_flow.out_port = A_PORT;
            new_flow.in_port = B_PORT as u16;
            let _ = FLOW_CTX_TABLE.insert(&flow_key, &new_flow, 0);
        }
        let ret = TX_PORT.redirect(B_PORT as u32, 0);
        return Ok(ret.unwrap_or_else(|e| e));
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
