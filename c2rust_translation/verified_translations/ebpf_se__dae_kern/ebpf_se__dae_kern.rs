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
use aya_ebpf::EbpfContext;

const IFNAMSIZ: usize = 16;
const PNAME_LEN: usize = 32;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// sk_buff field offsets (from C binary)
const SKB_DEV: usize = 16;
const SKB_SK: usize = 24;
const SKB_TRANSPORT_HEADER: usize = 182;
const SKB_NETWORK_HEADER: usize = 184;
const SKB_HEAD: usize = 200;
const SKB_MARK: usize = 168;

// net_device offsets
const NETDEV_IFINDEX: usize = 224;
const NETDEV_ND_NET_NET: usize = 280;
const NETDEV_NAME: usize = 304;

// net offsets
const NET_NS_INUM: usize = 144;

// sock offsets
const SK_SKC_NET_NET: usize = 48;

// task_struct offsets
const TASK_MM: usize = 2360;
const TASK_PID: usize = 2488;

// mm_struct offsets
const MM_ARG_START: usize = 376;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Addr {
    data: [u8; 16],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Meta {
    pc: u64,
    skb: u64,
    second_param: u64,
    mark: u32,
    netns: u32,
    ifindex: u32,
    pid: u32,
    ifname: [u8; IFNAMSIZ],
    pname: [u8; PNAME_LEN],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Tuple {
    saddr: Addr,
    daddr: Addr,
    sport: u16,
    dport: u16,
    l3_proto: u16,
    l4_proto: u8,
    tcp_flags: u8,
    payload_len: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Event {
    meta: Meta,
    tuple: Tuple,
}

#[repr(C)]
struct TracingConfig {
    port: u16,
    l4_proto: u16,
    ip_vsn: u8,
}

#[no_mangle]
static tracing_cfg: TracingConfig = TracingConfig {
    port: 0,
    l4_proto: 0,
    ip_vsn: 0,
};

#[map(name = "skb_addresses")]
static SKB_ADDRESSES: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 29, 0);

#[inline(always)]
fn read_ip_version(l3_hdr: u64) -> Result<u8, i64> {
    // SAFETY: reading first 4 bytes of IP header for version bitfield
    let raw: u32 = unsafe { bpf_probe_read_kernel((l3_hdr as *const u32).cast())? };
    Ok(((raw & 0xFF) >> 4) as u8)
}

#[inline(always)]
fn get_netns(skb: u64) -> Result<u32, i64> {
    // Read skb->dev
    // SAFETY: reading dev pointer from sk_buff
    let dev: u64 = unsafe { bpf_probe_read_kernel(((skb + SKB_DEV as u64) as *const u64).cast())? };

    // Read dev->nd_net.net
    // SAFETY: reading nd_net.net pointer from net_device
    let net: u64 = unsafe { bpf_probe_read_kernel(((dev + NETDEV_ND_NET_NET as u64) as *const u64).cast())? };

    // Read net->ns.inum
    // SAFETY: reading ns.inum from net namespace
    let netns: u32 = unsafe { bpf_probe_read_kernel(((net + NET_NS_INUM as u64) as *const u32).cast())? };

    if netns != 0 {
        return Ok(netns);
    }

    // Fallback: try skb->sk->__sk_common.skc_net.net->ns.inum
    // SAFETY: reading sk pointer from sk_buff
    let sk: u64 = unsafe { bpf_probe_read_kernel(((skb + SKB_SK as u64) as *const u64).cast())? };

    if sk == 0 {
        return Ok(0);
    }

    // SAFETY: reading skc_net.net pointer from sock
    let net2: u64 = unsafe { bpf_probe_read_kernel(((sk + SK_SKC_NET_NET as u64) as *const u64).cast())? };

    // SAFETY: reading ns.inum from net namespace
    let netns2: u32 = unsafe { bpf_probe_read_kernel(((net2 + NET_NS_INUM as u64) as *const u32).cast())? };

    Ok(netns2)
}

#[inline(always)]
fn filter_l3_and_l4(skb: u64) -> Result<bool, i64> {
    // SAFETY: reading head pointer from sk_buff
    let skb_head: u64 = unsafe { bpf_probe_read_kernel(((skb + SKB_HEAD as u64) as *const u64).cast())? };

    // SAFETY: reading network_header from sk_buff
    let l3_off: u16 = unsafe { bpf_probe_read_kernel(((skb + SKB_NETWORK_HEADER as u64) as *const u16).cast())? };

    // SAFETY: reading transport_header from sk_buff
    let l4_off: u16 = unsafe { bpf_probe_read_kernel(((skb + SKB_TRANSPORT_HEADER as u64) as *const u16).cast())? };

    let l3_hdr = skb_head + l3_off as u64;

    let ip_vsn = read_ip_version(l3_hdr)?;

    // SAFETY: reading volatile config value
    let cfg_ip_vsn = unsafe { core::ptr::read_volatile(&tracing_cfg.ip_vsn) };
    if ip_vsn != cfg_ip_vsn {
        return Ok(false);
    }

    let l4_proto: u8;
    if ip_vsn == 4 {
        // SAFETY: reading protocol from iphdr
        l4_proto = unsafe { bpf_probe_read_kernel(((l3_hdr + 9) as *const u8).cast())? };
    } else if ip_vsn == 6 {
        // SAFETY: reading nexthdr from ipv6hdr
        l4_proto = unsafe { bpf_probe_read_kernel(((l3_hdr + 6) as *const u8).cast())? };
    } else {
        return Ok(false);
    }

    // SAFETY: reading volatile config value
    let cfg_l4_proto = unsafe { core::ptr::read_volatile(&tracing_cfg.l4_proto) };
    if l4_proto as u16 != cfg_l4_proto {
        return Ok(false);
    }

    let l4_hdr = skb_head + l4_off as u64;
    let sport: u16;
    let dport: u16;

    if l4_proto == IPPROTO_TCP {
        // SAFETY: reading TCP source port
        sport = unsafe { bpf_probe_read_kernel((l4_hdr as *const u16).cast())? };
        // SAFETY: reading TCP dest port
        dport = unsafe { bpf_probe_read_kernel(((l4_hdr + 2) as *const u16).cast())? };
    } else if l4_proto == IPPROTO_UDP {
        // SAFETY: reading UDP source port
        sport = unsafe { bpf_probe_read_kernel((l4_hdr as *const u16).cast())? };
        // SAFETY: reading UDP dest port
        dport = unsafe { bpf_probe_read_kernel(((l4_hdr + 2) as *const u16).cast())? };
    } else {
        return Ok(false);
    }

    // SAFETY: reading volatile config value
    let cfg_port = unsafe { core::ptr::read_volatile(&tracing_cfg.port) };
    if dport != cfg_port && sport != cfg_port {
        return Ok(false);
    }

    Ok(true)
}

#[inline(always)]
fn set_meta(meta: &mut Meta, skb: u64, ctx: &ProbeContext) -> Result<(), i64> {
    // SAFETY: calling bpf_get_func_ip helper
    meta.pc = unsafe { bpf_get_func_ip(ctx.as_ptr()) };

    meta.skb = skb;

    let second_param: u64 = ctx.arg(1).unwrap_or(0u64);
    meta.second_param = second_param;

    // SAFETY: reading mark from sk_buff
    meta.mark = unsafe { bpf_probe_read_kernel(((skb + SKB_MARK as u64) as *const u32).cast())? };

    meta.netns = get_netns(skb)?;

    // Read skb->dev for ifindex
    // SAFETY: reading dev pointer from sk_buff
    let dev: u64 = unsafe { bpf_probe_read_kernel(((skb + SKB_DEV as u64) as *const u64).cast())? };

    // SAFETY: reading ifindex from net_device
    meta.ifindex = unsafe { bpf_probe_read_kernel(((dev + NETDEV_IFINDEX as u64) as *const u32).cast())? };

    // Read skb->dev again for name (matches C binary's separate BPF_CORE_READ chain)
    // SAFETY: reading dev pointer from sk_buff
    let dev2: u64 = unsafe { bpf_probe_read_kernel(((skb + SKB_DEV as u64) as *const u64).cast())? };

    // Read dev->name using probe_read_kernel_str
    // SAFETY: reading device name string
    unsafe { bpf_probe_read_kernel_str_bytes((dev2 + NETDEV_NAME as u64) as *const u8, &mut meta.ifname).map_err(|e| e as i64)? };

    // Get current task
    // SAFETY: calling bpf_get_current_task
    let task: u64 = unsafe { bpf_get_current_task() as u64 };

    // Read task->pid
    // SAFETY: reading pid from task_struct
    meta.pid = unsafe { bpf_probe_read_kernel(((task + TASK_PID as u64) as *const u32).cast())? };

    // Read task->mm
    // SAFETY: reading mm pointer from task_struct
    let mm: u64 = unsafe { bpf_probe_read_kernel(((task + TASK_MM as u64) as *const u64).cast())? };

    // Read mm->arg_start
    // SAFETY: reading arg_start from mm_struct
    let arg_start: u64 = unsafe { bpf_probe_read_kernel(((mm + MM_ARG_START as u64) as *const u64).cast())? };

    // Read process name from user space
    // SAFETY: reading user string from arg_start address
    unsafe { bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut meta.pname).map_err(|e| e as i64)? };

    Ok(())
}

#[inline(always)]
fn set_tuple(tpl: &mut Tuple, skb: u64) -> Result<(), i64> {
    // SAFETY: reading head pointer from sk_buff
    let skb_head: u64 = unsafe { bpf_probe_read_kernel(((skb + SKB_HEAD as u64) as *const u64).cast())? };

    // SAFETY: reading network_header from sk_buff
    let l3_off: u16 = unsafe { bpf_probe_read_kernel(((skb + SKB_NETWORK_HEADER as u64) as *const u16).cast())? };

    // SAFETY: reading transport_header from sk_buff
    let l4_off: u16 = unsafe { bpf_probe_read_kernel(((skb + SKB_TRANSPORT_HEADER as u64) as *const u16).cast())? };

    let l3_hdr = skb_head + l3_off as u64;
    let l4_hdr = skb_head + l4_off as u64;

    let ip_vsn = read_ip_version(l3_hdr)?;

    let mut l3_total_len: u16 = 0;

    if ip_vsn == 4 {
        // Read saddr (16 bytes from iphdr + 12, matching C's BPF_CORE_READ_INTO)
        // SAFETY: reading saddr from iphdr
        tpl.saddr = Addr { data: unsafe { bpf_probe_read_kernel(((l3_hdr + 12) as *const [u8; 16]).cast())? } };

        // Read daddr (16 bytes from iphdr + 16)
        // SAFETY: reading daddr from iphdr
        tpl.daddr = Addr { data: unsafe { bpf_probe_read_kernel(((l3_hdr + 16) as *const [u8; 16]).cast())? } };

        // SAFETY: reading protocol from iphdr
        tpl.l4_proto = unsafe { bpf_probe_read_kernel(((l3_hdr + 9) as *const u8).cast())? };

        tpl.l3_proto = ETH_P_IP;

        // SAFETY: reading tot_len from iphdr
        let tot_len_be: u16 = unsafe { bpf_probe_read_kernel(((l3_hdr + 2) as *const u16).cast())? };
        l3_total_len = u16::from_be(tot_len_be);
    } else if ip_vsn == 6 {
        // Read saddr (16 bytes from ipv6hdr + 8)
        // SAFETY: reading saddr from ipv6hdr
        tpl.saddr = Addr { data: unsafe { bpf_probe_read_kernel(((l3_hdr + 8) as *const [u8; 16]).cast())? } };

        // Read daddr (16 bytes from ipv6hdr + 24)
        // SAFETY: reading daddr from ipv6hdr
        tpl.daddr = Addr { data: unsafe { bpf_probe_read_kernel(((l3_hdr + 24) as *const [u8; 16]).cast())? } };

        // SAFETY: reading nexthdr from ipv6hdr
        tpl.l4_proto = unsafe { bpf_probe_read_kernel(((l3_hdr + 6) as *const u8).cast())? };

        tpl.l3_proto = ETH_P_IPV6;

        // SAFETY: reading payload_len from ipv6hdr
        let payload_len_be: u16 = unsafe { bpf_probe_read_kernel(((l3_hdr + 4) as *const u16).cast())? };
        l3_total_len = u16::from_be(payload_len_be);
    }

    let l3_hdr_len = l4_off.wrapping_sub(l3_off);

    if tpl.l4_proto == IPPROTO_TCP {
        // SAFETY: reading TCP source port
        tpl.sport = unsafe { bpf_probe_read_kernel((l4_hdr as *const u16).cast())? };

        // SAFETY: reading TCP dest port
        tpl.dport = unsafe { bpf_probe_read_kernel(((l4_hdr + 2) as *const u16).cast())? };

        // Read tcp_flags byte at tcphdr offset 13 (ack_seq + 5)
        // SAFETY: reading tcp flags byte
        tpl.tcp_flags = unsafe { bpf_probe_read_kernel(((l4_hdr + 13) as *const u8).cast())? };

        // Read doff bitfield: 4 bytes from tcphdr + 12, extract upper 4 bits of first byte
        // SAFETY: reading doff bitfield from tcphdr
        let doff_raw: u32 = unsafe { bpf_probe_read_kernel(((l4_hdr + 12) as *const u32).cast())? };
        let doff = ((doff_raw & 0xFF) >> 4) as u16;
        let l4_hdr_len = doff * 4;
        tpl.payload_len = l3_total_len.wrapping_sub(l3_hdr_len).wrapping_sub(l4_hdr_len);
    } else if tpl.l4_proto == IPPROTO_UDP {
        // SAFETY: reading UDP source port
        tpl.sport = unsafe { bpf_probe_read_kernel((l4_hdr as *const u16).cast())? };

        // SAFETY: reading UDP dest port
        tpl.dport = unsafe { bpf_probe_read_kernel(((l4_hdr + 2) as *const u16).cast())? };

        // SAFETY: reading UDP len
        let udp_len_be: u16 = unsafe { bpf_probe_read_kernel(((l4_hdr + 4) as *const u16).cast())? };
        tpl.payload_len = u16::from_be(udp_len_be).wrapping_sub(8);
    }

    Ok(())
}

#[inline(always)]
fn handle_skb(skb: u64, ctx: &ProbeContext) -> Result<i32, i64> {
    let skb_addr: u64 = skb;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let tracked = unsafe { SKB_ADDRESSES.get(&skb_addr) }.is_some();

    if !tracked {
        if !filter_l3_and_l4(skb)? {
            return Ok(0);
        }

        let true_val: u8 = 1;
        SKB_ADDRESSES.insert(&skb_addr, &true_val, 0).ok();
    }

    // SAFETY: zeroing event struct
    let mut ev: Event = unsafe { core::mem::zeroed() };
    set_meta(&mut ev.meta, skb, ctx)?;
    set_tuple(&mut ev.tuple, skb)?;

    EVENTS.output::<Event>(&ev, 0).map_err(|e| e as i64)?;

    Ok(0)
}

#[kprobe]
pub fn kprobe_skb_1(ctx: ProbeContext) -> u32 {
    let skb: u64 = ctx.arg(0).unwrap_or(0u64);
    match handle_skb(skb, &ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn kprobe_skb_2(ctx: ProbeContext) -> u32 {
    let skb: u64 = ctx.arg(1).unwrap_or(0u64);
    match handle_skb(skb, &ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn kprobe_skb_3(ctx: ProbeContext) -> u32 {
    let skb: u64 = ctx.arg(2).unwrap_or(0u64);
    match handle_skb(skb, &ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn kprobe_skb_4(ctx: ProbeContext) -> u32 {
    let skb: u64 = ctx.arg(3).unwrap_or(0u64);
    match handle_skb(skb, &ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn kprobe_skb_5(ctx: ProbeContext) -> u32 {
    let skb: u64 = ctx.arg(4).unwrap_or(0u64);
    match handle_skb(skb, &ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn kprobe_skb_lifetime_termination(ctx: ProbeContext) -> u32 {
    let skb_addr: u64 = ctx.arg(0).unwrap_or(0u64);
    SKB_ADDRESSES.remove(&skb_addr).ok();
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";
