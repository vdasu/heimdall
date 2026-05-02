#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext;

const IFNAMSIZ: usize = 16;
const PNAME_LEN: usize = 32;

// ---------- Data structures (packed, matching C layout) ----------

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct V6Addr {
    d1: u64,
    d2: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
union Addr {
    v4addr: u32,
    v6addr: V6Addr,
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
#[link_section = ".rodata"]
static TRACING_CFG: TracingConfig = TracingConfig {
    port: 0,
    l4_proto: 0,
    ip_vsn: 0,
};

// ---------- Maps ----------

#[map(name = "skb_addresses")]
static SKB_ADDRESSES: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 29, 0);

// ---------- Probe-read helper ----------

/// Wrapper around bpf_probe_read_kernel with single-unsafe-op compliance.
#[inline(always)]
fn pr<T: Copy>(ptr: *const T) -> Result<T, i64> {
    // SAFETY: reading kernel memory via bpf_probe_read_kernel helper
    unsafe { bpf_probe_read_kernel(ptr).map_err(|e| e as i64) }
}

// ---------- get_netns ----------

#[inline(always)]
fn get_netns(skb: *const u8) -> Result<u32, i64> {
    // skb->dev (pointer, 8 bytes)
    let dev: u64 = pr(skb.wrapping_add(16) as *const u64)?;
    // dev->nd_net.net (pointer, 8 bytes)
    let net: u64 = pr((dev as *const u8).wrapping_add(280) as *const u64)?;
    // net->ns.inum (u32, 4 bytes)
    let mut netns: u32 = pr((net as *const u8).wrapping_add(144) as *const u32)?;

    if netns == 0 {
        // skb->sk (pointer, 8 bytes)
        let sk: u64 = pr(skb.wrapping_add(24) as *const u64)?;
        if sk != 0 {
            // sk->__sk_common.skc_net.net (pointer, 8 bytes)
            let net2: u64 = pr((sk as *const u8).wrapping_add(48) as *const u64)?;
            // net2->ns.inum (u32, 4 bytes)
            netns = pr((net2 as *const u8).wrapping_add(144) as *const u32)?;
        }
    }

    Ok(netns)
}

// ---------- filter_l3_and_l4 ----------

#[inline(always)]
fn filter_l3_and_l4(skb: *const u8) -> Result<bool, i64> {
    // probe_read #0: skb->head (8 bytes)
    let skb_head: u64 = pr(skb.wrapping_add(200) as *const u64)?;
    // probe_read #1: skb->network_header (2 bytes)
    let l3_off: u16 = pr(skb.wrapping_add(184) as *const u16)?;
    // probe_read #2: skb->transport_header (2 bytes)
    let l4_off: u16 = pr(skb.wrapping_add(182) as *const u16)?;

    let l3_hdr = (skb_head as *const u8).wrapping_add(l3_off as usize);

    // probe_read #3: BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version) — 4 bytes
    let version_raw: u32 = pr(l3_hdr as *const u32)?;
    // Extract IP version: C does val <<= 56; val >>= 60 (unsigned)
    let ip_vsn = ((version_raw as u64) << 56 >> 60) as u8;

    // SAFETY: reading volatile const tracing_cfg.ip_vsn from .rodata
    let cfg_ip_vsn = unsafe { core::ptr::read_volatile(&TRACING_CFG.ip_vsn) };
    if ip_vsn != cfg_ip_vsn {
        return Ok(false);
    }

    // probe_read #4: l4_proto (1 byte)
    let proto_off: usize = if ip_vsn == 4 {
        9
    } else if ip_vsn == 6 {
        6
    } else {
        return Ok(false);
    };
    let l4_proto: u8 = pr(l3_hdr.wrapping_add(proto_off) as *const u8)?;

    // SAFETY: reading volatile const tracing_cfg.l4_proto from .rodata
    let cfg_l4_proto = unsafe { core::ptr::read_volatile(&TRACING_CFG.l4_proto) };
    if l4_proto as u16 != cfg_l4_proto {
        return Ok(false);
    }

    let l4_hdr = (skb_head as *const u8).wrapping_add(l4_off as usize);

    // probe_read #5: source port (2 bytes)
    // probe_read #6: dest port (2 bytes)
    let sport: u16;
    let dport: u16;
    if l4_proto == 6 {
        // TCP
        sport = pr(l4_hdr as *const u16)?;
        dport = pr(l4_hdr.wrapping_add(2) as *const u16)?;
    } else if l4_proto == 17 {
        // UDP
        sport = pr(l4_hdr as *const u16)?;
        dport = pr(l4_hdr.wrapping_add(2) as *const u16)?;
    } else {
        return Ok(false);
    }

    // SAFETY: reading volatile const tracing_cfg.port from .rodata
    let cfg_port = unsafe { core::ptr::read_volatile(&TRACING_CFG.port) };
    if dport != cfg_port && sport != cfg_port {
        return Ok(false);
    }

    Ok(true)
}

// ---------- set_meta ----------

#[inline(always)]
fn set_meta(meta: &mut Meta, skb: u64, ctx: &ProbeContext) -> Result<(), i64> {
    // bpf_get_func_ip — use raw binding from generated helpers
    // SAFETY: calling bpf_get_func_ip with valid kprobe context
    meta.pc = unsafe { aya_ebpf::helpers::generated::bpf_get_func_ip(ctx.as_ptr() as *mut _) };

    meta.skb = skb;

    // PT_REGS_PARM2(ctx) — read arg index 1
    meta.second_param = ctx.arg::<u64>(1).unwrap_or(0);

    let skb_ptr = skb as *const u8;

    // skb->mark (4 bytes)
    meta.mark = pr(skb_ptr.wrapping_add(168) as *const u32)?;

    // get_netns
    meta.netns = get_netns(skb_ptr)?;

    // skb->dev->ifindex: 2 probe_reads
    let dev: u64 = pr(skb_ptr.wrapping_add(16) as *const u64)?;
    meta.ifindex = pr((dev as *const u8).wrapping_add(0) as *const u32)?;

    // BPF_CORE_READ_STR_INTO(&meta->ifname, skb, dev, name):
    //   1) probe_read_kernel: skb->dev (8 bytes)
    //   2) probe_read_kernel_str: dev->name
    let dev2: u64 = pr(skb_ptr.wrapping_add(16) as *const u64)?;
    // SAFETY: reading device name via bpf_probe_read_kernel_str_bytes
    unsafe {
        bpf_probe_read_kernel_str_bytes(
            (dev2 as *const u8).wrapping_add(40),
            &mut meta.ifname,
        )
        .map_err(|e| e as i64)?
    };

    // SAFETY: calling bpf_get_current_task
    let current = unsafe { bpf_get_current_task() } as *const u8;
    // current->pid (4 bytes)
    meta.pid = pr(current.wrapping_add(0) as *const u32)? as u32;

    // current->mm->arg_start: 2 probe_reads
    let mm: u64 = pr(current.wrapping_add(8) as *const u64)?;
    let arg_start: u64 = pr((mm as *const u8).wrapping_add(0) as *const u64)?;

    // bpf_probe_read_user_str
    // SAFETY: reading user-space process name
    unsafe {
        bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut meta.pname)
            .map_err(|e| e as i64)?
    };

    Ok(())
}

// ---------- set_tuple ----------

#[inline(always)]
fn set_tuple(tpl: &mut Tuple, skb: *const u8) -> Result<(), i64> {
    let skb_head: u64 = pr(skb.wrapping_add(200) as *const u64)?;
    let l3_off: u16 = pr(skb.wrapping_add(184) as *const u16)?;
    let l4_off: u16 = pr(skb.wrapping_add(182) as *const u16)?;

    let l3_hdr = (skb_head as *const u8).wrapping_add(l3_off as usize);

    // Bitfield read for version (4 bytes)
    let version_raw: u32 = pr(l3_hdr as *const u32)?;
    let ip_vsn = ((version_raw as u64) << 56 >> 60) as u8;

    let mut l3_total_len: u16 = 0;

    if ip_vsn == 4 {
        // IPv4: saddr(4), daddr(4), protocol(1), tot_len(2)
        tpl.saddr = Addr {
            v4addr: pr(l3_hdr.wrapping_add(12) as *const u32)?,
        };
        tpl.daddr = Addr {
            v4addr: pr(l3_hdr.wrapping_add(16) as *const u32)?,
        };
        tpl.l4_proto = pr(l3_hdr.wrapping_add(9) as *const u8)?;
        tpl.l3_proto = 0x0800;
        l3_total_len = u16::from_be(pr(l3_hdr.wrapping_add(2) as *const u16)?);
    } else if ip_vsn == 6 {
        // IPv6: saddr(16), daddr(16), nexthdr(1), payload_len(2)
        tpl.saddr = Addr {
            v6addr: pr(l3_hdr.wrapping_add(8) as *const V6Addr)?,
        };
        tpl.daddr = Addr {
            v6addr: pr(l3_hdr.wrapping_add(24) as *const V6Addr)?,
        };
        tpl.l4_proto = pr(l3_hdr.wrapping_add(6) as *const u8)?;
        tpl.l3_proto = 0x86DD;
        l3_total_len = u16::from_be(pr(l3_hdr.wrapping_add(4) as *const u16)?);
    }

    let l3_hdr_len = l4_off.wrapping_sub(l3_off);
    let l4_hdr = (skb_head as *const u8).wrapping_add(l4_off as usize);

    if tpl.l4_proto == 6 {
        // TCP
        tpl.sport = pr(l4_hdr as *const u16)?;
        tpl.dport = pr(l4_hdr.wrapping_add(2) as *const u16)?;
        // tcp_flags: explicit bpf_probe_read_kernel at ack_seq+5 = offset 13
        tpl.tcp_flags = pr(l4_hdr.wrapping_add(13) as *const u8)?;
        // doff bitfield (4 bytes at offset 12)
        let doff_raw: u32 = pr(l4_hdr.wrapping_add(12) as *const u32)?;
        let doff = ((doff_raw as u64) << 56 >> 60) as u16;
        let l4_hdr_len = doff.wrapping_mul(4);
        tpl.payload_len = l3_total_len
            .wrapping_sub(l3_hdr_len)
            .wrapping_sub(l4_hdr_len);
    } else if tpl.l4_proto == 17 {
        // UDP
        tpl.sport = pr(l4_hdr as *const u16)?;
        tpl.dport = pr(l4_hdr.wrapping_add(2) as *const u16)?;
        let udp_len = u16::from_be(pr(l4_hdr.wrapping_add(4) as *const u16)?);
        tpl.payload_len = udp_len.wrapping_sub(8);
    }

    Ok(())
}

// ---------- handle_skb ----------

#[inline(always)]
fn handle_skb(skb: u64, ctx: &ProbeContext) -> Result<i32, i32> {
    let skb_addr = skb;

    // SAFETY: map lookup on skb_addresses
    let found = unsafe { SKB_ADDRESSES.get(&skb_addr).is_some() };

    if found {
        // tracked = true; goto cont
    } else {
        match filter_l3_and_l4(skb as *const u8) {
            Ok(true) => {}
            _ => return Ok(0),
        }
        let true_val: u8 = 1;
        if SKB_ADDRESSES.insert(&skb_addr, &true_val, 0).is_err() {}
    }

    // cont: fill event and output
    let mut ev = Event {
        meta: Meta {
            pc: 0,
            skb: 0,
            second_param: 0,
            mark: 0,
            netns: 0,
            ifindex: 0,
            pid: 0,
            ifname: [0u8; IFNAMSIZ],
            pname: [0u8; PNAME_LEN],
        },
        tuple: Tuple {
            saddr: Addr { v4addr: 0 },
            daddr: Addr { v4addr: 0 },
            sport: 0,
            dport: 0,
            l3_proto: 0,
            l4_proto: 0,
            tcp_flags: 0,
            payload_len: 0,
        },
    };

    if set_meta(&mut ev.meta, skb, ctx).is_err() {}
    if set_tuple(&mut ev.tuple, skb as *const u8).is_err() {}

    if EVENTS.output::<Event>(&ev, 0).is_err() {}

    Ok(0)
}

// ---------- Entry points ----------

#[kprobe(function = "skb-1")]
pub fn kprobe_skb_1(ctx: ProbeContext) -> u32 {
    let skb: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    match handle_skb(skb, &ctx) {
        Ok(ret) | Err(ret) => ret as u32,
    }
}

#[kprobe(function = "skb-2")]
pub fn kprobe_skb_2(ctx: ProbeContext) -> u32 {
    let skb: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    match handle_skb(skb, &ctx) {
        Ok(ret) | Err(ret) => ret as u32,
    }
}

#[kprobe(function = "skb-3")]
pub fn kprobe_skb_3(ctx: ProbeContext) -> u32 {
    let skb: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    match handle_skb(skb, &ctx) {
        Ok(ret) | Err(ret) => ret as u32,
    }
}

#[kprobe(function = "skb-4")]
pub fn kprobe_skb_4(ctx: ProbeContext) -> u32 {
    let skb: u64 = match ctx.arg(3) {
        Some(v) => v,
        None => return 0,
    };
    match handle_skb(skb, &ctx) {
        Ok(ret) | Err(ret) => ret as u32,
    }
}

#[kprobe(function = "skb-5")]
pub fn kprobe_skb_5(ctx: ProbeContext) -> u32 {
    let skb: u64 = match ctx.arg(4) {
        Some(v) => v,
        None => return 0,
    };
    match handle_skb(skb, &ctx) {
        Ok(ret) | Err(ret) => ret as u32,
    }
}

#[kprobe(function = "skb_lifetime_termination")]
pub fn kprobe_skb_lifetime_termination(ctx: ProbeContext) -> u32 {
    let skb: u64 = match ctx.arg::<u64>(0) {
        Some(v) => v,
        None => return 0,
    };
    if SKB_ADDRESSES.remove(&skb).is_err() {}
    0
}

// ---------- Boilerplate ----------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
