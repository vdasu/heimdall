#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::PerfEventArray;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::XdpContext;

const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_IPV6ROUTE: u8 = 43;
const IPV6_TLV_PAD1: u8 = 0;
const IPV6_TLV_IOAM: u8 = 49;
const IOAM6_TYPE_PREALLOC: u8 = 0;
const IPV6_SRCRT_TYPE_4: u8 = 4;
const XDP_PASS: u32 = 2;

const ETH_HLEN: usize = 14;
const IPV6_HLEN: usize = 40;
const HOPOPT_HLEN: usize = 2;
const IOAM6_HLEN: usize = 4;
const IOAM6_TRACE_HLEN: usize = 8;
const SRH_HLEN: usize = 8;

#[repr(C)]
struct Metadata {
    received_nanosecond: u64,
    sent_second: u32,
    sent_subsecond: u32,
}

#[map(name = "packet_probe_perf")]
static PACKET_PROBE_PERF: PerfEventArray<Metadata> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_prog(ctx: XdpContext) -> u32 {
    match try_xdp_prog(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_xdp_prog(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let packet_size = (data_end - data) as u64;

    let mut md = Metadata {
        received_nanosecond: 0,
        sent_second: 0,
        sent_subsecond: 0,
    };

    // SAFETY: calling BPF helper to get current time
    md.received_nanosecond = unsafe { bpf_ktime_get_ns() };

    // Ethernet header bounds check
    if data + ETH_HLEN > data_end {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading h_proto at offset 12
    let h_proto = unsafe { core::ptr::read_unaligned((data + 12) as *const u16) };
    if h_proto != ETH_P_IPV6.to_be() {
        return Ok(XDP_PASS);
    }

    // IPv6 header bounds check
    let ipv6_start = data + ETH_HLEN;
    if ipv6_start + IPV6_HLEN > data_end {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading nexthdr at ipv6+6
    let ipv6_nexthdr = unsafe { *((ipv6_start + 6) as *const u8) };
    if ipv6_nexthdr != IPPROTO_HOPOPTS {
        return Ok(XDP_PASS);
    }

    // Hop-by-hop options header bounds check
    let hopopt_start = ipv6_start + IPV6_HLEN;
    if hopopt_start + HOPOPT_HLEN > data_end {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading nexthdr
    let hopopt_nexthdr = unsafe { *(hopopt_start as *const u8) };
    // SAFETY: bounds checked above, reading hdrlen
    let hopopt_hdrlen = unsafe { *((hopopt_start + 1) as *const u8) };

    let hoplen = ((hopopt_hdrlen as i32) + 1) << 3;

    // p starts after hop-by-hop options header
    let mut p = hopopt_start + HOPOPT_HLEN;

    // First PAD1 check
    if p + 1 > data_end {
        return Ok(XDP_PASS);
    }
    // SAFETY: bounds checked above
    if unsafe { *(p as *const u8) } == IPV6_TLV_PAD1 {
        p += 1;
    }

    // Second PAD1 check
    if p + 1 > data_end {
        return Ok(XDP_PASS);
    }
    // SAFETY: bounds checked above
    if unsafe { *(p as *const u8) } == IPV6_TLV_PAD1 {
        p += 1;
    }

    // IOAM6 header bounds check
    if p + IOAM6_HLEN > data_end {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading opt_type
    let opt_type = unsafe { *(p as *const u8) };
    if opt_type != IPV6_TLV_IOAM {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading type field at offset 3
    let ioam6_type = unsafe { *((p + 3) as *const u8) };
    if ioam6_type != IOAM6_TYPE_PREALLOC {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading opt_len at offset 1
    let opt_len = unsafe { *((p + 1) as *const u8) };

    // IOAM6 trace header bounds check
    let trace_start = p + IOAM6_HLEN;
    if trace_start + IOAM6_TRACE_HLEN > data_end {
        return Ok(XDP_PASS);
    }

    // Inlined parse_ioam6_trace_header
    let hdr_len = (opt_len as i32) - 2;
    let second_index = (hdr_len - 8) as u8;
    let subsecond_index = (hdr_len - 4) as u8;

    // Bounds check for second timestamp
    if trace_start + (second_index as usize) + 4 > data_end {
        return Ok(XDP_PASS);
    }
    // SAFETY: bounds checked above, reading 32-bit timestamp
    let second_raw = unsafe { core::ptr::read_unaligned((trace_start + second_index as usize) as *const u32) };
    let second = u32::from_be(second_raw);

    // Bounds check for subsecond timestamp
    if trace_start + (subsecond_index as usize) + 4 > data_end {
        return Ok(XDP_PASS);
    }
    // SAFETY: bounds checked above, reading 32-bit timestamp
    let subsecond_raw = unsafe { core::ptr::read_unaligned((trace_start + subsecond_index as usize) as *const u32) };
    let subsecond = u32::from_be(subsecond_raw);

    md.sent_second = second;
    md.sent_subsecond = subsecond;

    // Check hop-by-hop nexthdr for routing header
    if hopopt_nexthdr != IPPROTO_IPV6ROUTE {
        return Ok(XDP_PASS);
    }

    // SRH bounds check
    let srh_start = hopopt_start + (hoplen as usize);
    if srh_start + SRH_HLEN > data_end {
        return Ok(XDP_PASS);
    }

    // SAFETY: bounds checked above, reading routingType at offset 2
    let routing_type = unsafe { *((srh_start + 2) as *const u8) };
    if routing_type != IPV6_SRCRT_TYPE_4 {
        return Err(u32::MAX); // C returns -1
    }

    let flags = 0xFFFF_FFFF_u64 | (packet_size << 32);
    PACKET_PROBE_PERF.output(ctx, &md, flags as u32);

    Ok(XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
