#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;

const ETH_P_IP: u16 = 0x0800;
const ETH_HLEN: usize = 14;
const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1FFF;
const IPPROTO_GRE: u32 = 47;

#[repr(C)]
struct SoEvent {
    src_addr: u32,
    dst_addr: u32,
    ports: u32,
    ip_proto: u32,
    pkt_type: u32,
    ifindex: u32,
}

#[map(name = "rb")]
static RB: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[socket_filter]
pub fn socket_handler(ctx: SkBuffContext) -> i64 {
    match try_socket_handler(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_socket_handler(ctx: &SkBuffContext) -> Result<i64, i64> {
    let nhoff: usize = ETH_HLEN;

    let proto: u16 = ctx.skb.load(12).map_err(|_| 0i64)?;
    let proto = u16::from_be(proto);
    if proto != ETH_P_IP {
        return Ok(0);
    }

    let frag_off: u16 = ctx.skb.load(nhoff + 6).map_err(|_| 0i64)?;
    let frag_off = u16::from_be(frag_off);
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        return Ok(0);
    }

    if let Some(mut entry) = RB.reserve::<SoEvent>(0) {
        // SAFETY: zero-initializing reserved ring buffer entry
        unsafe {
            core::ptr::write_bytes(
                entry.as_mut_ptr() as *mut u8,
                0u8,
                core::mem::size_of::<SoEvent>(),
            );
        }

        let e = entry.as_mut_ptr();

        let ip_proto: u8 = ctx.skb.load(nhoff + 9).unwrap_or(0);
        // SAFETY: writing ip_proto to reserved ring buffer entry
        unsafe { (*e).ip_proto = ip_proto as u32 };

        if ip_proto as u32 != IPPROTO_GRE {
            let src_addr: u32 = ctx.skb.load(nhoff + 12).unwrap_or(0);
            // SAFETY: writing src_addr to reserved ring buffer entry
            unsafe { (*e).src_addr = src_addr };

            let dst_addr: u32 = ctx.skb.load(nhoff + 16).unwrap_or(0);
            // SAFETY: writing dst_addr to reserved ring buffer entry
            unsafe { (*e).dst_addr = dst_addr };
        }

        let verlen: u8 = ctx.skb.load(nhoff).unwrap_or(0);
        let ports_off = nhoff + (((verlen & 0xF) as usize) << 2);
        let ports: u32 = ctx.skb.load(ports_off).unwrap_or(0);
        // SAFETY: writing ports to reserved ring buffer entry
        unsafe { (*e).ports = ports };

        // SAFETY: reading pkt_type from __sk_buff
        let pkt_type = unsafe { (*ctx.skb.skb).pkt_type };
        // SAFETY: writing pkt_type to reserved ring buffer entry
        unsafe { (*e).pkt_type = pkt_type };

        // SAFETY: reading ifindex from __sk_buff
        let ifindex = unsafe { (*ctx.skb.skb).ifindex };
        // SAFETY: writing ifindex to reserved ring buffer entry
        unsafe { (*e).ifindex = ifindex };

        entry.submit(0);

        return Ok(ctx.len() as i64);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
