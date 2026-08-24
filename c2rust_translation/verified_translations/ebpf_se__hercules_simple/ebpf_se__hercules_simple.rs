#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicI32, Ordering};

const MAX_NUM_SOCKETS: u32 = 256;
const SCION_ENDHOST_PORT: u16 = 30041;
const SCION_HEADER_LINELEN: usize = 4;
const SCION_HEADER_HBH: u8 = 200;
const SCION_HEADER_E2E: u8 = 201;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

const ETH_HLEN: usize = 14;
const IPH_LEN: usize = 20;
const UDPH_LEN: usize = 8;
const SCIONH_LEN: usize = 12;
const SCION_ADDR_IPV4_LEN: usize = 24;

#[repr(C)]
#[derive(Copy, Clone)]
struct HerculesAppAddr {
    ia: u64,
    ip: u32,
    port: u16,
}

#[map(name = "xsks_map")]
static XSKS_MAP: XskMap = XskMap::with_max_entries(MAX_NUM_SOCKETS, 0);

#[map(name = "num_xsks")]
static NUM_XSKS: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "local_addr")]
static LOCAL_ADDR: Array<HerculesAppAddr> = Array::with_max_entries(1, 0);

#[no_mangle]
#[link_section = ".bss"]
static zero: Global<u32> = Global::new(0);

#[no_mangle]
#[link_section = ".bss"]
static mut redirect_count: i32 = 0;

#[xdp]
pub fn xdp_prog_redirect_userspace(ctx: XdpContext) -> u32 {
    match try_xdp_prog(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_prog(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let min_len = ETH_HLEN + IPH_LEN + UDPH_LEN + SCIONH_LEN + SCION_ADDR_IPV4_LEN + UDPH_LEN;
    if data + min_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading h_proto at ethhdr offset 12
    let h_proto = unsafe { *((data + 12) as *const u16) };
    if h_proto != ETH_P_IP.to_be() {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading protocol at iphdr offset 9
    let protocol = unsafe { *((data + ETH_HLEN + 9) as *const u8) };
    if protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let key_zero = zero.load();
    let addr_ptr = LOCAL_ADDR.get_ptr(key_zero).ok_or(())?;
    // SAFETY: valid pointer from array map lookup
    let addr = unsafe { &*addr_ptr };

    // SAFETY: bounds checked above, reading daddr at iphdr offset 16
    let daddr = unsafe { *((data + ETH_HLEN + 16) as *const u32) };
    if daddr != addr.ip {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading dest at udphdr offset 2
    let udp_dest = unsafe { *((data + ETH_HLEN + IPH_LEN + 2) as *const u16) };
    if udp_dest != SCION_ENDHOST_PORT.to_be() {
        return Ok(xdp_action::XDP_PASS);
    }

    let scionh_base = data + ETH_HLEN + IPH_LEN + UDPH_LEN;

    // SAFETY: bounds checked above, reading first u32 for version bits
    let scion_first = unsafe { *(scionh_base as *const u32) };
    if scion_first & 0xF != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading type byte at scionhdr offset 9
    let type_byte = unsafe { *((scionh_base + 9) as *const u8) };
    if type_byte & 0x3 != 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    if (type_byte >> 2) & 0x3 != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading next_header at scionhdr offset 4
    let mut next_header = unsafe { *((scionh_base + 4) as *const u8) };
    // SAFETY: bounds checked above, reading header_len at scionhdr offset 5
    let header_len = unsafe { *((scionh_base + 5) as *const u8) };

    let mut next_offset: usize =
        ETH_HLEN + IPH_LEN + UDPH_LEN + (header_len as usize) * SCION_HEADER_LINELEN;

    if next_header == SCION_HEADER_HBH {
        if data + next_offset + 2 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }
        // SAFETY: bounds checked above
        next_header = unsafe { *((data + next_offset) as *const u8) };
        // SAFETY: bounds checked above
        let ext_len = unsafe { *((data + next_offset + 1) as *const u8) };
        next_offset += ((ext_len as usize) + 1) * SCION_HEADER_LINELEN;
    }

    if next_header == SCION_HEADER_E2E {
        if data + next_offset + 2 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }
        // SAFETY: bounds checked above
        next_header = unsafe { *((data + next_offset) as *const u8) };
        // SAFETY: bounds checked above
        let ext_len = unsafe { *((data + next_offset + 1) as *const u8) };
        next_offset += ((ext_len as usize) + 1) * SCION_HEADER_LINELEN;
    }

    if next_header != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let scion_addr_base = scionh_base + SCIONH_LEN;

    // SAFETY: bounds checked above, reading dst_ia at scionaddrhdr offset 0
    let dst_ia = unsafe { *(scion_addr_base as *const u64) };
    if dst_ia != addr.ia {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading dst_ip at scionaddrhdr offset 16
    let dst_ip = unsafe { *((scion_addr_base + 16) as *const u32) };
    if dst_ip != addr.ip {
        return Ok(xdp_action::XDP_PASS);
    }

    let offset = next_offset;
    let l4udph = data + offset;
    if l4udph + UDPH_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: bounds checked above, reading dest at L4 udphdr offset 2
    let l4_dest = unsafe { *((l4udph + 2) as *const u16) };
    if l4_dest != addr.port {
        return Ok(xdp_action::XDP_PASS);
    }

    let offset = offset + UDPH_LEN;

    // SAFETY: data is writable in XDP, writing payload offset
    unsafe { *(data as *mut u32) = offset as u32 };

    let num_xsks_ptr = NUM_XSKS.get_ptr(key_zero).ok_or(())?;
    // SAFETY: valid pointer from array map lookup
    let num_xsks_val = unsafe { *num_xsks_ptr };

    // SAFETY: creating atomic from valid BSS global pointer
    let counter = unsafe { AtomicI32::from_ptr(core::ptr::addr_of_mut!(redirect_count)) };
    counter.fetch_add(1, Ordering::Relaxed);

    // SAFETY: reading BSS global after atomic increment
    let count = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(redirect_count)) };

    let idx = if num_xsks_val != 0 {
        (count as u32) % num_xsks_val
    } else {
        count as u32
    };

    // SAFETY: calling bpf_redirect_map helper directly to match C return semantics
    let ret = unsafe {
        aya_ebpf::helpers::bpf_redirect_map(&XSKS_MAP as *const _ as *mut _, idx as u64, 0)
    };
    Ok(ret as u32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
