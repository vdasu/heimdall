#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::programs::TcContext;
use aya_ebpf::cty::*;
use aya_ebpf::bindings::__sk_buff;
use aya_ebpf::EbpfContext;

const TC_ACT_OK: i32 = 0;
const ETH_P_IP: u16 = 0x0800;

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

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let skb = ctx.as_ptr() as *const __sk_buff;

    // SAFETY: reading protocol field from __sk_buff context
    let protocol = unsafe { (*skb).protocol };

    if protocol != ETH_P_IP.to_be() as u32 {
        return TC_ACT_OK;
    }

    // SAFETY: reading data pointer from __sk_buff context
    let data = unsafe { (*skb).data } as usize;
    // SAFETY: reading data_end pointer from __sk_buff context
    let data_end = unsafe { (*skb).data_end } as usize;

    let l2 = data as *const EthHdr;
    if data + core::mem::size_of::<EthHdr>() > data_end {
        return TC_ACT_OK;
    }

    let l3 = (data + core::mem::size_of::<EthHdr>()) as *const IpHdr;
    if data + core::mem::size_of::<EthHdr>() + core::mem::size_of::<IpHdr>() > data_end {
        return TC_ACT_OK;
    }

    // SAFETY: reading tot_len from IP header (bounds-checked above)
    let tot_len = unsafe { (*l3).tot_len };
    // SAFETY: reading ttl from IP header (bounds-checked above)
    let ttl = unsafe { (*l3).ttl };

    // SAFETY: calling bpf_printk to log packet info
    unsafe {
        aya_ebpf::helpers::bpf_printk!(
            b"Got IP packet: tot_len: %d, ttl: %d",
            u16::from_be(tot_len) as u32,
            ttl as u32
        );
    }

    TC_ACT_OK
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
