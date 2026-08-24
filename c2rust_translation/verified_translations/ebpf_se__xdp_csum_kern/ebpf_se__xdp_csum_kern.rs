#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::programs::XdpContext;
use core::mem;

const XDP_DROP: u32 = 1;
const ETH_P_IP: u16 = 0x0800;
const LOOP_LEN: u32 = 32;

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

#[map(name = "rxcnt")]
static RXCNT: PerCpuArray<i64> = PerCpuArray::with_max_entries(256, 0);

#[inline(always)]
fn csum_fold_helper(csum: u32) -> u16 {
    !((csum & 0xffff) + (csum >> 16)) as u16
}

#[inline(always)]
fn ipv4_csum(data_start: *mut u32, data_size: u32, csum: &mut u32) {
    // SAFETY: calling bpf_csum_diff helper with valid packet data pointer
    *csum = unsafe {
        aya_ebpf::helpers::generated::bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            data_start,
            data_size,
            *csum,
        )
    } as u32;
    *csum = csum_fold_helper(*csum) as u32;
}

#[no_mangle]
#[link_section = "xdp_csum"]
pub fn xdp_prog1(ctx: *mut aya_ebpf::bindings::xdp_md) -> u32 {
    return xdp_prog1_inner(XdpContext::new(ctx));

    fn xdp_prog1_inner(ctx: XdpContext) -> u32 {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let rc: u32 = XDP_DROP;

        let nh_off = mem::size_of::<EthHdr>();
        if data + nh_off > data_end {
            return rc;
        }

        let eth = data as *const EthHdr;
        // SAFETY: bounds checked above
        let h_proto = unsafe { (*eth).h_proto };

        if h_proto != (ETH_P_IP).to_be() {
            return rc;
        }

        let iph = (data + nh_off) as *mut IpHdr;

        let nh_off2 = nh_off + mem::size_of::<IpHdr>();
        if data + nh_off2 > data_end {
            return rc;
        }

        let mut csum: u32 = 0;
        let dummy_int: u32 = 23;
        let mut i: u32 = 0;
        while i < LOOP_LEN {
            ipv4_csum(iph as *mut u32, mem::size_of::<IpHdr>() as u32, &mut csum);
            // SAFETY: writing checksum to validated IP header pointer
            unsafe { (*iph).check = csum as u16 };
            let _value = RXCNT.get_ptr(dummy_int);
            i += 1;
        }

        let value = RXCNT.get_ptr_mut(dummy_int);
        if let Some(ptr) = value {
            // SAFETY: dereferencing valid map pointer from successful lookup
            let val = unsafe { *ptr };
            // SAFETY: writing to valid map pointer from successful lookup
            unsafe { *ptr = val + 1 };
        }

        rc
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
