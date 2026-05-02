#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::PerCpuHashMap;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::bindings::xdp_action;

#[repr(C)]
#[derive(Clone, Copy)]
struct DummyKey {
    key: u8,
}

#[map(name = "rxcnt")]
static RXCNT: PerCpuHashMap<DummyKey, i64> = PerCpuHashMap::with_max_entries(256, 0);

#[xdp]
pub fn xdp_prog1(ctx: XdpContext) -> u32 {
    match try_xdp_prog1(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_xdp_prog1(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let rc: u32 = xdp_action::XDP_DROP;

    // ethhdr is 14 bytes
    let nh_off: usize = 14;
    if data + nh_off > data_end {
        return Ok(rc);
    }

    // Read h_proto (not used for branching, but matches C behavior)
    // SAFETY: bounds checked above, reading u16 at offset 12 within ethhdr
    let _h_proto: u16 = unsafe { *((data + 12) as *const u16) };

    let key = DummyKey { key: 23 };
    let value = RXCNT.get_ptr_mut(&key);
    if let Some(v) = value {
        // SAFETY: pointer from map lookup is valid for program lifetime
        unsafe { *v += 1 };
    } else {
        let dummy_value: i64 = 1;
        let _ = RXCNT.insert(&key, &dummy_value, 0);
    }

    Ok(rc)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
