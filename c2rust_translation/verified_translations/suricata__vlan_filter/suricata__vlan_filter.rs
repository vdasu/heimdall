#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::programs::SkBuffContext;
use aya_ebpf::EbpfContext;

#[no_mangle]
#[link_section = "filter"]
pub extern "C" fn hashfilter(ctx: *mut aya_ebpf::bindings::__sk_buff) -> i64 {
    let ctx = SkBuffContext::new(ctx);
    // SAFETY: reading vlan_tci field from __sk_buff context at offset 0x18
    let vlan_tci: u32 = unsafe { (*(ctx.as_ptr() as *const aya_ebpf::bindings::__sk_buff)).vlan_tci };
    let vlan_id = vlan_tci & 0x0fff;
    match vlan_id {
        2 | 4 => -1i32 as u32 as i64,
        _ => 0i64,
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
