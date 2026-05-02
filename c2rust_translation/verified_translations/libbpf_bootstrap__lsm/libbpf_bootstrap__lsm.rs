#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;

const EPERM: i32 = 1;

#[lsm(hook = "bpf")]
pub fn lsm_bpf(ctx: LsmContext) -> i32 {
    // arg3 is 'ret' - the return value from the previous BPF program
    let ret: i32 = ctx.arg(3);

    if ret != 0 {
        return ret;
    }

    // SAFETY: bpf_printk requires unsafe for the raw helper call
    unsafe { aya_ebpf::helpers::bpf_printk!(b"LSM: block bpf() worked") };

    -EPERM
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
