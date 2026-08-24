#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::cty::*;

#[uprobe]
pub fn uprobe_add(ctx: ProbeContext) -> u32 {
    let a: i32 = ctx.arg(0).unwrap_or(0);
    let b: i32 = ctx.arg(1).unwrap_or(0);
    // SAFETY: calling bpf_printk helper to log uprobe entry
    unsafe {
        aya_ebpf::helpers::bpf_printk!(b"uprobed_add ENTRY: a = %d, b = %d", a, b);
    }
    0
}

#[uretprobe]
pub fn uretprobe_add(ctx: RetProbeContext) -> u32 {
    let ret: i32 = ctx.ret::<i32>();
    // SAFETY: calling bpf_printk helper to log uretprobe exit
    unsafe {
        aya_ebpf::helpers::bpf_printk!(b"uprobed_add EXIT: return = %d", ret);
    }
    0
}

#[uprobe]
pub fn uprobe_sub(ctx: ProbeContext) -> u32 {
    let a: i32 = ctx.arg(0).unwrap_or(0);
    let b: i32 = ctx.arg(1).unwrap_or(0);
    // SAFETY: calling bpf_printk helper to log uprobe entry
    unsafe {
        aya_ebpf::helpers::bpf_printk!(b"uprobed_sub ENTRY: a = %d, b = %d", a, b);
    }
    0
}

#[uretprobe]
pub fn uretprobe_sub(ctx: RetProbeContext) -> u32 {
    let ret: i32 = ctx.ret::<i32>();
    // SAFETY: calling bpf_printk helper to log uretprobe exit
    unsafe {
        aya_ebpf::helpers::bpf_printk!(b"uprobed_sub EXIT: return = %d", ret);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
