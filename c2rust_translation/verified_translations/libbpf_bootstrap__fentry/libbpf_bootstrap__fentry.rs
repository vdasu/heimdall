#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::programs::FExitContext;

#[fentry(function = "do_unlinkat")]
pub fn do_unlinkat(ctx: FEntryContext) -> i32 {
    let name_ptr: u64 = ctx.arg(1);
    let pid: u64 = bpf_get_current_pid_tgid();
    // SAFETY: reading name->name field (offset 0) from filename struct pointer
    let name_name: u64 = unsafe { *(name_ptr as *const u64) };
    let pid = (pid >> 32) as u32;
    // SAFETY: calling bpf_printk helper
    unsafe { bpf_printk!(b"fentry: pid = %d, filename = %s\n", pid, name_name) };
    0
}

#[fexit(function = "do_unlinkat")]
pub fn do_unlinkat_exit(ctx: FExitContext) -> i32 {
    let ret: i64 = ctx.arg(2);
    let name_ptr: u64 = ctx.arg(1);
    let pid: u64 = bpf_get_current_pid_tgid();
    // SAFETY: reading name->name field (offset 0) from filename struct pointer
    let name_name: u64 = unsafe { *(name_ptr as *const u64) };
    let pid = (pid >> 32) as u32;
    // SAFETY: calling bpf_printk helper
    unsafe { bpf_printk!(b"fexit: pid = %d, filename = %s, ret = %ld\n", pid, name_name, ret) };
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
