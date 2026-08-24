#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::programs::RetProbeContext;

#[kprobe]
pub fn do_unlinkat(ctx: ProbeContext) -> u32 {
    let _dfd: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let name_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let pid: u64 = bpf_get_current_pid_tgid();
    let pid = (pid >> 32) as u32;
    // SAFETY: reading name->name field (offset 0) from filename struct pointer via probe read
    let filename: u64 = match unsafe { bpf_probe_read_kernel(name_ptr as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: calling bpf_printk helper
    unsafe { bpf_printk!(b"KPROBE ENTRY pid = %d, filename = %s\n", pid, filename) };
    0
}

#[kretprobe]
pub fn do_unlinkat_exit(ctx: RetProbeContext) -> u32 {
    let ret_val: i64 = ctx.ret();
    let pid: u64 = bpf_get_current_pid_tgid();
    let pid = (pid >> 32) as u32;
    // SAFETY: calling bpf_printk helper
    unsafe { bpf_printk!(b"KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret_val) };
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
