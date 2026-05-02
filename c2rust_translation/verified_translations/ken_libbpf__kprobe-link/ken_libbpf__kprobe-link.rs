#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

#[kprobe]
pub fn do_unlinkat(ctx: ProbeContext) -> u32 {
    match try_do_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_do_unlinkat(ctx: ProbeContext) -> Result<u32, u32> {
    // Read arg1: struct filename *name
    let name_ptr: u64 = ctx.arg(1).ok_or(1u32)?;

    // BPF_CORE_READ(name, name) — read name->name (offset 0, so just deref the pointer)
    // SAFETY: reading name->name field via bpf_probe_read_kernel
    let filename: u64 = unsafe { bpf_probe_read_kernel(name_ptr as *const u64).map_err(|_| 1u32)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // SAFETY: calling bpf_printk to trace output
    unsafe { bpf_printk!(b"KPROBE ENTRY pid = %d, filename = %s\n", pid, filename) };

    Ok(0)
}

#[kretprobe]
pub fn do_unlinkat_exit(ctx: RetProbeContext) -> u32 {
    match try_do_unlinkat_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_do_unlinkat_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    // Read return value
    let ret: i64 = ctx.ret::<i64>();

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // SAFETY: calling bpf_printk to trace output
    unsafe { bpf_printk!(b"KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret) };

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
