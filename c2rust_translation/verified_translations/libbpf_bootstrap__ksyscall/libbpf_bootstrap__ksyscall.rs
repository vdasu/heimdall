#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::ProbeContext;

#[kprobe]
pub fn tgkill_entry(ctx: ProbeContext) -> u32 {
    match try_tgkill_entry(ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

fn try_tgkill_entry(ctx: ProbeContext) -> Result<i32, i32> {
    let tgid: u64 = ctx.arg(0).ok_or(1i32)?;
    let tid: u64 = ctx.arg(1).ok_or(1i32)?;
    let sig: u64 = ctx.arg(2).ok_or(1i32)?;

    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if sig as i32 == 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1i32)?;

    // SAFETY: calling bpf_printk helper
    unsafe {
        bpf_printk!(
            b"tgkill syscall called by PID %d (%s) for thread id %d with pid %d and signal %d.",
            caller_pid,
            comm.as_ptr(),
            tid as u32,
            tgid as u32,
            sig as u32
        );
    }

    Ok(0)
}

#[kprobe]
pub fn entry_probe(ctx: ProbeContext) -> u32 {
    match try_entry_probe(ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

fn try_entry_probe(ctx: ProbeContext) -> Result<i32, i32> {
    let pid: u64 = ctx.arg(0).ok_or(1i32)?;
    let sig: u64 = ctx.arg(1).ok_or(1i32)?;

    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if sig as i32 == 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1i32)?;

    // SAFETY: calling bpf_printk helper
    unsafe {
        bpf_printk!(
            b"KILL syscall called by PID %d (%s) for PID %d with signal %d.",
            caller_pid,
            comm.as_ptr(),
            pid as u32,
            sig as u32
        );
    }

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
