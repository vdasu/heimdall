#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

const PID_TARGET: i32 = 0;

#[tracepoint]
pub fn tracepoint__syscalls__sys_enter_openat(ctx: TracePointContext) -> i32 {
    match try_tracepoint__syscalls__sys_enter_openat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_tracepoint__syscalls__sys_enter_openat(_ctx: &TracePointContext) -> Result<i32, i32> {
    let id: u64 = bpf_get_current_pid_tgid();
    let pid: u32 = id as u32;

    if PID_TARGET != 0 && PID_TARGET != pid as i32 {
        return Ok(0);
    }

    // SAFETY: calling bpf_printk helper
    unsafe { bpf_printk!(b"Process ID: %d enter sys openat\n", pid) };

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
