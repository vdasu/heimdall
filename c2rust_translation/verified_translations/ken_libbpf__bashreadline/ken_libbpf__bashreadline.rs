#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

const TASK_COMM_LEN: usize = 16;
const MAX_LINE_SIZE: usize = 80;

#[uretprobe]
pub fn printret(ctx: RetProbeContext) -> u32 {
    match try_printret(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_printret(ctx: RetProbeContext) -> Result<i32, i64> {
    let ret: *const c_void = ctx.ret();

    if ret.is_null() {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|e| e)?;

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut str_buf = [0u8; MAX_LINE_SIZE];
    // SAFETY: reading user string from valid user-space pointer
    unsafe { bpf_probe_read_user_str_bytes(ret as *const u8, &mut str_buf).map_err(|e| e as i64)? };

    // SAFETY: calling bpf_printk helper for trace output
    unsafe { bpf_printk!(b"PID %d (%s) read: %s ", pid, comm.as_ptr(), str_buf.as_ptr()) };

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
