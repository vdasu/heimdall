#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

const MAX_LINE_SIZE: usize = 80;

#[repr(C)]
struct StrT {
    pid: u32,
    str_buf: [u8; MAX_LINE_SIZE],
}

#[map(name = "events")]
static EVENTS: PerfEventArray<StrT> = PerfEventArray::new(0);

#[uretprobe]
pub fn printret(ctx: RetProbeContext) -> i32 {
    match try_printret(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_printret(ctx: &RetProbeContext) -> Result<i32, i32> {
    let ret: u64 = ctx.ret();
    if ret == 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 0i32)?;
    if comm[0] != b'b' || comm[1] != b'a' || comm[2] != b's' || comm[3] != b'h' || comm[4] != 0 {
        return Ok(0);
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let mut data = StrT {
        pid,
        str_buf: [0u8; MAX_LINE_SIZE],
    };

    // SAFETY: reading user string from return value pointer
    unsafe { bpf_probe_read_user_str(ret as *const u8, &mut data.str_buf) }.map_err(|_| 0i32)?;

    EVENTS.output(ctx, &data, 0);

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
