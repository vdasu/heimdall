#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::Array;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::TracePointContext;
use core::ffi::c_void;

#[map(name = "my_pid_map")]
static MY_PID_MAP: Array<i32> = Array::with_max_entries(1, 0);

#[no_mangle]
#[link_section = "tp/syscalls/sys_enter_write"]
pub fn handle_tp(ctx: *mut c_void) -> u32 {
    let ctx = TracePointContext::new(ctx);
    match try_handle_tp(ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

fn try_handle_tp(_ctx: TracePointContext) -> Result<i32, i32> {
    let index: u32 = 0;
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    let my_pid_ptr = match MY_PID_MAP.get_ptr(index) {
        Some(ptr) => ptr,
        None => return Ok(1),
    };

    // SAFETY: pointer from get_ptr is valid for the BPF program lifetime
    let my_pid = unsafe { *my_pid_ptr };

    if my_pid != pid {
        return Ok(1);
    }

    // SAFETY: calling bpf_printk helper
    unsafe {
        bpf_printk!(b"BPF triggered from PID %d.\n", pid);
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
