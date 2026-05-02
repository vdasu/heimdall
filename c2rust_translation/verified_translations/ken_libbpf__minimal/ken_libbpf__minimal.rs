#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;

const PID_FILTER: u32 = 0;

#[tracepoint]
pub fn handle_tp(ctx: TracePointContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if PID_FILTER != 0 && pid != PID_FILTER {
        return 0;
    }
    // SAFETY: bpf_printk macro requires unsafe for the underlying helper call
    unsafe { bpf_printk!(b"BPF triggered sys_enter_write from PID %d.\n", pid) };
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
