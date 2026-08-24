#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::tracepoint;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::TracePointContext;
use core::cell::UnsafeCell;

#[repr(transparent)]
struct BssGlobal<T>(UnsafeCell<T>);

// SAFETY: eBPF programs have single-threaded per-CPU execution
unsafe impl<T> Sync for BssGlobal<T> {}

impl<T> BssGlobal<T> {
    const fn new(val: T) -> Self {
        BssGlobal(UnsafeCell::new(val))
    }
}

impl<T: Copy> BssGlobal<T> {
    fn load(&self) -> T {
        // SAFETY: single-threaded BPF execution, loader initializes before run
        unsafe { core::ptr::read_volatile(self.0.get()) }
    }
}

#[no_mangle]
static my_pid: BssGlobal<i32> = BssGlobal::new(0);

#[tracepoint]
pub fn handle_tp(_ctx: TracePointContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if pid != my_pid.load() {
        return 0;
    }

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
