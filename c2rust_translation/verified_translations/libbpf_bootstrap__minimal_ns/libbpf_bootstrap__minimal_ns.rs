#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::tracepoint;
use aya_ebpf::helpers::bpf_get_ns_current_pid_tgid;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::bindings::bpf_pidns_info;
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
        unsafe { core::ptr::read(self.0.get()) }
    }
}

#[no_mangle]
static my_pid: BssGlobal<i32> = BssGlobal::new(0);

#[no_mangle]
static dev: BssGlobal<u64> = BssGlobal::new(0);

#[no_mangle]
static ino: BssGlobal<u64> = BssGlobal::new(0);

#[tracepoint]
pub fn handle_tp(_ctx: TracePointContext) -> i32 {
    let mut ns = bpf_pidns_info { pid: 0, tgid: 0 };

    // SAFETY: calling bpf_get_ns_current_pid_tgid with valid stack-allocated struct pointer
    unsafe {
        bpf_get_ns_current_pid_tgid(
            dev.load(),
            ino.load(),
            &mut ns as *mut bpf_pidns_info,
            core::mem::size_of::<bpf_pidns_info>() as u32,
        );
    }

    if ns.pid != my_pid.load() as u32 {
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
