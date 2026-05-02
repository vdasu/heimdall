#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

#[repr(C)]
struct Event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    duration_ns: u64,
    comm: [u8; 16],
}

#[map(name = "rb")]
static RB: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(_ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;
    let tid = id as u32;

    if pid != tid {
        return 0;
    }

    if let Some(mut entry) = RB.reserve::<Event>(0) {
        let evt = entry.as_mut_ptr();
        // SAFETY: zero-initializing reserved ring buffer entry to prevent stale data leaks
        unsafe { core::ptr::write_bytes(evt as *mut u8, 0u8, core::mem::size_of::<Event>()) };

        // SAFETY: calling bpf_get_current_task helper
        let task = unsafe { bpf_get_current_task() } as *const u8;

        // SAFETY: writing duration_ns to reserved ring buffer entry
        unsafe { (*evt).duration_ns = 0 };
        // SAFETY: writing pid to reserved ring buffer entry
        unsafe { (*evt).pid = pid as i32 };

        // SAFETY: reading real_parent pointer from task_struct
        let rp_result = unsafe { bpf_probe_read_kernel(task.wrapping_add(2504) as *const u64) };
        let real_parent = match rp_result {
            Ok(v) => v as *const u8,
            Err(_) => {
                entry.discard(0);
                return 0;
            }
        };

        // SAFETY: reading tgid from parent task_struct
        let ppid_result = unsafe { bpf_probe_read_kernel(real_parent.wrapping_add(2492) as *const i32) };
        let ppid = match ppid_result {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                return 0;
            }
        };
        // SAFETY: writing ppid to reserved ring buffer entry
        unsafe { (*evt).ppid = ppid };

        // SAFETY: reading exit_code from task_struct
        let ec_result = unsafe { bpf_probe_read_kernel(task.wrapping_add(2388) as *const u32) };
        let exit_code_raw = match ec_result {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                return 0;
            }
        };
        // SAFETY: writing exit_code to reserved ring buffer entry
        unsafe { (*evt).exit_code = (exit_code_raw >> 8) & 0xff };

        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => {
                entry.discard(0);
                return 0;
            }
        };
        // SAFETY: writing comm to reserved ring buffer entry
        unsafe { (*evt).comm = comm };

        entry.submit(0);
    }

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
