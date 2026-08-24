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

const TASK_COMM_LEN: usize = 16;

#[repr(C)]
struct Event {
    pid: i32,
    ppid: i32,
    uid: i32,
    comm: [u8; TASK_COMM_LEN],
}

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint]
pub fn tracepoint__syscalls__sys_enter_execve(ctx: TracePointContext) -> i32 {
    match try_tracepoint(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_tracepoint(ctx: TracePointContext) -> Result<i32, i64> {
    let uid = bpf_get_current_uid_gid() as u32;
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as i32;

    let mut event = Event {
        pid: tgid,
        ppid: 0,
        uid: uid as i32,
        comm: [0u8; TASK_COMM_LEN],
    };

    // SAFETY: calling BPF helper to get current task pointer
    let task = unsafe { bpf_get_current_task() } as *const u8;

    // Read task->real_parent (pointer at offset 2504)
    let real_parent_ptr = (task as usize + 2504) as *const *const u8;
    // SAFETY: reading real_parent pointer from task_struct via bpf_probe_read_kernel
    let real_parent: *const u8 = unsafe { bpf_probe_read_kernel(real_parent_ptr)? };

    // Read real_parent->tgid (i32 at offset 2492)
    let tgid_ptr = (real_parent as usize + 2492) as *const i32;
    // SAFETY: reading tgid from parent task_struct via bpf_probe_read_kernel
    let ppid: i32 = unsafe { bpf_probe_read_kernel(tgid_ptr)? };
    event.ppid = ppid;

    let comm = bpf_get_current_comm();
    if let Ok(c) = comm {
        event.comm = c;
    }

    EVENTS.output(&ctx, &event, 0);

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
