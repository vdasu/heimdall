#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: u32,
    tpid: u32,
    sig: i32,
    ret: i32,
    comm: [u8; TASK_COMM_LEN],
}

#[map(name = "values")]
static VALUES: HashMap<u32, Event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
#[link_section = ".rodata"]
static failed_only: Global<u8> = Global::new(0);

#[inline(always)]
fn probe_entry(tpid: u32, sig: i32) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
    let event = Event {
        pid: (pid_tgid >> 32) as u32,
        tpid,
        sig,
        ret: 0,
        comm,
    };
    let _ = VALUES.insert(&tid, &event, 0);
    0
}

#[inline(always)]
fn probe_exit(ret: i32) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    match unsafe { VALUES.get(&tid) } {
        Some(_) => {}
        None => return 0,
    }

    if failed_only.load() != 0 && ret >= 0 {
        let _ = VALUES.remove(&tid);
        return 0;
    }

    let _ = VALUES.remove(&tid);
    0
}

#[tracepoint]
pub fn kill_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint args[0] at byte offset 16
    let args0: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let tpid = args0 as u32;
    // SAFETY: reading tracepoint args[1] at byte offset 24
    let args1: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let sig = args1 as i32;
    probe_entry(tpid, sig)
}

#[tracepoint]
pub fn kill_exit(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint ret field at byte offset 16
    let ret_val: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_exit(ret_val as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
