#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::{HashMap, StackTrace};
use aya_ebpf::helpers::*;
use aya_ebpf::programs::PerfEventContext;
use aya_ebpf::Global;

const TASK_COMM_LEN: usize = 16;
const MAX_ENTRIES: u32 = 10240;
const MAX_PID_NR: u32 = 30;
const MAX_TID_NR: u32 = 30;
const BPF_F_USER_STACK: u64 = 1 << 8;
const BPF_NOEXIST: u64 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct KeyT {
    pid: u32,
    user_stack_id: i32,
    kern_stack_id: i32,
    name: [u8; TASK_COMM_LEN],
}

#[no_mangle]
static kernel_stacks_only: Global<u8> = Global::new(0);
#[no_mangle]
static user_stacks_only: Global<u8> = Global::new(0);
#[no_mangle]
static include_idle: Global<u8> = Global::new(0);
#[no_mangle]
static filter_by_pid: Global<u8> = Global::new(0);
#[no_mangle]
static filter_by_tid: Global<u8> = Global::new(0);
#[no_mangle]
static use_pidns: Global<u8> = Global::new(0);
#[no_mangle]
static pidns_dev: Global<u64> = Global::new(0);
#[no_mangle]
static pidns_ino: Global<u64> = Global::new(0);

#[map(name = "stackmap")]
static STACKMAP: StackTrace = StackTrace::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "counts")]
static COUNTS: HashMap<KeyT, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "pids")]
static PIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_NR, 0);

#[map(name = "tids")]
static TIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_TID_NR, 0);

#[perf_event]
pub fn do_perf_event(ctx: PerfEventContext) -> i32 {
    let pid: u32;
    let tid: u32;

    if use_pidns.load() != 0 {
        let mut ns = aya_ebpf::bindings::bpf_pidns_info { pid: 0, tgid: 0 };
        // SAFETY: calling bpf_get_ns_current_pid_tgid helper with valid pointer
        let ret = unsafe {
            aya_ebpf::helpers::bpf_get_ns_current_pid_tgid(
                pidns_dev.load(),
                pidns_ino.load(),
                &mut ns as *mut _,
                core::mem::size_of::<aya_ebpf::bindings::bpf_pidns_info>() as u32,
            )
        };
        if ret == 0 {
            pid = ns.tgid;
            tid = ns.pid;
        } else {
            let id = bpf_get_current_pid_tgid();
            pid = (id >> 32) as u32;
            tid = id as u32;
        }
    } else {
        let id = bpf_get_current_pid_tgid();
        pid = (id >> 32) as u32;
        tid = id as u32;
    }

    if include_idle.load() == 0 && tid == 0 {
        return 0;
    }

    if filter_by_pid.load() != 0 && PIDS.get_ptr(&pid).is_none() {
        return 0;
    }

    if filter_by_tid.load() != 0 && TIDS.get_ptr(&tid).is_none() {
        return 0;
    }

    let mut key = KeyT {
        pid,
        user_stack_id: 0,
        kern_stack_id: 0,
        name: [0u8; TASK_COMM_LEN],
    };

    key.name = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    if user_stacks_only.load() != 0 {
        key.kern_stack_id = -1;
    } else {
        // SAFETY: calling bpf_get_stackid via StackTrace map
        key.kern_stack_id = match unsafe { STACKMAP.get_stackid::<PerfEventContext>(&ctx, 0) } {
            Ok(id) => id as i32,
            Err(_) => return 0,
        };
    }

    if kernel_stacks_only.load() != 0 {
        key.user_stack_id = -1;
    } else {
        // SAFETY: calling bpf_get_stackid via StackTrace map with user stack flag
        key.user_stack_id = match unsafe { STACKMAP.get_stackid::<PerfEventContext>(&ctx, BPF_F_USER_STACK) } {
            Ok(id) => id as i32,
            Err(_) => return 0,
        };
    }

    let mut valp = COUNTS.get_ptr_mut(&key);
    if valp.is_none() {
        let zero: u64 = 0;
        let err = COUNTS.insert(&key, &zero, BPF_NOEXIST);
        if let Err(e) = err {
            if e != -17 {
                return 0;
            }
        }
        valp = COUNTS.get_ptr_mut(&key);
    }
    if let Some(ptr) = valp {
        // SAFETY: creating atomic from valid map pointer for fetch_add
        let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
        counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
