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
use aya_ebpf::programs::tracing::StackIdContext;
use aya_ebpf::cty::*;
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
struct args_t {
    cap: c_int,
    cap_opt: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct cap_event {
    pid: u32,
    cap: u32,
    tgid: u32,
    uid: u32,
    audit: c_int,
    insetid: c_int,
    ret: c_int,
    task: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct key_t {
    pid: u32,
    tgid: u32,
    user_stack_id: c_int,
    kern_stack_id: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct unique_key {
    cap: c_int,
    tgid: u32,
    cgroupid: u64,
}

#[no_mangle]
static my_pid: Global<i32> = Global::new(-1);

#[no_mangle]
static unique_type: Global<u32> = Global::new(0);

#[no_mangle]
static kernel_stack: Global<bool> = Global::new(false);

#[no_mangle]
static user_stack: Global<bool> = Global::new(false);

#[no_mangle]
static filter_cg: Global<bool> = Global::new(false);

#[no_mangle]
static targ_pid: Global<i32> = Global::new(-1);

#[no_mangle]
#[link_section = ".kconfig"]
static LINUX_KERNEL_VERSION: Global<i32> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u64, args_t> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<cap_event> = PerfEventArray::new(0);

#[map(name = "stackmap")]
static STACKMAP: StackTrace = StackTrace::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "info")]
static INFO: HashMap<key_t, cap_event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "seen")]
static SEEN: HashMap<unique_key, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[kprobe(function = "cap_capable")]
pub fn kprobe__cap_capable_entry(ctx: ProbeContext) -> u32 {
    match try_cap_capable_entry(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_cap_capable_entry(ctx: ProbeContext) -> Result<i32, i64> {
    if filter_cg.load() {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if pid == my_pid.load() as u32 {
        return Ok(0);
    }

    let targ = targ_pid.load();
    if targ != -1 && targ as u32 != pid {
        return Ok(0);
    }

    let cap: c_int = ctx.arg(2).ok_or(1i64)?;
    let cap_opt: c_int = ctx.arg(3).ok_or(1i64)?;

    let args = args_t { cap, cap_opt };
    START.insert(&pid_tgid, &args, 0).ok();

    Ok(0)
}

#[kretprobe(function = "cap_capable")]
pub fn kprobe__cap_capable_exit(ctx: RetProbeContext) -> u32 {
    match try_cap_capable_exit(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_cap_capable_exit(ctx: RetProbeContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let ap = match unsafe { START.get(&pid_tgid) } {
        Some(v) => *v,
        None => return Ok(0),
    };

    START.remove(&pid_tgid).ok();

    let mut event = cap_event {
        pid: (pid_tgid >> 32) as u32,
        cap: ap.cap as u32,
        tgid: pid_tgid as u32,
        uid: bpf_get_current_uid_gid() as u32,
        audit: 0,
        insetid: 0,
        ret: 0,
        task: [0u8; TASK_COMM_LEN],
    };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    event.task = comm;

    event.ret = ctx.ret::<c_int>();

    let kver = LINUX_KERNEL_VERSION.load();
    if kver >= 0x50100 {
        event.audit = if (ap.cap_opt & 0b10) == 0 { 1 } else { 0 };
        event.insetid = if (ap.cap_opt & 0b100) != 0 { 1 } else { 0 };
    } else {
        event.audit = ap.cap_opt;
        event.insetid = -1;
    }

    let uniq = unique_type.load();
    if uniq != 0 {
        let mut key = unique_key {
            cap: ap.cap,
            tgid: 0,
            cgroupid: 0,
        };
        if uniq == 2 {
            // SAFETY: bpf_get_current_cgroup_id is unsafe binding
            key.cgroupid = unsafe { bpf_get_current_cgroup_id() };
        } else {
            key.tgid = pid_tgid as u32;
        }

        // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
        if unsafe { SEEN.get(&key) }.is_some() {
            return Ok(0);
        }

        let zero: u64 = 0;
        SEEN.insert(&key, &zero, 0).ok();
    }

    let ks = kernel_stack.load();
    let us = user_stack.load();

    if ks || us {
        let mut i_key = key_t {
            pid: (pid_tgid >> 32) as u32,
            tgid: pid_tgid as u32,
            user_stack_id: -1,
            kern_stack_id: -1,
        };

        if us {
            let sid = match ctx.get_stackid(&STACKMAP, 256u64) {
                Ok(id) => id as c_int,
                Err(_) => return Ok(0),
            };
            i_key.user_stack_id = sid;
        }

        if ks {
            let sid = match ctx.get_stackid(&STACKMAP, 0u64) {
                Ok(id) => id as c_int,
                Err(_) => return Ok(0),
            };
            i_key.kern_stack_id = sid;
        }

        INFO.insert(&i_key, &event, 1).ok();
    }

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
