#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::{HashMap, PerfEventArray};
use aya_ebpf::helpers::*;
use aya_ebpf::programs::{BtfTracePointContext, RawTracePointContext};
use aya_ebpf::{EbpfContext, Global};

const TASK_COMM_LEN: usize = 16;

const STATE_OFF: usize = 0;
const PID_OFF: usize = 2488;
const TGID_OFF: usize = 2492;
const COMM_OFF: usize = 3032;

#[repr(C)]
struct Event {
    task: [u8; TASK_COMM_LEN],
    prev_task: [u8; TASK_COMM_LEN],
    delta_us: u64,
    pid: u32,
    prev_pid: u32,
}

#[no_mangle]
static targ_comm: Global<[u8; 16]> = Global::new([0u8; 16]);
#[no_mangle]
static filter_comm: Global<u8> = Global::new(0);
#[no_mangle]
static min_us: Global<u64> = Global::new(0);
#[no_mangle]
static targ_pid: Global<u32> = Global::new(0);
#[no_mangle]
static targ_tgid: Global<u32> = Global::new(0);

#[map(name = "start")]
static START: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn comm_allowed(comm: *const u8) -> bool {
    let tc = targ_comm.load();
    let mut i: usize = 0;
    while i < TASK_COMM_LEN {
        if tc[i] == 0 {
            return true;
        }
        // SAFETY: reading byte from comm memory region
        let c = unsafe { *comm.add(i) };
        if c != tc[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn trace_enqueue(tgid: u32, pid: u32, comm: *const u8) -> i32 {
    if pid == 0 {
        return 0;
    }
    let tt = targ_tgid.load();
    if tt != 0 && tt != tgid {
        return 0;
    }
    let tp = targ_pid.load();
    if tp != 0 && tp != pid {
        return 0;
    }
    if filter_comm.load() == 1 && !comm_allowed(comm) {
        return 0;
    }
    // SAFETY: reading kernel monotonic time
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&pid, &ts, 0);
    0
}

#[inline(always)]
fn handle_switch<C: EbpfContext>(ctx: &C, prev: u64, next: u64) -> i32 {
    let mut event = Event {
        task: [0u8; TASK_COMM_LEN],
        prev_task: [0u8; TASK_COMM_LEN],
        delta_us: 0,
        pid: 0,
        prev_pid: 0,
    };
    let mut comm = [0u8; TASK_COMM_LEN];

    // SAFETY: reading __state from kernel task_struct via probe_read
    let state = match unsafe {
        bpf_probe_read_kernel((prev as *const u8).add(STATE_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if state == 0 {
        if filter_comm.load() == 1 {
            // SAFETY: reading comm string from kernel task_struct
            match unsafe {
                bpf_probe_read_kernel_str_bytes(
                    (prev as *const u8).add(COMM_OFF),
                    &mut comm,
                )
            } {
                Ok(_) => {}
                Err(_) => return 0,
            };
        }
        // SAFETY: reading tgid from kernel task_struct
        let tgid = match unsafe {
            bpf_probe_read_kernel((prev as *const u8).add(TGID_OFF) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => return 0,
        };
        // SAFETY: reading pid from kernel task_struct
        let prev_pid = match unsafe {
            bpf_probe_read_kernel((prev as *const u8).add(PID_OFF) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => return 0,
        };
        trace_enqueue(tgid, prev_pid, comm.as_ptr());
    }

    // SAFETY: reading pid from kernel task_struct (next process)
    let pid = match unsafe {
        bpf_probe_read_kernel((next as *const u8).add(PID_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // SAFETY: looking up start map for enqueue timestamp
    let tsp = match unsafe { START.get(&pid) } {
        Some(v) => *v,
        None => return 0,
    };

    // SAFETY: reading kernel monotonic time
    let ktime = unsafe { bpf_ktime_get_ns() };
    let delta_us = (ktime - tsp) / 1000;

    let mu = min_us.load();
    if mu != 0 && delta_us <= mu {
        return 0;
    }

    event.pid = pid;

    // SAFETY: reading pid from kernel task_struct (prev process)
    event.prev_pid = match unsafe {
        bpf_probe_read_kernel((prev as *const u8).add(PID_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    event.delta_us = delta_us;

    // SAFETY: reading comm from kernel task_struct (next process)
    match unsafe {
        bpf_probe_read_kernel_str_bytes(
            (next as *const u8).add(COMM_OFF),
            &mut event.task,
        )
    } {
        Ok(_) => {}
        Err(_) => return 0,
    };

    // SAFETY: reading comm from kernel task_struct (prev process)
    match unsafe {
        bpf_probe_read_kernel_str_bytes(
            (prev as *const u8).add(COMM_OFF),
            &mut event.prev_task,
        )
    } {
        Ok(_) => {}
        Err(_) => return 0,
    };

    let _ = EVENTS.output(ctx, &event, 0);
    let _ = START.remove(&pid);
    0
}

#[btf_tracepoint(function = "sched_wakeup")]
pub fn sched_wakeup(ctx: BtfTracePointContext) -> i32 {
    let p: u64 = ctx.arg(0);
    // SAFETY: reading tgid from kernel task_struct via BTF direct access
    let tgid = unsafe { *((p as *const u8).add(TGID_OFF) as *const u32) };
    // SAFETY: reading pid from kernel task_struct via BTF direct access
    let pid = unsafe { *((p as *const u8).add(PID_OFF) as *const u32) };
    let comm_ptr = (p as *const u8).wrapping_add(COMM_OFF);
    trace_enqueue(tgid, pid, comm_ptr)
}

#[btf_tracepoint(function = "sched_wakeup_new")]
pub fn sched_wakeup_new(ctx: BtfTracePointContext) -> i32 {
    let p: u64 = ctx.arg(0);
    // SAFETY: reading tgid from kernel task_struct via BTF direct access
    let tgid = unsafe { *((p as *const u8).add(TGID_OFF) as *const u32) };
    // SAFETY: reading pid from kernel task_struct via BTF direct access
    let pid = unsafe { *((p as *const u8).add(PID_OFF) as *const u32) };
    let comm_ptr = (p as *const u8).wrapping_add(COMM_OFF);
    trace_enqueue(tgid, pid, comm_ptr)
}

#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch(ctx: BtfTracePointContext) -> i32 {
    let prev: u64 = ctx.arg(1);
    let next: u64 = ctx.arg(2);
    handle_switch(&ctx, prev, next)
}

#[raw_tracepoint(tracepoint = "sched_wakeup")]
pub fn handle_sched_wakeup(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading first arg from raw tracepoint context
    let p = unsafe { *ctx_ptr };

    let mut comm = [0u8; TASK_COMM_LEN];
    if filter_comm.load() == 1 {
        // SAFETY: reading comm from kernel task_struct via probe_read
        match unsafe {
            bpf_probe_read_kernel_str_bytes(
                (p as *const u8).add(COMM_OFF),
                &mut comm,
            )
        } {
            Ok(_) => {}
            Err(_) => return 0,
        };
    }

    // SAFETY: reading tgid from kernel task_struct via probe_read
    let tgid = match unsafe {
        bpf_probe_read_kernel((p as *const u8).add(TGID_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // SAFETY: reading pid from kernel task_struct via probe_read
    let pid = match unsafe {
        bpf_probe_read_kernel((p as *const u8).add(PID_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    trace_enqueue(tgid, pid, comm.as_ptr())
}

#[raw_tracepoint(tracepoint = "sched_wakeup_new")]
pub fn handle_sched_wakeup_new(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading first arg from raw tracepoint context
    let p = unsafe { *ctx_ptr };

    let mut comm = [0u8; TASK_COMM_LEN];
    if filter_comm.load() == 1 {
        // SAFETY: reading comm from kernel task_struct via probe_read
        match unsafe {
            bpf_probe_read_kernel_str_bytes(
                (p as *const u8).add(COMM_OFF),
                &mut comm,
            )
        } {
            Ok(_) => {}
            Err(_) => return 0,
        };
    }

    // SAFETY: reading tgid from kernel task_struct via probe_read
    let tgid = match unsafe {
        bpf_probe_read_kernel((p as *const u8).add(TGID_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // SAFETY: reading pid from kernel task_struct via probe_read
    let pid = match unsafe {
        bpf_probe_read_kernel((p as *const u8).add(PID_OFF) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    trace_enqueue(tgid, pid, comm.as_ptr())
}

#[raw_tracepoint(tracepoint = "sched_switch")]
pub fn handle_sched_switch(ctx: RawTracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u64;
    // SAFETY: reading prev pointer from raw tracepoint context
    let prev = unsafe { *(ctx_ptr.add(1)) };
    // SAFETY: reading next pointer from raw tracepoint context
    let next = unsafe { *(ctx_ptr.add(2)) };
    handle_switch(&ctx, prev, next)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
