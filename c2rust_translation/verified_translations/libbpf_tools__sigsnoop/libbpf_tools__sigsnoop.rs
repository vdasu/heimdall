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
    tcomm: [u8; TASK_COMM_LEN],
}

#[no_mangle]
#[link_section = ".rodata"]
static filtered_pid: Global<u32> = Global::new(0);

#[no_mangle]
#[link_section = ".rodata"]
static target_signals: Global<u32> = Global::new(0);

#[no_mangle]
#[link_section = ".rodata"]
static failed_only: Global<u8> = Global::new(0);

#[map(name = "values")]
static VALUES: HashMap<u32, Event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn is_target_signal(sig: i32) -> bool {
    let ts = target_signals.load();
    if ts == 0 {
        return true;
    }
    if (ts & (1u32 << ((sig - 1) as u32))) == 0 {
        return false;
    }
    true
}

fn probe_entry(tpid: i32, sig: i32) -> i32 {
    if !is_target_signal(sig) {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let fp = filtered_pid.load();
    if fp != 0 && pid != fp {
        return 0;
    }

    let mut event = Event {
        pid,
        tpid: tpid as u32,
        sig,
        ret: 0,
        comm: [0u8; TASK_COMM_LEN],
        tcomm: [0u8; TASK_COMM_LEN],
    };

    event.tcomm[0] = b'N';
    event.tcomm[1] = b'/';
    event.tcomm[2] = b'A';
    event.tcomm[3] = 0;

    event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let _ = VALUES.insert(&tid, &event, 0);
    0
}

fn probe_exit(ctx: &TracePointContext, ret: i64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let event_ref = match unsafe { VALUES.get(&tid) } {
        Some(r) => r,
        None => return 0,
    };

    let fo = failed_only.load();
    if fo != 0 && (ret as i32) >= 0 {
        let _ = VALUES.remove(&tid);
        return 0;
    }

    let mut event = *event_ref;
    event.ret = ret as i32;
    EVENTS.output(ctx, &event, 0);

    let _ = VALUES.remove(&tid);
    0
}

#[tracepoint]
pub fn kill_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint args[0] at byte offset 16
    let tpid: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading tracepoint args[1] at byte offset 24
    let sig: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(tpid as i32, sig as i32)
}

#[tracepoint]
pub fn kill_exit(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint ret field at byte offset 16
    let ret: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_exit(&ctx, ret as i64)
}

#[tracepoint]
pub fn tkill_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint args[0] at byte offset 16
    let tpid: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading tracepoint args[1] at byte offset 24
    let sig: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(tpid as i32, sig as i32)
}

#[tracepoint]
pub fn tkill_exit(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint ret field at byte offset 16
    let ret: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_exit(&ctx, ret as i64)
}

#[tracepoint]
pub fn tgkill_entry(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint args[1] at byte offset 24
    let tpid: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading tracepoint args[2] at byte offset 32
    let sig: u64 = match unsafe { ctx.read_at(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_entry(tpid as i32, sig as i32)
}

#[tracepoint]
pub fn tgkill_exit(ctx: TracePointContext) -> i32 {
    // SAFETY: reading tracepoint ret field at byte offset 16
    let ret: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    probe_exit(&ctx, ret as i64)
}

#[tracepoint]
pub fn sig_trace(ctx: TracePointContext) -> i32 {
    // SAFETY: reading sig field at byte offset 8
    let sig_val: u32 = match unsafe { ctx.read_at(8) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading errno field at byte offset 12
    let errno_val: u32 = match unsafe { ctx.read_at(12) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // SAFETY: reading pid field at byte offset 36
    let tpid: u32 = match unsafe { ctx.read_at(36) } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let ret = errno_val as i32;
    let sig = sig_val as i32;

    let fo = failed_only.load();
    if fo != 0 && ret == 0 {
        return 0;
    }

    if !is_target_signal(sig) {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let fp = filtered_pid.load();
    if fp != 0 && pid != fp {
        return 0;
    }

    let mut event = Event {
        pid,
        tpid,
        sig,
        ret,
        comm: [0u8; TASK_COMM_LEN],
        tcomm: [0u8; TASK_COMM_LEN],
    };

    event.tcomm[0] = b'N';
    event.tcomm[1] = b'/';
    event.tcomm[2] = b'A';
    event.tcomm[3] = 0;

    event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
    EVENTS.output(&ctx, &event, 0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
