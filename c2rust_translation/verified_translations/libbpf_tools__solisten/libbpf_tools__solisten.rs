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
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const SOCKET_SK_OFF: usize = 24;
const SOCKET_TYPE_OFF: usize = 4;
const SK_FAMILY_OFF: usize = 16;
const SK_RCV_SADDR_OFF: usize = 4;
const SK_V6_RCV_SADDR_OFF: usize = 72;
const INET_SPORT_OFF: usize = 782;

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    addr: [u32; 4],
    pid: u32,
    proto: u32,
    backlog: i32,
    ret: i32,
    port: u16,
    task: [u8; 16],
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

#[map(name = "values")]
static VALUES: HashMap<u32, Event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn fill_event(event: &mut Event, sock: *const c_void) -> Result<(), i64> {
    // SAFETY: reading sock->sk pointer via probe_read_kernel
    let sk: *const c_void = unsafe {
        bpf_probe_read_kernel((sock as *const u8).add(SOCKET_SK_OFF) as *const *const c_void)
    }?;

    // SAFETY: reading sk->__sk_common.skc_family via probe_read_kernel
    let family: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SK_FAMILY_OFF) as *const u16)
    }?;

    // SAFETY: reading sock->type via probe_read_kernel
    let sock_type: u16 = unsafe {
        bpf_probe_read_kernel((sock as *const u8).add(SOCKET_TYPE_OFF) as *const u16)
    }?;

    event.proto = ((family as u32) << 16) | (sock_type as u32);

    // SAFETY: reading inet->inet_sport via probe_read_kernel
    let sport: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(INET_SPORT_OFF) as *const u16)
    }?;
    event.port = u16::from_be(sport);

    if family == AF_INET {
        // SAFETY: reading sk->__sk_common.skc_rcv_saddr via probe_read_kernel
        event.addr[0] = unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(SK_RCV_SADDR_OFF) as *const u32)
        }?;
    } else if family == AF_INET6 {
        // SAFETY: reading first u32 of sk->__sk_common.skc_v6_rcv_saddr via probe_read_kernel
        event.addr[0] = unsafe {
            bpf_probe_read_kernel((sk as *const u8).add(SK_V6_RCV_SADDR_OFF) as *const u32)
        }?;
    }

    event.task = bpf_get_current_comm()?;

    Ok(())
}

#[kprobe]
pub fn inet_listen_entry(ctx: ProbeContext) -> i32 {
    match try_inet_listen_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_inet_listen_entry(ctx: ProbeContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let targ_pid = target_pid.load();
    if targ_pid != 0 && targ_pid != pid as i32 {
        return Ok(0);
    }

    let sock: *const c_void = ctx.arg(0).ok_or(1i64)?;
    let backlog: i32 = ctx.arg(1).ok_or(1i64)?;

    let mut event = Event {
        addr: [0u32; 4],
        pid: 0,
        proto: 0,
        backlog: 0,
        ret: 0,
        port: 0,
        task: [0u8; 16],
    };

    fill_event(&mut event, sock)?;
    event.pid = pid;
    event.backlog = backlog;

    VALUES.insert(&tid, &event, 0).ok();

    Ok(0)
}

#[kretprobe]
pub fn inet_listen_exit(ctx: RetProbeContext) -> i32 {
    match try_inet_listen_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_inet_listen_exit(ctx: RetProbeContext) -> Result<i32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let event_ref = match unsafe { VALUES.get(&tid) } {
        Some(r) => r,
        None => return Ok(0),
    };
    let mut event = *event_ref;

    let ret: i32 = ctx.ret::<i32>();
    event.ret = ret;

    EVENTS.output(&ctx, &event, 0);
    VALUES.remove(&tid).ok();

    Ok(0)
}

#[fexit(function = "inet_listen")]
pub fn inet_listen_fexit(ctx: FExitContext) -> i32 {
    match try_inet_listen_fexit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_inet_listen_fexit(ctx: FExitContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let targ_pid = target_pid.load();
    if targ_pid != 0 && targ_pid != pid as i32 {
        return Ok(0);
    }

    let sock: *const c_void = ctx.arg(0);
    let backlog: i32 = ctx.arg(1);
    let ret: i32 = ctx.arg(2);

    let mut event = Event {
        addr: [0u32; 4],
        pid: 0,
        proto: 0,
        backlog: 0,
        ret: 0,
        port: 0,
        task: [0u8; 16],
    };

    fill_event(&mut event, sock)?;
    event.pid = pid;
    event.backlog = backlog;
    event.ret = ret;

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
