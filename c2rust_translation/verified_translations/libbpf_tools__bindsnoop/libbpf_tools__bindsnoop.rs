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
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const MAX_PORTS: u32 = 1024;

#[no_mangle]
static filter_cg: Global<u8> = Global::new(0);

#[no_mangle]
static target_pid: Global<u32> = Global::new(0);

#[no_mangle]
static ignore_errors: Global<u8> = Global::new(1);

#[no_mangle]
static filter_by_port: Global<u8> = Global::new(0);

#[repr(C)]
#[derive(Copy, Clone)]
struct BindEvent {
    addr: [u8; 16],
    ts_us: u64,
    pid: u32,
    bound_dev_if: u32,
    ret: i32,
    port: u16,
    proto: u16,
    opts: u8,
    ver: u8,
    task: [u8; 16],
}

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "sockets")]
static SOCKETS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "ports")]
static PORTS: HashMap<u16, u16> = HashMap::with_max_entries(MAX_PORTS, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<BindEvent> = PerfEventArray::new(0);

#[inline(always)]
fn do_probe_entry(ctx: &ProbeContext) -> Result<i32, i32> {
    let socket: u64 = ctx.arg(0).ok_or(1i32)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let tgt_pid = target_pid.load();
    if tgt_pid != 0 && tgt_pid != pid {
        return Ok(0);
    }

    SOCKETS.insert(&tid, &socket, 0).ok();
    Ok(0)
}

#[inline(always)]
fn do_probe_exit(ctx: &RetProbeContext, ver: u8) -> Result<i32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let socket = match unsafe { SOCKETS.get(&tid) } {
        Some(s) => *s,
        None => return Ok(0),
    };

    let ret_raw: u64 = ctx.ret::<u64>();
    let ret = ret_raw as i32;

    if !(ignore_errors.load() == 1 && ret != 0) {
        do_probe_exit_event(ctx, socket, pid, ret, ver);
    }

    SOCKETS.remove(&tid).ok();
    Ok(0)
}

#[inline(always)]
fn do_probe_exit_event(ctx: &RetProbeContext, socket: u64, pid: u32, ret: i32, ver: u8) {
    // SAFETY: reading sock pointer from kernel socket struct
    let sock: u64 = match unsafe { bpf_probe_read_kernel((socket + 24) as *const u64) } {
        Ok(v) => v,
        Err(_) => return,
    };

    // SAFETY: reading inet_sport from inet_sock struct
    let sport_raw: u16 = match unsafe { bpf_probe_read_kernel((sock + 782) as *const u16) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let sport = u16::from_be(sport_raw);

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let port_found = unsafe { PORTS.get(&sport) }.is_some();
    if filter_by_port.load() == 1 && !port_found {
        return;
    }

    // SAFETY: reading freebind bitfield byte from inet_sock
    let fb_byte: u8 = match unsafe { bpf_probe_read_kernel(sock as *const u8) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let freebind = fb_byte & 1;

    // SAFETY: reading transparent bitfield byte from inet_sock
    let tr_byte: u8 = match unsafe { bpf_probe_read_kernel(sock as *const u8) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let transparent = (tr_byte >> 1) & 1;

    // SAFETY: reading bind_address_no_port bitfield byte from inet_sock
    let ba_byte: u8 = match unsafe { bpf_probe_read_kernel(sock as *const u8) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let bind_addr_no_port = (ba_byte >> 2) & 1;

    // SAFETY: reading skc_reuse area from sock common
    let reuse_area: u64 = match unsafe { bpf_probe_read_kernel((sock + 16) as *const u64) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let reuseaddress = ((reuse_area >> 24) & 1) as u8;

    // SAFETY: reading skc_reuseport area from sock common
    let reuseport_area: u64 =
        match unsafe { bpf_probe_read_kernel((sock + 16) as *const u64) } {
            Ok(v) => v,
            Err(_) => return,
        };
    let reuseport = ((reuseport_area >> 28) & 1) as u8;

    let opts = freebind
        | (transparent << 1)
        | (bind_addr_no_port << 2)
        | (reuseaddress << 3)
        | (reuseport << 4);

    // SAFETY: bpf_ktime_get_ns is unsafe in aya-ebpf
    let ts_us = unsafe { bpf_ktime_get_ns() } / 1000;

    // SAFETY: reading bound_dev_if from sock common
    let bound_dev_if: u32 = match unsafe { bpf_probe_read_kernel((sock + 20) as *const u32) } {
        Ok(v) => v,
        Err(_) => return,
    };

    // SAFETY: reading sk_protocol from sock struct
    let proto: u16 = match unsafe { bpf_probe_read_kernel((sock + 516) as *const u16) } {
        Ok(v) => v,
        Err(_) => return,
    };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return,
    };

    let addr_offset: u64 = if ver == 4 { 776 } else { 72 };
    // SAFETY: reading address from inet_sock or sock v6 struct
    let addr: [u8; 16] =
        match unsafe { bpf_probe_read_kernel((sock + addr_offset) as *const [u8; 16]) } {
            Ok(v) => v,
            Err(_) => return,
        };

    // SAFETY: zeroing BindEvent struct including padding bytes
    let mut event: BindEvent = unsafe { core::mem::zeroed() };
    event.addr = addr;
    event.ts_us = ts_us;
    event.pid = pid;
    event.bound_dev_if = bound_dev_if;
    event.ret = ret;
    event.port = sport;
    event.proto = proto;
    event.opts = opts;
    event.ver = ver;
    event.task = comm;

    EVENTS.output(ctx, &event, 0);
}

#[kprobe]
pub fn ipv4_bind_entry(ctx: ProbeContext) -> u32 {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return 0,
        }
    }
    match do_probe_entry(&ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn ipv4_bind_exit(ctx: RetProbeContext) -> u32 {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return 0,
        }
    }
    match do_probe_exit(&ctx, 4) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn ipv6_bind_entry(ctx: ProbeContext) -> u32 {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return 0,
        }
    }
    match do_probe_entry(&ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn ipv6_bind_exit(ctx: RetProbeContext) -> u32 {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return 0,
        }
    }
    match do_probe_exit(&ctx, 6) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
