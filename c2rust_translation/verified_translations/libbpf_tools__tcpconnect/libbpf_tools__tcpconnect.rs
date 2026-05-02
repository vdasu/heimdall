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
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_ENTRIES: u32 = 8192;
const MAX_PORTS: usize = 64;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv4FlowKey {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv6FlowKey {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    saddr: [u8; 16],
    daddr: [u8; 16],
    task: [u8; 16],
    ts_us: u64,
    af: u32,
    pid: u32,
    uid: u32,
    sport: u16,
    dport: u16,
}

#[map(name = "sockets")]
static SOCKETS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "ipv4_count")]
static IPV4_COUNT: HashMap<Ipv4FlowKey, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "ipv6_count")]
static IPV6_COUNT: HashMap<Ipv6FlowKey, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[no_mangle]
static filter_ports: Global<[c_int; MAX_PORTS]> = Global::new([0; MAX_PORTS]);

#[no_mangle]
static filter_ports_len: Global<c_int> = Global::new(0);

#[no_mangle]
static filter_uid: Global<u32> = Global::new(0xFFFFFFFF);

#[no_mangle]
static filter_pid: Global<i32> = Global::new(0);

#[no_mangle]
static do_count: Global<bool> = Global::new(false);

#[no_mangle]
static source_port: Global<bool> = Global::new(false);

#[no_mangle]
static mut COUNT_V4_ZERO: u64 = 0;

#[inline(always)]
fn filter_port(port: u16) -> bool {
    let len = filter_ports_len.load();
    if len == 0 {
        return false;
    }
    let bound = if len < MAX_PORTS as c_int { len as usize } else { MAX_PORTS };
    let base = &filter_ports as *const Global<[c_int; MAX_PORTS]> as *const c_int;
    let mut i = 0;
    while i < MAX_PORTS {
        if i >= bound {
            break;
        }
        // SAFETY: reading element i from .rodata filter_ports array within MAX_PORTS bound
        let p = unsafe { core::ptr::read_volatile(base.add(i)) };
        if port as c_int == p {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn enter_tcp_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let fpid = filter_pid.load();
    if fpid != 0 && pid != fpid as u32 {
        return Ok(0);
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let fuid = filter_uid.load();
    if fuid != 0xFFFFFFFF && uid != fuid {
        return Ok(0);
    }

    let sk: u64 = ctx.arg(0).ok_or(1i64)?;
    let _ = SOCKETS.insert(&tid, &sk, 0);
    Ok(0)
}

#[inline(always)]
fn count_v4(sk: u64, sport: u16, dport: u16) -> Result<(), i64> {
    let mut key = Ipv4FlowKey { saddr: 0, daddr: 0, sport: 0, dport: 0 };
    // SAFETY: reading skc_rcv_saddr at offset 4
    key.saddr = unsafe { bpf_probe_read_kernel((sk as *const u8).add(4) as *const u32) }?;
    // SAFETY: reading skc_daddr at offset 0
    key.daddr = unsafe { bpf_probe_read_kernel(sk as *const u32) }?;
    key.sport = sport;
    key.dport = dport;

    if let Some(ptr) = IPV4_COUNT.get_ptr_mut(&key) {
        // SAFETY: creating atomic from valid map pointer
        let counter = unsafe { AtomicU64::from_ptr(ptr) };
        counter.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    // SAFETY: mutable .bss zero-template for map init (matches C static __u64 zero)
    let zero: u64 = unsafe { *core::ptr::addr_of_mut!(COUNT_V4_ZERO) };
    match IPV4_COUNT.insert(&key, &zero, 1) {
        Ok(()) => {}
        Err(e) => {
            if e != -17 {
                return Ok(());
            }
        }
    }

    if let Some(ptr) = IPV4_COUNT.get_ptr_mut(&key) {
        // SAFETY: creating atomic from valid map pointer
        let counter = unsafe { AtomicU64::from_ptr(ptr) };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    Ok(())
}

#[inline(always)]
fn count_v6(sk: u64, sport: u16, dport: u16) -> Result<(), i64> {
    let mut key = Ipv6FlowKey { saddr: [0; 16], daddr: [0; 16], sport: 0, dport: 0 };
    // SAFETY: reading skc_v6_rcv_saddr at offset 72
    key.saddr = unsafe { bpf_probe_read_kernel((sk as *const u8).add(72) as *const [u8; 16]) }?;
    // SAFETY: reading skc_v6_daddr at offset 56
    key.daddr = unsafe { bpf_probe_read_kernel((sk as *const u8).add(56) as *const [u8; 16]) }?;
    key.sport = sport;
    key.dport = dport;

    if let Some(ptr) = IPV6_COUNT.get_ptr_mut(&key) {
        // SAFETY: creating atomic from valid map pointer
        let counter = unsafe { AtomicU64::from_ptr(ptr) };
        counter.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    let zero: u64 = 0;
    match IPV6_COUNT.insert(&key, &zero, 1) {
        Ok(()) => {}
        Err(e) => {
            if e != -17 {
                return Ok(());
            }
        }
    }

    if let Some(ptr) = IPV6_COUNT.get_ptr_mut(&key) {
        // SAFETY: creating atomic from valid map pointer
        let counter = unsafe { AtomicU64::from_ptr(ptr) };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    Ok(())
}

#[inline(always)]
fn trace_v4(ctx: &RetProbeContext, pid: u32, sk: u64, sport: u16, dport: u16) -> Result<(), i64> {
    let mut event = Event {
        saddr: [0u8; 16],
        daddr: [0u8; 16],
        task: [0u8; 16],
        ts_us: 0,
        af: AF_INET,
        pid,
        uid: 0,
        sport,
        dport,
    };

    event.uid = bpf_get_current_uid_gid() as u32;
    // SAFETY: calling bpf_ktime_get_ns
    event.ts_us = unsafe { bpf_ktime_get_ns() } / 1000;

    // SAFETY: reading skc_rcv_saddr at offset 4
    let saddr_v4: u32 = unsafe { bpf_probe_read_kernel((sk as *const u8).add(4) as *const u32) }?;
    let bytes = saddr_v4.to_ne_bytes();
    event.saddr[0] = bytes[0];
    event.saddr[1] = bytes[1];
    event.saddr[2] = bytes[2];
    event.saddr[3] = bytes[3];

    // SAFETY: reading skc_daddr at offset 0
    let daddr_v4: u32 = unsafe { bpf_probe_read_kernel(sk as *const u32) }?;
    let bytes = daddr_v4.to_ne_bytes();
    event.daddr[0] = bytes[0];
    event.daddr[1] = bytes[1];
    event.daddr[2] = bytes[2];
    event.daddr[3] = bytes[3];

    event.task = bpf_get_current_comm()?;

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

#[inline(always)]
fn trace_v6(ctx: &RetProbeContext, pid: u32, sk: u64, sport: u16, dport: u16) -> Result<(), i64> {
    let mut event = Event {
        saddr: [0u8; 16],
        daddr: [0u8; 16],
        task: [0u8; 16],
        ts_us: 0,
        af: AF_INET6,
        pid,
        uid: 0,
        sport,
        dport,
    };

    event.uid = bpf_get_current_uid_gid() as u32;
    // SAFETY: calling bpf_ktime_get_ns
    event.ts_us = unsafe { bpf_ktime_get_ns() } / 1000;

    // SAFETY: reading skc_v6_rcv_saddr at offset 72
    event.saddr = unsafe { bpf_probe_read_kernel((sk as *const u8).add(72) as *const [u8; 16]) }?;

    // SAFETY: reading skc_v6_daddr at offset 56
    event.daddr = unsafe { bpf_probe_read_kernel((sk as *const u8).add(56) as *const [u8; 16]) }?;

    event.task = bpf_get_current_comm()?;

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

#[inline(always)]
fn do_exit_work(ctx: &RetProbeContext, pid: u32, sk: u64, ip_ver: u32) -> Result<(), i64> {
    let mut sport: u16 = 0;
    if source_port.load() {
        // SAFETY: reading skc_num at offset 14
        sport = unsafe { bpf_probe_read_kernel((sk as *const u8).add(14) as *const u16) }?;
    }

    // SAFETY: reading skc_dport at offset 12
    let dport: u16 = unsafe { bpf_probe_read_kernel((sk as *const u8).add(12) as *const u16) }?;

    if filter_port(dport) {
        return Ok(());
    }

    if do_count.load() {
        if ip_ver == 4 {
            count_v4(sk, sport, dport)?;
        } else {
            count_v6(sk, sport, dport)?;
        }
    } else {
        if ip_ver == 4 {
            trace_v4(ctx, pid, sk, sport, dport)?;
        } else {
            trace_v6(ctx, pid, sk, sport, dport)?;
        }
    }

    Ok(())
}

#[inline(always)]
fn exit_tcp_connect(ctx: &RetProbeContext, ret_raw: u64, ip_ver: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // SAFETY: HashMap::get is pub unsafe fn
    let sk_val = match unsafe { SOCKETS.get(&tid) } {
        Some(v) => *v,
        None => return 0,
    };

    if ret_raw as u32 == 0 {
        let _ = do_exit_work(ctx, pid, sk_val, ip_ver);
    }

    let _ = SOCKETS.remove(&tid);
    0
}

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match enter_tcp_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn tcp_v4_connect_ret(ctx: RetProbeContext) -> u32 {
    let ret_raw: u64 = ctx.ret();
    exit_tcp_connect(&ctx, ret_raw, 4)
}

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    match enter_tcp_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn tcp_v6_connect_ret(ctx: RetProbeContext) -> u32 {
    let ret_raw: u64 = ctx.ret();
    exit_tcp_connect(&ctx, ret_raw, 6)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
