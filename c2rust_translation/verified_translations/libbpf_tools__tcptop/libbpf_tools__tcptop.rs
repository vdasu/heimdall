#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::cty::*;
use aya_ebpf::Global;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const TASK_COMM_LEN: usize = 16;

#[no_mangle]
static filter_cg: Global<u8> = Global::new(0);

#[no_mangle]
static target_pid: Global<i32> = Global::new(-1);

#[no_mangle]
static target_family: Global<i32> = Global::new(-1);

#[repr(C, align(16))]
#[derive(Copy, Clone)]
struct Addr128 {
    bytes: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IpKey {
    saddr: Addr128,
    daddr: Addr128,
    pid: u32,
    name: [u8; TASK_COMM_LEN],
    lport: u16,
    dport: u16,
    family: u16,
    _padding: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Traffic {
    sent: u64,
    received: u64,
}

#[map(name = "cgroup_map")]
static CGROUP_MAP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map(name = "ip_map")]
static IP_MAP: HashMap<IpKey, Traffic> = HashMap::with_max_entries(10240, 0);

#[inline(always)]
fn probe_ip(receiving: bool, sk: *const u8, size: u64) -> Result<i32, i64> {
    if filter_cg.load() == 1 {
        match CGROUP_MAP.current_task_under_cgroup(0) {
            Ok(true) => {}
            _ => return Ok(0),
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let tgt_pid = target_pid.load();
    if tgt_pid != -1 && tgt_pid != pid as i32 {
        return Ok(0);
    }

    // SAFETY: reading skc_family from sock pointer at offset 16
    let family: u16 = unsafe { bpf_probe_read_kernel(sk.add(16) as *const u16) }?;

    let tgt_family = target_family.load();
    if tgt_family != -1 && tgt_family != family as i32 {
        return Ok(0);
    }

    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let mut ip_key = IpKey {
        saddr: Addr128 { bytes: [0u8; 16] },
        daddr: Addr128 { bytes: [0u8; 16] },
        pid: 0,
        name: [0u8; TASK_COMM_LEN],
        lport: 0,
        dport: 0,
        family: 0,
        _padding: [0u8; 6],
    };

    ip_key.pid = pid;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    ip_key.name = comm;

    // SAFETY: reading skc_num (local port) from sock pointer at offset 14
    let lport: u16 = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16) }?;
    ip_key.lport = lport;

    // SAFETY: reading skc_dport from sock pointer at offset 12
    let dport_be: u16 = unsafe { bpf_probe_read_kernel(sk.add(12) as *const u16) }?;
    ip_key.dport = u16::from_be(dport_be);

    ip_key.family = family;

    if family == AF_INET {
        // SAFETY: reading skc_rcv_saddr (IPv4 src) at offset 4
        let saddr: u32 = unsafe { bpf_probe_read_kernel(sk.add(4) as *const u32) }?;
        ip_key.saddr.bytes[..4].copy_from_slice(&saddr.to_ne_bytes());

        // SAFETY: reading skc_daddr (IPv4 dst) at offset 0
        let daddr: u32 = unsafe { bpf_probe_read_kernel(sk as *const u32) }?;
        ip_key.daddr.bytes[..4].copy_from_slice(&daddr.to_ne_bytes());
    } else {
        // SAFETY: reading skc_v6_rcv_saddr at offset 72
        let saddr: [u8; 16] = unsafe { bpf_probe_read_kernel(sk.add(72) as *const [u8; 16]) }?;
        ip_key.saddr.bytes = saddr;

        // SAFETY: reading skc_v6_daddr at offset 56
        let daddr: [u8; 16] = unsafe { bpf_probe_read_kernel(sk.add(56) as *const [u8; 16]) }?;
        ip_key.daddr.bytes = daddr;
    }

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let trafficp = unsafe { IP_MAP.get(&ip_key) };

    if let Some(traffic) = trafficp {
        let mut updated = *traffic;
        if receiving {
            updated.received += size;
        } else {
            updated.sent += size;
        }
        let _ = IP_MAP.insert(&ip_key, &updated, 2);
    } else {
        let zero = if receiving {
            Traffic { sent: 0, received: size }
        } else {
            Traffic { sent: size, received: 0 }
        };
        let _ = IP_MAP.insert(&ip_key, &zero, 1);
    }

    Ok(0)
}

#[kprobe(function = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<i32, i64> {
    let sk = ctx.arg::<u64>(0).ok_or(1i64)? as *const u8;
    let size: u64 = ctx.arg(2).ok_or(1i64)?;
    probe_ip(false, sk, size)
}

#[kprobe(function = "tcp_cleanup_rbuf")]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    match try_tcp_cleanup_rbuf(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_tcp_cleanup_rbuf(ctx: ProbeContext) -> Result<i32, i64> {
    let sk = ctx.arg::<u64>(0).ok_or(1i64)? as *const u8;
    let copied = ctx.arg::<u64>(1).ok_or(1i64)? as i32;

    if copied <= 0 {
        return Ok(0);
    }

    probe_ip(true, sk, copied as u64)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
