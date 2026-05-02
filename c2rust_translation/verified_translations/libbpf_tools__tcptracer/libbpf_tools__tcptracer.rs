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
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 8192;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const TCP_EVENT_TYPE_CONNECT: u8 = 0;
const TCP_EVENT_TYPE_ACCEPT: u8 = 1;
const TCP_EVENT_TYPE_CLOSE: u8 = 2;

const TCP_ESTABLISHED: u32 = 1;
const TCP_CLOSE: u32 = 7;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_NEW_SYN_RECV: u8 = 12;

const SKC_DADDR_OFF: usize = 0;
const SKC_RCV_SADDR_OFF: usize = 4;
const SKC_DPORT_OFF: usize = 12;
const SKC_NUM_OFF: usize = 14;
const SKC_FAMILY_OFF: usize = 16;
const SKC_STATE_OFF: usize = 18;
const SKC_NET_OFF: usize = 48;
const SKC_V6_DADDR_OFF: usize = 56;
const SKC_V6_RCV_SADDR_OFF: usize = 72;
const INET_SPORT_OFF: usize = 782;
const NET_NS_INUM_OFF: usize = 144;

#[repr(C)]
#[derive(Copy, Clone)]
struct TupleKey {
    saddr_v6: u128,
    daddr_v6: u128,
    sport: u16,
    dport: u16,
    netns: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PidComm {
    pid: u64,
    comm: [u8; 16],
    uid: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    saddr_v6: u128,
    daddr_v6: u128,
    task: [u8; 16],
    ts_us: u64,
    af: u32,
    pid: u32,
    uid: u32,
    netns: u32,
    dport: u16,
    sport: u16,
    type_: u8,
    _pad: [u8; 3],
}

#[no_mangle]
static filter_uid: Global<u32> = Global::new(0xFFFFFFFF);

#[no_mangle]
static filter_pid: Global<u32> = Global::new(0);

#[map(name = "tuplepid")]
static TUPLEPID: HashMap<TupleKey, PidComm> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "sockets")]
static SOCKETS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn filter_event(sk: u64, uid: u32, pid: u32) -> bool {
    // SAFETY: reading skc_family from kernel sock struct
    let family: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_FAMILY_OFF) as *const u16)
    }
    .unwrap_or(0);

    if family != AF_INET && family != AF_INET6 {
        return true;
    }

    let fpid = filter_pid.load();
    if fpid != 0 && pid != fpid {
        return true;
    }

    let fuid = filter_uid.load();
    if fuid != 0xFFFFFFFF && uid != fuid {
        return true;
    }

    false
}

#[inline(always)]
fn fill_tuple(tuple: &mut TupleKey, sk: u64, family: u16) -> bool {
    // SAFETY: reading skc_net pointer from sock struct
    let net_ptr: u64 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_NET_OFF) as *const u64)
    }
    .unwrap_or(0);

    // SAFETY: reading ns.inum from net struct
    tuple.netns = unsafe {
        bpf_probe_read_kernel((net_ptr as *const u8).add(NET_NS_INUM_OFF) as *const u32)
    }
    .unwrap_or(0);

    match family {
        AF_INET => {
            // SAFETY: reading skc_rcv_saddr from sock struct
            let saddr: u32 = unsafe {
                bpf_probe_read_kernel(
                    (sk as *const u8).add(SKC_RCV_SADDR_OFF) as *const u32,
                )
            }
            .unwrap_or(0);
            if saddr == 0 {
                return false;
            }
            tuple.saddr_v6 = saddr as u128;

            // SAFETY: reading skc_daddr from sock struct
            let daddr: u32 = unsafe {
                bpf_probe_read_kernel(
                    (sk as *const u8).add(SKC_DADDR_OFF) as *const u32,
                )
            }
            .unwrap_or(0);
            if daddr == 0 {
                return false;
            }
            tuple.daddr_v6 = daddr as u128;
        }
        AF_INET6 => {
            // SAFETY: reading skc_v6_rcv_saddr from sock struct
            let saddr: u128 = unsafe {
                bpf_probe_read_kernel(
                    (sk as *const u8).add(SKC_V6_RCV_SADDR_OFF) as *const u128,
                )
            }
            .unwrap_or(0);
            if saddr == 0 {
                return false;
            }
            tuple.saddr_v6 = saddr;

            // SAFETY: reading skc_v6_daddr from sock struct
            let daddr: u128 = unsafe {
                bpf_probe_read_kernel(
                    (sk as *const u8).add(SKC_V6_DADDR_OFF) as *const u128,
                )
            }
            .unwrap_or(0);
            if daddr == 0 {
                return false;
            }
            tuple.daddr_v6 = daddr;
        }
        _ => return false,
    }

    // SAFETY: reading skc_dport from sock struct
    tuple.dport = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_DPORT_OFF) as *const u16)
    }
    .unwrap_or(0);
    if tuple.dport == 0 {
        return false;
    }

    // SAFETY: reading inet_sport from sock struct
    tuple.sport = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(INET_SPORT_OFF) as *const u16)
    }
    .unwrap_or(0);
    if tuple.sport == 0 {
        return false;
    }

    true
}

#[inline(always)]
fn fill_event(tuple: &TupleKey, event: &mut Event, pid: u32, uid: u32, family: u16, type_: u8) {
    // SAFETY: bpf_ktime_get_ns is an unsafe BPF helper
    let ts = unsafe { bpf_ktime_get_ns() };
    event.ts_us = ts / 1000;
    event.type_ = type_;
    event.pid = pid;
    event.uid = uid;
    event.af = family as u32;
    event.netns = tuple.netns;
    if family == AF_INET {
        event.saddr_v6 = tuple.saddr_v6;
        event.daddr_v6 = tuple.daddr_v6;
    } else {
        event.saddr_v6 = tuple.saddr_v6;
        event.daddr_v6 = tuple.daddr_v6;
    }
    event.sport = tuple.sport;
    event.dport = tuple.dport;
}

#[inline(always)]
fn enter_tcp_connect(sk: u64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    if filter_event(sk, uid, pid) {
        return 0;
    }

    let _ = SOCKETS.insert(&tid, &sk, 0);
    0
}

#[inline(always)]
fn do_exit_tcp_connect(ret: u32, family: u16) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let sk = match unsafe { SOCKETS.get(&tid) } {
        Some(v) => *v,
        None => return 0,
    };

    if ret == 0 {
        let mut tuple = TupleKey {
            saddr_v6: 0,
            daddr_v6: 0,
            sport: 0,
            dport: 0,
            netns: 0,
        };

        if fill_tuple(&mut tuple, sk, family) {
            let mut pid_comm = PidComm {
                pid: pid as u64,
                comm: [0u8; 16],
                uid,
                _pad: 0,
            };
            pid_comm.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
            let _ = TUPLEPID.insert(&tuple, &pid_comm, 0);
        }
    }

    let _ = SOCKETS.remove(&tid);
    0
}

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    enter_tcp_connect(sk) as u32
}

#[kretprobe]
pub fn tcp_v4_connect_ret(ctx: RetProbeContext) -> u32 {
    let ret: i64 = ctx.ret::<i64>();
    do_exit_tcp_connect(ret as u32, AF_INET) as u32
}

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    enter_tcp_connect(sk) as u32
}

#[kretprobe]
pub fn tcp_v6_connect_ret(ctx: RetProbeContext) -> u32 {
    let ret: i64 = ctx.ret::<i64>();
    do_exit_tcp_connect(ret as u32, AF_INET6) as u32
}

#[kprobe]
pub fn entry_trace_close(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    if filter_event(sk, uid, pid) {
        return 0;
    }

    // SAFETY: reading skc_state from sock struct
    let oldstate: u8 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_STATE_OFF) as *const u8)
    }
    .unwrap_or(0);

    if oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV {
        return 0;
    }

    // SAFETY: reading skc_family from sock struct
    let family: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_FAMILY_OFF) as *const u16)
    }
    .unwrap_or(0);

    let mut tuple = TupleKey {
        saddr_v6: 0,
        daddr_v6: 0,
        sport: 0,
        dport: 0,
        netns: 0,
    };

    if !fill_tuple(&mut tuple, sk, family) {
        return 0;
    }

    let mut event = Event {
        saddr_v6: 0,
        daddr_v6: 0,
        task: [0u8; 16],
        ts_us: 0,
        af: 0,
        pid: 0,
        uid: 0,
        netns: 0,
        dport: 0,
        sport: 0,
        type_: 0,
        _pad: [0u8; 3],
    };

    fill_event(&tuple, &mut event, pid, uid, family, TCP_EVENT_TYPE_CLOSE);
    event.task = bpf_get_current_comm().unwrap_or([0u8; 16]);

    EVENTS.output(&ctx, &event, 0);

    0
}

#[kprobe]
pub fn enter_tcp_set_state(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    let state_raw: u64 = ctx.arg(1).unwrap_or(0);
    let state = state_raw as u32;

    let mut tuple = TupleKey {
        saddr_v6: 0,
        daddr_v6: 0,
        sport: 0,
        dport: 0,
        netns: 0,
    };

    if state != TCP_ESTABLISHED && state != TCP_CLOSE {
        let _ = TUPLEPID.remove(&tuple);
        return 0;
    }

    // SAFETY: reading skc_family from sock struct
    let family: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_FAMILY_OFF) as *const u16)
    }
    .unwrap_or(0);

    if !fill_tuple(&mut tuple, sk, family) {
        let _ = TUPLEPID.remove(&tuple);
        return 0;
    }

    if state == TCP_CLOSE {
        let _ = TUPLEPID.remove(&tuple);
        return 0;
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let p = match unsafe { TUPLEPID.get(&tuple) } {
        Some(v) => *v,
        None => return 0,
    };

    let mut event = Event {
        saddr_v6: 0,
        daddr_v6: 0,
        task: [0u8; 16],
        ts_us: 0,
        af: 0,
        pid: 0,
        uid: 0,
        netns: 0,
        dport: 0,
        sport: 0,
        type_: 0,
        _pad: [0u8; 3],
    };

    fill_event(&tuple, &mut event, p.pid as u32, p.uid, family, TCP_EVENT_TYPE_CONNECT);
    event.task = p.comm;

    EVENTS.output(&ctx, &event, 0);

    let _ = TUPLEPID.remove(&tuple);
    0
}

#[kretprobe]
pub fn exit_inet_csk_accept(ctx: RetProbeContext) -> u32 {
    let sk: u64 = ctx.ret::<u64>();
    if sk == 0 {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    if filter_event(sk, uid, pid) {
        return 0;
    }

    // SAFETY: reading skc_family from sock struct
    let family: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_FAMILY_OFF) as *const u16)
    }
    .unwrap_or(0);

    // SAFETY: reading skc_num from sock struct
    let sport_host: u16 = unsafe {
        bpf_probe_read_kernel((sk as *const u8).add(SKC_NUM_OFF) as *const u16)
    }
    .unwrap_or(0);

    let mut t = TupleKey {
        saddr_v6: 0,
        daddr_v6: 0,
        sport: 0,
        dport: 0,
        netns: 0,
    };
    fill_tuple(&mut t, sk, family);
    t.sport = sport_host.to_be();

    if t.saddr_v6 == 0 || t.daddr_v6 == 0 || t.dport == 0 || t.sport == 0 {
        return 0;
    }

    let mut event = Event {
        saddr_v6: 0,
        daddr_v6: 0,
        task: [0u8; 16],
        ts_us: 0,
        af: 0,
        pid: 0,
        uid: 0,
        netns: 0,
        dport: 0,
        sport: 0,
        type_: 0,
        _pad: [0u8; 3],
    };

    fill_event(&t, &mut event, pid, uid, family, TCP_EVENT_TYPE_ACCEPT);
    event.task = bpf_get_current_comm().unwrap_or([0u8; 16]);

    EVENTS.output(&ctx, &event, 0);

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
