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

const MAX_ENTRIES: u32 = 102400;
const TASK_COMM_LEN: usize = 16;
const BPF_F_FAST_STACK_CMP: u64 = 1 << 9;

#[repr(C)]
#[derive(Copy, Clone)]
struct LockStat {
    acq_count: u64,
    acq_total_time: u64,
    acq_max_time: u64,
    acq_max_id: u64,
    acq_max_lock_ptr: u64,
    acq_max_nltype: u64,
    acq_max_ioctl: u64,
    acq_max_comm: [u8; TASK_COMM_LEN],
    hld_count: u64,
    hld_total_time: u64,
    hld_max_time: u64,
    hld_max_id: u64,
    hld_max_lock_ptr: u64,
    hld_max_nltype: u64,
    hld_max_ioctl: u64,
    hld_max_comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TaskLock {
    task_id: u64,
    lock_ptr: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TaskState {
    nlmsg_type: u16,
    ioctl: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct LockholderInfo {
    stack_id: i32,
    nlmsg_type: u16,
    ioctl: u16,
    task_id: u64,
    try_at: u64,
    acq_at: u64,
    rel_at: u64,
    lock_ptr: u64,
}

#[no_mangle]
static targ_tgid: Global<i32> = Global::new(0);
#[no_mangle]
static targ_pid: Global<i32> = Global::new(0);
#[no_mangle]
static targ_lock: Global<u64> = Global::new(0);
#[no_mangle]
static per_thread: Global<i32> = Global::new(0);

#[map(name = "stack_map")]
static STACK_MAP: StackTrace = StackTrace::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "lockholder_map")]
static LOCKHOLDER_MAP: HashMap<TaskLock, LockholderInfo> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "stat_map")]
static STAT_MAP: HashMap<i32, LockStat> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "locks")]
static LOCKS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "task_states")]
static TASK_STATES: HashMap<u32, TaskState> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn tracing_task(task_id: u64) -> bool {
    let tgid = (task_id >> 32) as u32;
    let pid = task_id as u32;
    let t_tgid = targ_tgid.load();
    if t_tgid != 0 && t_tgid as u32 != tgid {
        return false;
    }
    let t_pid = targ_pid.load();
    if t_pid != 0 && t_pid as u32 != pid {
        return false;
    }
    true
}

#[inline(always)]
fn lock_contended<C: EbpfContext>(ctx: &C, lock: u64) {
    let t_lock = targ_lock.load();
    if t_lock != 0 && t_lock != lock {
        return;
    }
    let task_id = bpf_get_current_pid_tgid();
    if !tracing_task(task_id) {
        return;
    }
    // SAFETY: zero-initialized repr(C) struct with no invariants
    let mut li: LockholderInfo = unsafe { core::mem::zeroed() };
    li.task_id = task_id;
    li.lock_ptr = lock;
    // SAFETY: get_stackid is pub unsafe fn calling BPF helper
    let stack_id = match unsafe { STACK_MAP.get_stackid::<C>(ctx, BPF_F_FAST_STACK_CMP) } {
        Ok(id) => id as i32,
        Err(_) => return,
    };
    if stack_id < 0 {
        return;
    }
    li.stack_id = stack_id;
    // SAFETY: calling BPF ktime helper
    li.try_at = unsafe { bpf_ktime_get_ns() };
    let tl = TaskLock { task_id, lock_ptr: lock };
    LOCKHOLDER_MAP.insert(&tl, &li, 0).ok();
}

#[inline(always)]
fn lock_aborted(lock: u64) {
    let t_lock = targ_lock.load();
    if t_lock != 0 && t_lock != lock {
        return;
    }
    let task_id = bpf_get_current_pid_tgid();
    if !tracing_task(task_id) {
        return;
    }
    let tl = TaskLock { task_id, lock_ptr: lock };
    LOCKHOLDER_MAP.remove(&tl).ok();
}

#[inline(always)]
fn lock_acquired(lock: u64) {
    let t_lock = targ_lock.load();
    if t_lock != 0 && t_lock != lock {
        return;
    }
    let task_id = bpf_get_current_pid_tgid();
    if !tracing_task(task_id) {
        return;
    }
    let tl = TaskLock { task_id, lock_ptr: lock };
    // SAFETY: HashMap::get is pub unsafe fn
    let li_ref = match unsafe { LOCKHOLDER_MAP.get(&tl) } {
        Some(r) => r,
        None => return,
    };
    let mut li = *li_ref;
    // SAFETY: calling BPF ktime helper
    li.acq_at = unsafe { bpf_ktime_get_ns() };
    let tid = task_id as u32;
    // SAFETY: HashMap::get is pub unsafe fn
    if let Some(state) = unsafe { TASK_STATES.get(&tid) } {
        li.nlmsg_type = state.nlmsg_type;
        li.ioctl = state.ioctl;
    }
    LOCKHOLDER_MAP.insert(&tl, &li, 0).ok();
}

#[inline(never)]
fn account(li: &LockholderInfo) {
    let per_thread_val = per_thread.load();
    let key: i32 = if per_thread_val != 0 {
        li.task_id as i32
    } else {
        li.stack_id
    };

    // SAFETY: HashMap::get is pub unsafe fn
    let mut ls = match unsafe { STAT_MAP.get(&key) } {
        Some(r) => *r,
        None => {
            // SAFETY: zero-initialized repr(C) struct with no invariants
            let mut fresh: LockStat = unsafe { core::mem::zeroed() };
            if per_thread_val != 0 {
                fresh.acq_max_comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
            }
            fresh
        }
    };

    let delta = li.acq_at.wrapping_sub(li.try_at);
    ls.acq_count = ls.acq_count.wrapping_add(1);
    ls.acq_total_time = ls.acq_total_time.wrapping_add(delta);
    if delta > ls.acq_max_time {
        ls.acq_max_time = delta;
        ls.acq_max_id = li.task_id;
        ls.acq_max_lock_ptr = li.lock_ptr;
        ls.acq_max_nltype = li.nlmsg_type as u64;
        ls.acq_max_ioctl = li.ioctl as u64;
        if per_thread_val == 0 {
            ls.acq_max_comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        }
    }

    let delta_hld = li.rel_at.wrapping_sub(li.acq_at);
    ls.hld_count = ls.hld_count.wrapping_add(1);
    ls.hld_total_time = ls.hld_total_time.wrapping_add(delta_hld);
    if delta_hld > ls.hld_max_time {
        ls.hld_max_time = delta_hld;
        ls.hld_max_id = li.task_id;
        ls.hld_max_lock_ptr = li.lock_ptr;
        ls.hld_max_nltype = li.nlmsg_type as u64;
        ls.hld_max_ioctl = li.ioctl as u64;
        if per_thread_val == 0 {
            ls.hld_max_comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        }
    }

    STAT_MAP.insert(&key, &ls, 0).ok();
}

#[inline(never)]
fn lock_released(lock: u64) {
    let t_lock = targ_lock.load();
    if t_lock != 0 && t_lock != lock {
        return;
    }
    let task_id = bpf_get_current_pid_tgid();
    if !tracing_task(task_id) {
        return;
    }
    let tl = TaskLock { task_id, lock_ptr: lock };
    // SAFETY: HashMap::get is pub unsafe fn
    let li_ref = match unsafe { LOCKHOLDER_MAP.get(&tl) } {
        Some(r) => r,
        None => return,
    };
    let mut li = *li_ref;
    // SAFETY: calling BPF ktime helper
    li.rel_at = unsafe { bpf_ktime_get_ns() };
    account(&li);
    LOCKHOLDER_MAP.remove(&tl).ok();
}

#[inline(always)]
fn record_nltype(hdr: u64) {
    let tid = bpf_get_current_pid_tgid() as u32;
    let mut state = TaskState { nlmsg_type: 0, ioctl: 0 };
    let ptr = (hdr as *const u8).wrapping_add(4) as *const u16;
    // SAFETY: reading nlmsg_type from nlmsghdr at offset 4 via probe_read
    state.nlmsg_type = unsafe { bpf_probe_read_kernel(ptr) }.unwrap_or(0);
    TASK_STATES.insert(&tid, &state, 0).ok();
}

#[inline(always)]
fn record_ioctl(cmd: u32) {
    let tid = bpf_get_current_pid_tgid() as u32;
    let state = TaskState { nlmsg_type: 0, ioctl: cmd as u16 };
    TASK_STATES.insert(&tid, &state, 0).ok();
}

#[inline(always)]
fn release_task_state() {
    let tid = bpf_get_current_pid_tgid() as u32;
    TASK_STATES.remove(&tid).ok();
}

#[inline(always)]
fn netlink_dump_logic(sk: u64) {
    // container_of(sk, netlink_sock, sk): sk offset is 0
    let nlk = sk;
    let ptr = (nlk as *const u8).wrapping_add(856) as *const u64;
    // SAFETY: reading cb.nlh pointer from netlink_sock at offset 856
    let nlh: u64 = unsafe { bpf_probe_read_kernel(ptr) }.unwrap_or(0);
    record_nltype(nlh);
}

#[inline(always)]
fn kret_get_and_delete_lock() -> Option<u64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: HashMap::get is pub unsafe fn
    let lock_val = match unsafe { LOCKS.get(&tid) } {
        Some(v) => *v,
        None => return None,
    };
    LOCKS.remove(&tid).ok();
    Some(lock_val)
}

// ==================== fentry programs ====================

#[fentry(function = "rtnetlink_rcv_msg")]
pub fn rtnetlink_rcv_msg(ctx: FEntryContext) -> i32 {
    let nlh: u64 = ctx.arg(1);
    record_nltype(nlh);
    0
}

#[fentry(function = "netlink_dump")]
pub fn netlink_dump(ctx: FEntryContext) -> i32 {
    let sk: u64 = ctx.arg(0);
    netlink_dump_logic(sk);
    0
}

#[fentry(function = "sock_do_ioctl")]
pub fn sock_do_ioctl(ctx: FEntryContext) -> i32 {
    let cmd: u64 = ctx.arg(2);
    record_ioctl(cmd as u32);
    0
}

#[fentry(function = "mutex_lock")]
pub fn mutex_lock(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "mutex_lock_interruptible")]
pub fn mutex_lock_interruptible(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "mutex_lock_killable")]
pub fn mutex_lock_killable(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "mutex_unlock")]
pub fn mutex_unlock(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_released(lock);
    0
}

#[fentry(function = "down_read")]
pub fn down_read(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "down_read_interruptible")]
pub fn down_read_interruptible(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "down_read_killable")]
pub fn down_read_killable(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "up_read")]
pub fn up_read(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_released(lock);
    0
}

#[fentry(function = "down_write")]
pub fn down_write(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "down_write_killable")]
pub fn down_write_killable(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_contended(&ctx, lock);
    0
}

#[fentry(function = "up_write")]
pub fn up_write(ctx: FEntryContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_released(lock);
    0
}

// ==================== fexit programs ====================

#[fexit(function = "rtnetlink_rcv_msg")]
pub fn rtnetlink_rcv_msg_exit(_ctx: FExitContext) -> i32 {
    release_task_state();
    0
}

#[fexit(function = "netlink_dump")]
pub fn netlink_dump_exit(_ctx: FExitContext) -> i32 {
    release_task_state();
    0
}

#[fexit(function = "sock_do_ioctl")]
pub fn sock_do_ioctl_exit(_ctx: FExitContext) -> i32 {
    release_task_state();
    0
}

#[fexit(function = "mutex_lock")]
pub fn mutex_lock_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_acquired(lock);
    0
}

#[fexit(function = "mutex_trylock")]
pub fn mutex_trylock_exit(ctx: FExitContext) -> i32 {
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        let lock: u64 = ctx.arg(0);
        lock_contended(&ctx, lock);
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "mutex_lock_interruptible")]
pub fn mutex_lock_interruptible_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        lock_aborted(lock);
    } else {
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "mutex_lock_killable")]
pub fn mutex_lock_killable_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        lock_aborted(lock);
    } else {
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "down_read")]
pub fn down_read_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_acquired(lock);
    0
}

#[fexit(function = "down_read_trylock")]
pub fn down_read_trylock_exit(ctx: FExitContext) -> i32 {
    let ret: i64 = ctx.arg(1);
    if ret == 1 {
        let lock: u64 = ctx.arg(0);
        lock_contended(&ctx, lock);
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "down_read_interruptible")]
pub fn down_read_interruptible_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        lock_aborted(lock);
    } else {
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "down_read_killable")]
pub fn down_read_killable_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        lock_aborted(lock);
    } else {
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "down_write")]
pub fn down_write_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    lock_acquired(lock);
    0
}

#[fexit(function = "down_write_trylock")]
pub fn down_write_trylock_exit(ctx: FExitContext) -> i32 {
    let ret: i64 = ctx.arg(1);
    if ret == 1 {
        let lock: u64 = ctx.arg(0);
        lock_contended(&ctx, lock);
        lock_acquired(lock);
    }
    0
}

#[fexit(function = "down_write_killable")]
pub fn down_write_killable_exit(ctx: FExitContext) -> i32 {
    let lock: u64 = ctx.arg(0);
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        lock_aborted(lock);
    } else {
        lock_acquired(lock);
    }
    0
}

// ==================== kprobe programs ====================

#[kprobe(function = "mutex_lock")]
pub fn kprobe_mutex_lock(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "mutex_trylock")]
pub fn kprobe_mutex_trylock(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    0
}

#[kprobe(function = "mutex_lock_interruptible")]
pub fn kprobe_mutex_lock_interruptible(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "mutex_lock_killable")]
pub fn kprobe_mutex_lock_killable(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "mutex_unlock")]
pub fn kprobe_mutex_unlock(ctx: ProbeContext) -> u32 {
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    lock_released(lock);
    0
}

#[kprobe(function = "down_read")]
pub fn kprobe_down_read(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_read_trylock")]
pub fn kprobe_down_read_trylock(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    0
}

#[kprobe(function = "down_read_interruptible")]
pub fn kprobe_down_read_interruptible(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_read_killable")]
pub fn kprobe_down_read_killable(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "up_read")]
pub fn kprobe_up_read(ctx: ProbeContext) -> u32 {
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    lock_released(lock);
    0
}

#[kprobe(function = "down_write")]
pub fn kprobe_down_write(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_write_trylock")]
pub fn kprobe_down_write_trylock(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    0
}

#[kprobe(function = "down_write_killable")]
pub fn kprobe_down_write_killable(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "up_write")]
pub fn kprobe_up_write(ctx: ProbeContext) -> u32 {
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    lock_released(lock);
    0
}

#[kprobe(function = "mutex_lock_nested")]
pub fn kprobe_mutex_lock_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "mutex_lock_interruptible_nested")]
pub fn kprobe_mutex_lock_interruptible_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "mutex_lock_killable_nested")]
pub fn kprobe_mutex_lock_killable_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_read_nested")]
pub fn kprobe_down_read_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_read_killable_nested")]
pub fn kprobe_down_read_killable_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_write_nested")]
pub fn kprobe_down_write_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "down_write_killable_nested")]
pub fn kprobe_down_write_killable_nested(ctx: ProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    let lock: u64 = ctx.arg(0).unwrap_or(0);
    LOCKS.insert(&tid, &lock, 0).ok();
    lock_contended(&ctx, lock);
    0
}

#[kprobe(function = "rtnetlink_rcv_msg")]
pub fn kprobe_rtnetlink_rcv_msg(ctx: ProbeContext) -> u32 {
    let nlh: u64 = ctx.arg(1).unwrap_or(0);
    record_nltype(nlh);
    0
}

#[kprobe(function = "netlink_dump")]
pub fn kprobe_netlink_dump(ctx: ProbeContext) -> u32 {
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    netlink_dump_logic(sk);
    0
}

#[kprobe(function = "sock_do_ioctl")]
pub fn kprobe_sock_do_ioctl(ctx: ProbeContext) -> u32 {
    let ptr = (ctx.as_ptr() as *const u64).wrapping_add(2);
    // SAFETY: reading cmd from BPF_PROG-style kprobe context at offset 16
    let cmd = unsafe { *ptr } as u32;
    record_ioctl(cmd);
    0
}

// ==================== kretprobe programs ====================

#[kretprobe(function = "mutex_lock")]
pub fn kprobe_mutex_lock_exit(_ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    lock_acquired(lock_val);
    0
}

#[kretprobe(function = "mutex_trylock")]
pub fn kprobe_mutex_trylock_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_contended(&ctx, lock_val);
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "mutex_lock_interruptible")]
pub fn kprobe_mutex_lock_interruptible_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "mutex_lock_killable")]
pub fn kprobe_mutex_lock_killable_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_read")]
pub fn kprobe_down_read_exit(_ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    lock_acquired(lock_val);
    0
}

#[kretprobe(function = "down_read_trylock")]
pub fn kprobe_down_read_trylock_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret == 1 {
        lock_contended(&ctx, lock_val);
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_read_interruptible")]
pub fn kprobe_down_read_interruptible_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_read_killable")]
pub fn kprobe_down_read_killable_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_write")]
pub fn kprobe_down_write_exit(_ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    lock_acquired(lock_val);
    0
}

#[kretprobe(function = "down_write_trylock")]
pub fn kprobe_down_write_trylock_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret == 1 {
        lock_contended(&ctx, lock_val);
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_write_killable")]
pub fn kprobe_down_write_killable_exit(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "mutex_lock_nested")]
pub fn kprobe_mutex_lock_exit_nested(_ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    lock_acquired(lock_val);
    0
}

#[kretprobe(function = "mutex_lock_interruptible_nested")]
pub fn kprobe_mutex_lock_interruptible_exit_nested(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "mutex_lock_killable_nested")]
pub fn kprobe_mutex_lock_killable_exit_nested(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_read_nested")]
pub fn kprobe_down_read_exit_nested(_ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    lock_acquired(lock_val);
    0
}

#[kretprobe(function = "down_read_killable_nested")]
pub fn kprobe_down_read_killable_exit_nested(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "down_write_nested")]
pub fn kprobe_down_write_exit_nested(_ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    lock_acquired(lock_val);
    0
}

#[kretprobe(function = "down_write_killable_nested")]
pub fn kprobe_down_write_killable_exit_nested(ctx: RetProbeContext) -> u32 {
    let lock_val = match kret_get_and_delete_lock() {
        Some(v) => v,
        None => return 0,
    };
    let ret: i64 = ctx.ret::<i64>();
    if ret != 0 {
        lock_aborted(lock_val);
    } else {
        lock_acquired(lock_val);
    }
    0
}

#[kretprobe(function = "rtnetlink_rcv_msg")]
pub fn kprobe_rtnetlink_rcv_msg_exit(_ctx: RetProbeContext) -> u32 {
    release_task_state();
    0
}

#[kretprobe(function = "netlink_dump")]
pub fn kprobe_netlink_dump_exit(_ctx: RetProbeContext) -> u32 {
    release_task_state();
    0
}

#[kretprobe(function = "sock_do_ioctl")]
pub fn kprobe_sock_do_ioctl_exit(_ctx: RetProbeContext) -> u32 {
    release_task_state();
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
