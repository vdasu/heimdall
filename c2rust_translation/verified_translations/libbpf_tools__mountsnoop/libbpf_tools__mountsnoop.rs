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
use aya_ebpf::cty::*;
use aya_ebpf::EbpfContext;

const MAX_ENTRIES: u32 = 10240;
const FS_NAME_LEN: usize = 8;
const DATA_LEN: usize = 512;
const PATH_MAX_SIZE: usize = 4096;
const RINGBUF_SIZE: u32 = 1024 * 256;
const EVENT_SIZE: usize = 8768;

const MOUNT_OP: u32 = 1;
const UMOUNT_OP: u32 = 2;
const FSOPEN_OP: u32 = 3;
const FSCONFIG_OP: u32 = 4;
const FSMOUNT_OP: u32 = 5;
const MOVE_MOUNT_OP: u32 = 6;

const TASK_NSPROXY_OFF: usize = 3120;
const NSPROXY_MNT_NS_OFF: usize = 24;
const MNT_NS_INUM_OFF: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
struct MountArgs {
    flags: u64,
    src: u64,
    dest: u64,
    fs: u64,
    data: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UmountArgs {
    flags: u64,
    dest: u64,
    _pad: [u8; 24],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FsopenArgs {
    fs: u64,
    flags: u32,
    _pad: [u8; 28],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FsconfigArgs {
    fd: i32,
    cmd: u32,
    key: u64,
    value: u64,
    aux: i32,
    _pad: [u8; 12],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FsmountArgs {
    fs_fd: i32,
    flags: u32,
    attr_flags: u32,
    _pad: [u8; 28],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MoveMountArgs {
    from_dfd: i32,
    _pad1: u32,
    from_pathname: u64,
    to_dfd: i32,
    _pad2: u32,
    to_pathname: u64,
    flags: u32,
    _pad3: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
union SysArg {
    mount: MountArgs,
    umount: UmountArgs,
    fsopen: FsopenArgs,
    fsconfig: FsconfigArgs,
    fsmount: FsmountArgs,
    move_mount: MoveMountArgs,
    _bytes: [u8; 40],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Arg {
    ts: u64,
    op: u32,
    _pad: u32,
    sys: SysArg,
}

#[repr(C)]
struct Event {
    _bytes: [u8; EVENT_SIZE],
}

#[map(name = "heap")]
static HEAP: PerCpuArray<[u8; 10240]> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE, 0);

#[map(name = "args")]
static ARGS: HashMap<u32, Arg> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
static target_pid: aya_ebpf::Global<u32> = aya_ebpf::Global::new(0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[inline(always)]
fn do_probe_entry(sys_arg: SysArg, op: u32) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let tpid = target_pid.load();
    if tpid != 0 && tpid != pid {
        return Ok(0);
    }

    // SAFETY: bpf_ktime_get_ns is an unsafe binding
    let ts = unsafe { bpf_ktime_get_ns() };

    let arg = Arg {
        ts,
        op,
        _pad: 0,
        sys: sys_arg,
    };

    ARGS.insert(&tid, &arg, 0).ok();
    Ok(0)
}

#[inline(always)]
fn do_probe_exit(_ctx_addr: usize, ret: i32) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // SAFETY: HashMap::get is pub unsafe fn
    let argp = match unsafe { ARGS.get(&tid) } {
        Some(a) => a,
        None => return Ok(0),
    };
    let arg = *argp;

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        // SAFETY: zero-initializing reserved ringbuf memory to prevent stale data leaks
        unsafe {
            core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, 0u8, core::mem::size_of::<Event>());
        }
        let evt = entry.as_mut_ptr() as usize;

        // SAFETY: bpf_get_current_task is unsafe
        let task = unsafe { bpf_get_current_task() } as usize;

        // SAFETY: bpf_ktime_get_ns is unsafe
        let ktime = unsafe { bpf_ktime_get_ns() };

        let delta = ktime - arg.ts;

        // SAFETY: writing delta to ringbuf entry
        unsafe { *((evt) as *mut u64) = delta };
        // SAFETY: writing op to ringbuf entry
        unsafe { *((evt + 24) as *mut u32) = arg.op };
        // SAFETY: writing pid to ringbuf entry
        unsafe { *((evt + 8) as *mut u32) = pid };
        // SAFETY: writing tid to ringbuf entry
        unsafe { *((evt + 12) as *mut u32) = tid };

        // BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)
        // SAFETY: reading nsproxy ptr from task struct
        let nsproxy: u64 = match unsafe {
            bpf_probe_read_kernel((task + TASK_NSPROXY_OFF) as *const u64)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                ARGS.remove(&tid).ok();
                return Ok(0);
            }
        };

        // SAFETY: reading mnt_ns ptr from nsproxy
        let mnt_ns: u64 = match unsafe {
            bpf_probe_read_kernel((nsproxy as usize + NSPROXY_MNT_NS_OFF) as *const u64)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                ARGS.remove(&tid).ok();
                return Ok(0);
            }
        };

        // SAFETY: reading ns.inum from mnt_namespace
        let inum: u32 = match unsafe {
            bpf_probe_read_kernel((mnt_ns as usize + MNT_NS_INUM_OFF) as *const u32)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                ARGS.remove(&tid).ok();
                return Ok(0);
            }
        };

        // SAFETY: writing ret to ringbuf entry
        unsafe { *((evt + 20) as *mut i32) = ret };
        // SAFETY: writing mnt_ns to ringbuf entry
        unsafe { *((evt + 16) as *mut u32) = inum };

        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => {
                entry.discard(0);
                ARGS.remove(&tid).ok();
                return Ok(0);
            }
        };
        // SAFETY: writing comm to ringbuf entry
        unsafe { *((evt + 28) as *mut [u8; 16]) = comm };

        match arg.op {
            MOUNT_OP => {
                // SAFETY: reading mount variant from arg union
                let m = unsafe { arg.sys.mount };
                // SAFETY: writing mount.flags to ringbuf
                unsafe { *((evt + 48) as *mut u64) = m.flags };

                // SAFETY: creating dst slice for src
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 64) as *mut u8, PATH_MAX_SIZE)
                };
                // SAFETY: reading user string for mount.src
                match unsafe { bpf_probe_read_user_str_bytes(m.src as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };

                // SAFETY: creating dst slice for dest
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 4160) as *mut u8, PATH_MAX_SIZE)
                };
                // SAFETY: reading user string for mount.dest
                match unsafe { bpf_probe_read_user_str_bytes(m.dest as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };

                // SAFETY: creating dst slice for fs
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 56) as *mut u8, FS_NAME_LEN)
                };
                // SAFETY: reading user string for mount.fs
                match unsafe { bpf_probe_read_user_str_bytes(m.fs as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };

                // SAFETY: creating dst slice for data
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 8256) as *mut u8, DATA_LEN)
                };
                // SAFETY: reading user string for mount.data
                match unsafe { bpf_probe_read_user_str_bytes(m.data as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };
            }
            UMOUNT_OP => {
                // SAFETY: reading umount variant from arg union
                let u = unsafe { arg.sys.umount };
                // SAFETY: writing umount.flags to ringbuf
                unsafe { *((evt + 48) as *mut u64) = u.flags };

                // SAFETY: creating dst slice for dest
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 56) as *mut u8, PATH_MAX_SIZE)
                };
                // SAFETY: reading user string for umount.dest
                match unsafe { bpf_probe_read_user_str_bytes(u.dest as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };
            }
            FSOPEN_OP => {
                // SAFETY: reading fsopen variant from arg union
                let f = unsafe { arg.sys.fsopen };
                // SAFETY: writing fsopen.flags to ringbuf
                unsafe { *((evt + 56) as *mut u32) = f.flags };

                // SAFETY: creating dst slice for fs
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 48) as *mut u8, FS_NAME_LEN)
                };
                // SAFETY: reading user string for fsopen.fs
                match unsafe { bpf_probe_read_user_str_bytes(f.fs as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };
            }
            FSCONFIG_OP => {
                // SAFETY: reading fsconfig variant from arg union
                let fc = unsafe { arg.sys.fsconfig };
                // SAFETY: writing fsconfig.fd to ringbuf
                unsafe { *((evt + 48) as *mut i32) = fc.fd };
                // SAFETY: writing fsconfig.cmd to ringbuf
                unsafe { *((evt + 52) as *mut u32) = fc.cmd };

                // SAFETY: creating dst slice for key
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 56) as *mut u8, DATA_LEN)
                };
                // SAFETY: reading user string for fsconfig.key
                match unsafe { bpf_probe_read_user_str_bytes(fc.key as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };

                // SAFETY: creating dst slice for value
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 568) as *mut u8, DATA_LEN)
                };
                // SAFETY: reading user string for fsconfig.value
                match unsafe { bpf_probe_read_user_str_bytes(fc.value as *const u8, dst) } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };

                // SAFETY: writing fsconfig.aux to ringbuf
                unsafe { *((evt + 1080) as *mut i32) = fc.aux };
            }
            FSMOUNT_OP => {
                // SAFETY: reading fsmount variant from arg union
                let fm = unsafe { arg.sys.fsmount };
                // SAFETY: writing fsmount.fs_fd to ringbuf
                unsafe { *((evt + 48) as *mut i32) = fm.fs_fd };
                // SAFETY: writing fsmount.flags to ringbuf
                unsafe { *((evt + 52) as *mut u32) = fm.flags };
                // SAFETY: writing fsmount.attr_flags to ringbuf
                unsafe { *((evt + 56) as *mut u32) = fm.attr_flags };
            }
            MOVE_MOUNT_OP => {
                // SAFETY: reading move_mount variant from arg union
                let mm = unsafe { arg.sys.move_mount };
                // SAFETY: writing move_mount.from_dfd to ringbuf
                unsafe { *((evt + 48) as *mut i32) = mm.from_dfd };

                // SAFETY: creating dst slice for from_pathname
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 52) as *mut u8, PATH_MAX_SIZE)
                };
                // SAFETY: reading user string for from_pathname
                match unsafe {
                    bpf_probe_read_user_str_bytes(mm.from_pathname as *const u8, dst)
                } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };

                // SAFETY: writing move_mount.to_dfd to ringbuf
                unsafe { *((evt + 4148) as *mut i32) = mm.to_dfd };

                // SAFETY: creating dst slice for to_pathname
                let dst = unsafe {
                    core::slice::from_raw_parts_mut((evt + 4152) as *mut u8, PATH_MAX_SIZE)
                };
                // SAFETY: reading user string for to_pathname
                match unsafe {
                    bpf_probe_read_user_str_bytes(mm.to_pathname as *const u8, dst)
                } {
                    Ok(_) => {}
                    Err(_) => {
                        entry.discard(0);
                        ARGS.remove(&tid).ok();
                        return Ok(0);
                    }
                };
            }
            _ => {}
        }

        entry.submit(0);
    }

    ARGS.remove(&tid).ok();
    Ok(0)
}

// ===== mount =====

#[tracepoint]
pub fn mount_entry(ctx: TracePointContext) -> i32 {
    match try_mount_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_mount_entry(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading args[0] (src) from tracepoint context
    let src: u64 = unsafe { *((c + 16) as *const u64) };
    // SAFETY: reading args[1] (dest)
    let dest: u64 = unsafe { *((c + 24) as *const u64) };
    // SAFETY: reading args[2] (fs)
    let fs: u64 = unsafe { *((c + 32) as *const u64) };
    // SAFETY: reading args[3] (flags)
    let flags: u64 = unsafe { *((c + 40) as *const u64) };
    // SAFETY: reading args[4] (data)
    let data: u64 = unsafe { *((c + 48) as *const u64) };

    let sys = SysArg {
        mount: MountArgs {
            flags,
            src,
            dest,
            fs,
            data,
        },
    };
    do_probe_entry(sys, MOUNT_OP)
}

#[tracepoint]
pub fn mount_exit(ctx: TracePointContext) -> i32 {
    match try_mount_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_mount_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint
    let ret = unsafe { *((c + 16) as *const u64) } as i32;
    do_probe_exit(c, ret)
}

// ===== umount =====

#[tracepoint]
pub fn umount_entry(ctx: TracePointContext) -> i32 {
    match try_umount_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_umount_entry(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading args[0] (dest)
    let dest: u64 = unsafe { *((c + 16) as *const u64) };
    // SAFETY: reading args[1] (flags)
    let flags: u64 = unsafe { *((c + 24) as *const u64) };

    let sys = SysArg {
        umount: UmountArgs {
            flags,
            dest,
            _pad: [0u8; 24],
        },
    };
    do_probe_entry(sys, UMOUNT_OP)
}

#[tracepoint]
pub fn umount_exit(ctx: TracePointContext) -> i32 {
    match try_umount_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_umount_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint
    let ret = unsafe { *((c + 16) as *const u64) } as i32;
    do_probe_exit(c, ret)
}

// ===== fsopen =====

#[tracepoint]
pub fn fsopen_entry(ctx: TracePointContext) -> i32 {
    match try_fsopen_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fsopen_entry(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading args[0] (fs)
    let fs: u64 = unsafe { *((c + 16) as *const u64) };
    // SAFETY: reading args[1] (flags)
    let flags_raw: u64 = unsafe { *((c + 24) as *const u64) };

    let sys = SysArg {
        fsopen: FsopenArgs {
            fs,
            flags: flags_raw as u32,
            _pad: [0u8; 28],
        },
    };
    do_probe_entry(sys, FSOPEN_OP)
}

#[tracepoint]
pub fn fsopen_exit(ctx: TracePointContext) -> i32 {
    match try_fsopen_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fsopen_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint
    let ret = unsafe { *((c + 16) as *const u64) } as i32;
    do_probe_exit(c, ret)
}

// ===== fsconfig =====

#[tracepoint]
pub fn fsconfig_entry(ctx: TracePointContext) -> i32 {
    match try_fsconfig_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fsconfig_entry(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading args[0] (fd)
    let fd_raw: u64 = unsafe { *((c + 16) as *const u64) };
    // SAFETY: reading args[1] (cmd)
    let cmd_raw: u64 = unsafe { *((c + 24) as *const u64) };
    // SAFETY: reading args[2] (key)
    let key: u64 = unsafe { *((c + 32) as *const u64) };
    // SAFETY: reading args[3] (value)
    let value: u64 = unsafe { *((c + 40) as *const u64) };
    // SAFETY: reading args[4] (aux)
    let aux_raw: u64 = unsafe { *((c + 48) as *const u64) };

    let sys = SysArg {
        fsconfig: FsconfigArgs {
            fd: fd_raw as i32,
            cmd: cmd_raw as u32,
            key,
            value,
            aux: aux_raw as i32,
            _pad: [0u8; 12],
        },
    };
    do_probe_entry(sys, FSCONFIG_OP)
}

#[tracepoint]
pub fn fsconfig_exit(ctx: TracePointContext) -> i32 {
    match try_fsconfig_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fsconfig_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint
    let ret = unsafe { *((c + 16) as *const u64) } as i32;
    do_probe_exit(c, ret)
}

// ===== fsmount =====

#[tracepoint]
pub fn fsmount_entry(ctx: TracePointContext) -> i32 {
    match try_fsmount_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fsmount_entry(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading args[0] (fs_fd)
    let fs_fd_raw: u64 = unsafe { *((c + 16) as *const u64) };
    // SAFETY: reading args[1] (flags)
    let flags_raw: u64 = unsafe { *((c + 24) as *const u64) };
    // SAFETY: reading args[2] (attr_flags)
    let attr_flags_raw: u64 = unsafe { *((c + 32) as *const u64) };

    let sys = SysArg {
        fsmount: FsmountArgs {
            fs_fd: fs_fd_raw as i32,
            flags: flags_raw as u32,
            attr_flags: attr_flags_raw as u32,
            _pad: [0u8; 28],
        },
    };
    do_probe_entry(sys, FSMOUNT_OP)
}

#[tracepoint]
pub fn fsmount_exit(ctx: TracePointContext) -> i32 {
    match try_fsmount_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fsmount_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint
    let ret = unsafe { *((c + 16) as *const u64) } as i32;
    do_probe_exit(c, ret)
}

// ===== move_mount =====

#[tracepoint]
pub fn move_mount_entry(ctx: TracePointContext) -> i32 {
    match try_move_mount_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_move_mount_entry(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading args[0] (from_dfd)
    let from_dfd_raw: u64 = unsafe { *((c + 16) as *const u64) };
    // SAFETY: reading args[1] (from_pathname)
    let from_pathname: u64 = unsafe { *((c + 24) as *const u64) };
    // SAFETY: reading args[2] (to_dfd)
    let to_dfd_raw: u64 = unsafe { *((c + 32) as *const u64) };
    // SAFETY: reading args[3] (to_pathname)
    let to_pathname: u64 = unsafe { *((c + 40) as *const u64) };

    let sys = SysArg {
        move_mount: MoveMountArgs {
            from_dfd: from_dfd_raw as i32,
            _pad1: 0,
            from_pathname,
            to_dfd: to_dfd_raw as i32,
            _pad2: 0,
            to_pathname,
            flags: 0,
            _pad3: [0u8; 4],
        },
    };
    do_probe_entry(sys, MOVE_MOUNT_OP)
}

#[tracepoint]
pub fn move_mount_exit(ctx: TracePointContext) -> i32 {
    match try_move_mount_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_move_mount_exit(ctx: TracePointContext) -> Result<i32, i64> {
    let c = ctx.as_ptr() as usize;
    // SAFETY: reading ret from sys_exit tracepoint
    let ret = unsafe { *((c + 16) as *const u64) } as i32;
    do_probe_exit(c, ret)
}
