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

const TASK_COMM_LEN: usize = 16;
const NAME_MAX: usize = 255;
const MAX_PATH_DEPTH: usize = 32;
const MAX_EVENT_SIZE: usize = 10240;
const FMODE_CREATED: u32 = 0x100000;
const RINGBUF_SIZE: u32 = 1024 * 256;

const TASK_FS_OFFSET: u64 = 3096;
const FS_PWD_MNT_OFFSET: u64 = 40;
const PATH_DENTRY_OFFSET: u64 = 8;
const FILE_F_MODE_OFFSET: u64 = 20;
const DENTRY_D_NAME_NAME_OFFSET: u64 = 40;
const DENTRY_D_PARENT_OFFSET: u64 = 24;
const MOUNT_MNT_OFFSET: i64 = -32;
const VFSMOUNT_MNT_ROOT_OFFSET: u64 = 0;
const MOUNT_MNT_PARENT_OFFSET: u64 = 16;
const MOUNT_MNT_MOUNTPOINT_OFFSET: u64 = 32;

#[repr(C)]
#[derive(Copy, Clone)]
struct FullPath {
    pathes: [u8; NAME_MAX * MAX_PATH_DEPTH],
    depth: u32,
    failed: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    fname: FullPath,
    task: [u8; TASK_COMM_LEN],
    delta_ns: u64,
    tgid: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CreateArg {
    ts: u64,
    cwd_vfsmnt: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UnlinkEvent {
    delta_ns: u64,
    tgid: i32,
    _pad: u32,
    dentry: u64,
    cwd_vfsmnt: u64,
}

#[no_mangle]
static targ_tgid: Global<i32> = Global::new(0);

#[no_mangle]
static full_path: Global<u8> = Global::new(0);

#[map(name = "heap")]
static HEAP: PerCpuArray<[u8; MAX_EVENT_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE, 0);

#[map(name = "start")]
static START: HashMap<u64, CreateArg> = HashMap::with_max_entries(8192, 0);

#[map(name = "currevent")]
static CURREVENT: HashMap<u32, UnlinkEvent> = HashMap::with_max_entries(8192, 0);

#[inline(always)]
fn probe_create(dentry: u64) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;

    let target = targ_tgid.load();
    if target != 0 && target != tgid as i32 {
        return Ok(0);
    }

    // SAFETY: calling bpf_get_current_task_btf (helper 158)
    let task = unsafe { bpf_get_current_task_btf() } as u64;
    // SAFETY: calling bpf_ktime_get_ns
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: reading task->fs at offset 3096
    let fs: u64 = unsafe { bpf_probe_read_kernel((task + TASK_FS_OFFSET) as *const u64) }?;
    // SAFETY: reading fs->pwd.mnt at offset 40
    let mnt: u64 = unsafe { bpf_probe_read_kernel((fs + FS_PWD_MNT_OFFSET) as *const u64) }?;

    let arg = CreateArg {
        ts,
        cwd_vfsmnt: mnt,
    };

    let _ = START.insert(&dentry, &arg, 0);
    Ok(0)
}

#[kprobe(function = "security_inode_create")]
pub fn security_inode_create(ctx: ProbeContext) -> u32 {
    match try_security_inode_create(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_security_inode_create(ctx: ProbeContext) -> Result<i32, i32> {
    let dentry: u64 = ctx.arg(1).ok_or(1i32)?;
    probe_create(dentry)
}

#[kprobe(function = "vfs_create")]
pub fn vfs_create(ctx: ProbeContext) -> u32 {
    match try_vfs_create(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_vfs_create(ctx: ProbeContext) -> Result<i32, i32> {
    let dentry: u64 = ctx.arg(2).ok_or(1i32)?;
    probe_create(dentry)
}

#[kprobe(function = "vfs_open")]
pub fn vfs_open(ctx: ProbeContext) -> u32 {
    match try_vfs_open(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_vfs_open(ctx: ProbeContext) -> Result<i32, i32> {
    let path: u64 = ctx.arg(0).ok_or(1i32)?;
    let file: u64 = ctx.arg(1).ok_or(1i32)?;

    // SAFETY: reading path->dentry at offset 8
    let dentry: u64 =
        unsafe { bpf_probe_read_kernel((path + PATH_DENTRY_OFFSET) as *const u64) }?;

    // SAFETY: reading file->f_mode at offset 20
    let fmode: u32 =
        unsafe { bpf_probe_read_kernel((file + FILE_F_MODE_OFFSET) as *const u32) }?;

    if (fmode & FMODE_CREATED) == 0 {
        return Ok(0);
    }

    probe_create(dentry)
}

#[kprobe(function = "vfs_unlink")]
pub fn vfs_unlink(ctx: ProbeContext) -> u32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_vfs_unlink(ctx: ProbeContext) -> Result<i32, i32> {
    let arg2: u64 = ctx.arg(2).ok_or(1i32)?;

    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let tid = id as u32;

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let create_arg = match unsafe { START.get(&arg2) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    // SAFETY: calling bpf_ktime_get_ns
    let ktime = unsafe { bpf_ktime_get_ns() };
    let delta_ns = ktime - create_arg.ts;

    let unlink_event = UnlinkEvent {
        delta_ns,
        tgid: tgid as i32,
        _pad: 0,
        dentry: arg2,
        cwd_vfsmnt: create_arg.cwd_vfsmnt,
    };

    let _ = CURREVENT.insert(&tid, &unlink_event, 0);
    Ok(0)
}

#[kretprobe(function = "vfs_unlink")]
pub fn vfs_unlink_ret(ctx: RetProbeContext) -> u32 {
    match try_vfs_unlink_ret(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_vfs_unlink_ret(ctx: RetProbeContext) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();
    let tid = id as u32;

    let ret: u64 = ctx.ret();

    // SAFETY: HashMap::get requires unsafe in aya-ebpf
    let unlink_event = match unsafe { CURREVENT.get(&tid) } {
        Some(e) => *e,
        None => return Ok(0),
    };

    let _ = CURREVENT.remove(&tid);

    let ret_val = ret as u32;
    if ret_val != 0 {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let evt = entry.as_mut_ptr();

        // SAFETY: zero-initialize reserved ringbuf memory to prevent stale data leaks
        unsafe { core::ptr::write_bytes(evt as *mut u8, 0u8, core::mem::size_of::<Event>()) };

        // SAFETY: writing tgid to reserved ringbuf entry
        unsafe { (*evt).tgid = unlink_event.tgid };
        // SAFETY: writing delta_ns to reserved ringbuf entry
        unsafe { (*evt).delta_ns = unlink_event.delta_ns };

        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };
        // SAFETY: writing task comm to reserved ringbuf entry
        unsafe { (*evt).task = comm };

        let dentry = unlink_event.dentry;
        // SAFETY: reading dentry->d_name.name at offset 40
        let qs_name_ptr: u64 = match unsafe {
            bpf_probe_read_kernel((dentry + DENTRY_D_NAME_NAME_OFFSET) as *const u64)
        } {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        // SAFETY: accessing pathes pointer in reserved ringbuf entry
        let pathes_ptr = unsafe { (*evt).fname.pathes.as_mut_ptr() };
        // SAFETY: creating mutable slice from reserved ringbuf entry
        let dest =
            unsafe { core::slice::from_raw_parts_mut(pathes_ptr, NAME_MAX * MAX_PATH_DEPTH) };
        match unsafe { bpf_probe_read_kernel_str_bytes(qs_name_ptr as *const u8, dest) } {
            Ok(_) => {}
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        // SAFETY: writing fname.depth to reserved ringbuf entry
        unsafe { (*evt).fname.depth = 0 };

        if full_path.load() == 1 {
            // SAFETY: reading first byte of pathes from reserved ringbuf entry
            let first_byte = unsafe { (*evt).fname.pathes[0] };
            if first_byte != b'/' {
                do_dentry_full_path(evt, &unlink_event);
            }
        }

        let _ = START.remove(&unlink_event.dentry);

        entry.submit(0);
    }

    Ok(0)
}

#[inline(always)]
fn do_dentry_full_path(evt: *mut Event, ue: &UnlinkEvent) {
    let mut dentry_ptr = ue.dentry;
    let cwd_vfsmnt = ue.cwd_vfsmnt;

    let mnt_addr = (cwd_vfsmnt as i64 + MOUNT_MNT_OFFSET) as u64;
    // SAFETY: reading vfsmount->mnt_root
    let mnt_root: u64 = match unsafe {
        bpf_probe_read_kernel((cwd_vfsmnt + VFSMOUNT_MNT_ROOT_OFFSET) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => {
            // SAFETY: writing failed flag
            unsafe { (*evt).fname.failed = 1 };
            return;
        }
    };

    let mut mnt = mnt_addr;
    let mut mnt_root_val = mnt_root;
    let mut payload_offset: usize = 0;
    let mut depth: u32 = 0;
    let mut i: u32 = 0;

    while i < MAX_PATH_DEPTH as u32 {
        // SAFETY: reading dentry->d_name.name
        let name_ptr: u64 = match unsafe {
            bpf_probe_read_kernel((dentry_ptr + DENTRY_D_NAME_NAME_OFFSET) as *const u64)
        } {
            Ok(v) => v,
            Err(_) => {
                // SAFETY: writing failed flag and depth before returning
                unsafe { (*evt).fname.failed = 1 };
                unsafe { (*evt).fname.depth = depth };
                return;
            }
        };

        if payload_offset + NAME_MAX > NAME_MAX * MAX_PATH_DEPTH {
            break;
        }

        // SAFETY: computing destination pointer for path component
        let dest_ptr = unsafe { (*evt).fname.pathes.as_mut_ptr().add(payload_offset) };
        // SAFETY: creating mutable slice for path component
        let dest_slice = unsafe { core::slice::from_raw_parts_mut(dest_ptr, NAME_MAX) };
        let read_len = match unsafe {
            bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, dest_slice)
        } {
            Ok(s) => s.len(),
            Err(_) => {
                // SAFETY: writing failed flag and depth before returning
                unsafe { (*evt).fname.failed = 1 };
                unsafe { (*evt).fname.depth = depth };
                return;
            }
        };

        if read_len > NAME_MAX {
            break;
        }

        // SAFETY: reading dentry->d_parent
        let parent_dentry: u64 = match unsafe {
            bpf_probe_read_kernel((dentry_ptr + DENTRY_D_PARENT_OFFSET) as *const u64)
        } {
            Ok(v) => v,
            Err(_) => {
                // SAFETY: writing depth before returning
                unsafe { (*evt).fname.depth = depth };
                return;
            }
        };

        if dentry_ptr == parent_dentry || dentry_ptr == mnt_root_val {
            // SAFETY: reading mount->mnt_parent
            let mnt_parent: u64 = match unsafe {
                bpf_probe_read_kernel((mnt + MOUNT_MNT_PARENT_OFFSET) as *const u64)
            } {
                Ok(v) => v,
                Err(_) => {
                    // SAFETY: writing depth before returning
                    unsafe { (*evt).fname.depth = depth };
                    return;
                }
            };

            if mnt != mnt_parent {
                // SAFETY: reading mount->mnt_mountpoint
                dentry_ptr = match unsafe {
                    bpf_probe_read_kernel((mnt + MOUNT_MNT_MOUNTPOINT_OFFSET) as *const u64)
                } {
                    Ok(v) => v,
                    Err(_) => {
                        // SAFETY: writing depth before returning
                        unsafe { (*evt).fname.depth = depth };
                        return;
                    }
                };
                mnt = mnt_parent;
                let new_vfsmnt = (mnt_parent as i64 - MOUNT_MNT_OFFSET) as u64;
                // SAFETY: reading new vfsmount->mnt_root
                mnt_root_val = match unsafe {
                    bpf_probe_read_kernel(
                        (new_vfsmnt + VFSMOUNT_MNT_ROOT_OFFSET) as *const u64,
                    )
                } {
                    Ok(v) => v,
                    Err(_) => {
                        // SAFETY: writing depth before returning
                        unsafe { (*evt).fname.depth = depth };
                        return;
                    }
                };
                depth += 1;
                payload_offset += NAME_MAX;
                i += 1;
                continue;
            } else {
                break;
            }
        }

        payload_offset += NAME_MAX;
        dentry_ptr = parent_dentry;
        depth += 1;
        i += 1;
    }

    // SAFETY: writing depth to reserved ringbuf entry
    unsafe { (*evt).fname.depth = depth };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
