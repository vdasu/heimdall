#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::HashMap;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const PATH_MAX: usize = 4096;
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;
const S_IFSOCK: u16 = 0o140000;

const FILE_F_PATH_DENTRY: usize = 160;
const FILE_F_INODE: usize = 168;
const INODE_I_MODE: usize = 0;
const INODE_I_SB: usize = 56;
const INODE_I_INO: usize = 80;
const INODE_I_RDEV: usize = 92;
const SB_S_DEV: usize = 16;
const DENTRY_D_NAME: usize = 32;
const QSTR_NAME_OFF: usize = 8;

#[repr(C)]
#[derive(Copy, Clone)]
struct FileId {
    inode: u64,
    dev: u32,
    rdev: u32,
    pid: u32,
    tid: u32,
}

#[repr(C)]
struct FileStat {
    reads: u64,
    read_bytes: u64,
    writes: u64,
    write_bytes: u64,
    pid: u32,
    tid: u32,
    filename: [u8; PATH_MAX],
    comm: [u8; 16],
    type_: u8,
    _pad: [u8; 7],
}

#[map(name = "entries")]
static ENTRIES: HashMap<FileId, FileStat> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[no_mangle]
static target_pid: Global<u32> = Global::new(0);

#[no_mangle]
static regular_file_only: Global<u8> = Global::new(1);

#[no_mangle]
#[link_section = ".bss"]
static zero_value: FileStat = FileStat {
    reads: 0,
    read_bytes: 0,
    writes: 0,
    write_bytes: 0,
    pid: 0,
    tid: 0,
    filename: [0u8; PATH_MAX],
    comm: [0u8; 16],
    type_: 0,
    _pad: [0u8; 7],
};

#[kprobe]
pub fn vfs_read_entry(ctx: ProbeContext) -> i32 {
    match try_probe(&ctx, 0u32) {
        Ok(r) => r,
        Err(r) => r,
    }
}

#[kprobe]
pub fn vfs_write_entry(ctx: ProbeContext) -> i32 {
    match try_probe(&ctx, 1u32) {
        Ok(r) => r,
        Err(r) => r,
    }
}

#[inline(always)]
fn try_probe(ctx: &ProbeContext, op: u32) -> Result<i32, i32> {
    let file: u64 = ctx.arg(0).ok_or(0i32)?;
    let count: u64 = ctx.arg(2).ok_or(0i32)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let tpid = target_pid.load();
    if tpid != 0 && tpid != pid {
        return Ok(0);
    }

    // SAFETY: reading f_inode pointer from kernel file struct
    let f_inode = unsafe {
        bpf_probe_read_kernel(
            (file as *const u8).wrapping_add(FILE_F_INODE) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading i_mode from kernel inode struct
    let mode: u16 = unsafe {
        bpf_probe_read_kernel(
            (f_inode as *const u8).wrapping_add(INODE_I_MODE) as *const u16,
        )
    }
    .map_err(|_| 0i32)?;

    let reg_only = regular_file_only.load();
    if reg_only != 0 && (mode & S_IFMT) != S_IFREG {
        return Ok(0);
    }

    // SAFETY: reading f_inode pointer from kernel file struct (for dev chain)
    let f_inode2 = unsafe {
        bpf_probe_read_kernel(
            (file as *const u8).wrapping_add(FILE_F_INODE) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading i_sb pointer from kernel inode struct
    let i_sb = unsafe {
        bpf_probe_read_kernel(
            (f_inode2 as *const u8).wrapping_add(INODE_I_SB) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading s_dev from kernel super_block struct
    let dev: u32 = unsafe {
        bpf_probe_read_kernel(
            (i_sb as *const u8).wrapping_add(SB_S_DEV) as *const u32,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading f_inode pointer from kernel file struct (for rdev chain)
    let f_inode3 = unsafe {
        bpf_probe_read_kernel(
            (file as *const u8).wrapping_add(FILE_F_INODE) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading i_rdev from kernel inode struct
    let rdev: u32 = unsafe {
        bpf_probe_read_kernel(
            (f_inode3 as *const u8).wrapping_add(INODE_I_RDEV) as *const u32,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading f_inode pointer from kernel file struct (for ino chain)
    let f_inode4 = unsafe {
        bpf_probe_read_kernel(
            (file as *const u8).wrapping_add(FILE_F_INODE) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading i_ino from kernel inode struct
    let ino = unsafe {
        bpf_probe_read_kernel(
            (f_inode4 as *const u8).wrapping_add(INODE_I_INO) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    let key = FileId {
        inode: ino,
        dev,
        rdev,
        pid,
        tid,
    };

    let ptr = match ENTRIES.get_ptr_mut(&key) {
        Some(p) => p,
        None => {
            let _ = ENTRIES.insert(&key, &zero_value, 0);
            match ENTRIES.get_ptr_mut(&key) {
                Some(p) => {
                    init_new_entry(p, pid, tid, mode, file)?;
                    p
                }
                None => return Ok(0),
            }
        }
    };

    update_counters(ptr, op, count);
    Ok(0)
}

#[inline(always)]
fn init_new_entry(
    p: *mut FileStat,
    pid: u32,
    tid: u32,
    mode: u16,
    file: u64,
) -> Result<(), i32> {
    // SAFETY: obtaining pointer to pid field in valid map entry
    let pid_ptr = unsafe { core::ptr::addr_of_mut!((*p).pid) };
    // SAFETY: writing pid to map entry
    unsafe { core::ptr::write(pid_ptr, pid) };

    // SAFETY: obtaining pointer to tid field in valid map entry
    let tid_ptr = unsafe { core::ptr::addr_of_mut!((*p).tid) };
    // SAFETY: writing tid to map entry
    unsafe { core::ptr::write(tid_ptr, tid) };

    let comm = bpf_get_current_comm().map_err(|_| 0i32)?;
    // SAFETY: obtaining pointer to comm field in valid map entry
    let comm_ptr = unsafe { core::ptr::addr_of_mut!((*p).comm) };
    // SAFETY: writing comm to map entry
    unsafe { core::ptr::write(comm_ptr, comm) };

    // SAFETY: reading dentry pointer from kernel file struct
    let dentry = unsafe {
        bpf_probe_read_kernel(
            (file as *const u8).wrapping_add(FILE_F_PATH_DENTRY) as *const u64,
        )
    }
    .map_err(|_| 0i32)?;

    // SAFETY: reading qstr struct from kernel dentry
    let qstr: [u8; 16] = unsafe {
        bpf_probe_read_kernel(
            (dentry as *const u8).wrapping_add(DENTRY_D_NAME) as *const [u8; 16],
        )
    }
    .map_err(|_| 0i32)?;

    let name_ptr = u64::from_ne_bytes([
        qstr[QSTR_NAME_OFF],
        qstr[QSTR_NAME_OFF + 1],
        qstr[QSTR_NAME_OFF + 2],
        qstr[QSTR_NAME_OFF + 3],
        qstr[QSTR_NAME_OFF + 4],
        qstr[QSTR_NAME_OFF + 5],
        qstr[QSTR_NAME_OFF + 6],
        qstr[QSTR_NAME_OFF + 7],
    ]);

    // SAFETY: obtaining pointer to filename buffer in valid map entry
    let fn_ptr = unsafe { core::ptr::addr_of_mut!((*p).filename) } as *mut u8;
    // SAFETY: creating mutable slice from valid map entry filename buffer
    let fn_buf = unsafe { core::slice::from_raw_parts_mut(fn_ptr, PATH_MAX) };
    // SAFETY: reading kernel string into filename buffer (str variant stops at NUL)
    unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, fn_buf) }
        .map_err(|_| 0i32)?;

    let type_char = if (mode & S_IFMT) == S_IFREG {
        b'R'
    } else if (mode & S_IFMT) == S_IFSOCK {
        b'S'
    } else {
        b'O'
    };
    // SAFETY: obtaining pointer to type_ field in valid map entry
    let type_ptr = unsafe { core::ptr::addr_of_mut!((*p).type_) };
    // SAFETY: writing type to map entry
    unsafe { core::ptr::write(type_ptr, type_char) };

    Ok(())
}

#[inline(always)]
fn update_counters(ptr: *mut FileStat, op: u32, count: u64) {
    let base = ptr as *mut u8;
    if op == 0 {
        // SAFETY: reading reads counter from valid map entry at offset 0
        let reads = unsafe { core::ptr::read(base as *const u64) };
        // SAFETY: writing incremented reads counter
        unsafe { core::ptr::write(base as *mut u64, reads + 1) };
        let rb = base.wrapping_add(8) as *mut u64;
        // SAFETY: reading read_bytes from valid map entry at offset 8
        let read_bytes = unsafe { core::ptr::read(rb as *const u64) };
        // SAFETY: writing updated read_bytes
        unsafe { core::ptr::write(rb, read_bytes + count) };
    } else {
        let wp = base.wrapping_add(16) as *mut u64;
        // SAFETY: reading writes counter from valid map entry at offset 16
        let writes = unsafe { core::ptr::read(wp as *const u64) };
        // SAFETY: writing incremented writes counter
        unsafe { core::ptr::write(wp, writes + 1) };
        let wbp = base.wrapping_add(24) as *mut u64;
        // SAFETY: reading write_bytes from valid map entry at offset 24
        let write_bytes = unsafe { core::ptr::read(wbp as *const u64) };
        // SAFETY: writing updated write_bytes
        unsafe { core::ptr::write(wbp, write_bytes + count) };
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
