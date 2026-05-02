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

const OFF_FILE_F_PATH_DENTRY: usize = 160;
const OFF_FILE_F_INODE: usize = 168;
const OFF_INODE_I_MODE: usize = 0;
const OFF_INODE_I_SB: usize = 56;
const OFF_INODE_I_INO: usize = 80;
const OFF_INODE_I_RDEV: usize = 92;
const OFF_SB_S_DEV: usize = 16;
const OFF_DENTRY_D_NAME: usize = 32;

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
#[derive(Copy, Clone)]
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
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

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
};

#[map(name = "entries")]
static ENTRIES: HashMap<FileId, FileStat> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
fn probe_entry(ctx: &ProbeContext, op: u32) -> Result<i32, i32> {
    let file: u64 = ctx.arg(0).ok_or(0i32)?;
    let count: u64 = ctx.arg(2).ok_or(0i32)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let tgt_pid = target_pid.load();
    if tgt_pid != 0 && tgt_pid as u32 != pid {
        return Ok(0);
    }

    let file_ptr = file as usize as *const u8;

    // probe_read #1: file->f_inode
    let f_inode_src = file_ptr.wrapping_add(OFF_FILE_F_INODE) as *const u64;
    // SAFETY: reading kernel struct field via probe_read
    let inode_ptr: u64 = unsafe { bpf_probe_read_kernel(f_inode_src) }.map_err(|_| 0i32)?;

    // probe_read #2: inode->i_mode (2 bytes)
    let i_mode_src = (inode_ptr as usize as *const u8).wrapping_add(OFF_INODE_I_MODE) as *const u16;
    // SAFETY: reading kernel struct field via probe_read
    let mode: u16 = unsafe { bpf_probe_read_kernel(i_mode_src) }.map_err(|_| 0i32)?;

    let reg_only = regular_file_only.load();
    if reg_only != 0 && (mode & S_IFMT) != S_IFREG {
        return Ok(0);
    }

    // probe_read #3: file->f_inode (re-read for dev chain, matching C BPF_CORE_READ)
    // SAFETY: reading kernel struct field via probe_read
    let inode_ptr2: u64 = unsafe { bpf_probe_read_kernel(f_inode_src) }.map_err(|_| 0i32)?;

    // probe_read #4: inode->i_sb
    let i_sb_src = (inode_ptr2 as usize as *const u8).wrapping_add(OFF_INODE_I_SB) as *const u64;
    // SAFETY: reading kernel struct field via probe_read
    let sb_ptr: u64 = unsafe { bpf_probe_read_kernel(i_sb_src) }.map_err(|_| 0i32)?;

    // probe_read #5: sb->s_dev (4 bytes)
    let s_dev_src = (sb_ptr as usize as *const u8).wrapping_add(OFF_SB_S_DEV) as *const u32;
    // SAFETY: reading kernel struct field via probe_read
    let dev: u32 = unsafe { bpf_probe_read_kernel(s_dev_src) }.map_err(|_| 0i32)?;

    // probe_read #6: file->f_inode (re-read for rdev)
    // SAFETY: reading kernel struct field via probe_read
    let inode_ptr3: u64 = unsafe { bpf_probe_read_kernel(f_inode_src) }.map_err(|_| 0i32)?;

    // probe_read #7: inode->i_rdev (4 bytes)
    let i_rdev_src = (inode_ptr3 as usize as *const u8).wrapping_add(OFF_INODE_I_RDEV) as *const u32;
    // SAFETY: reading kernel struct field via probe_read
    let rdev: u32 = unsafe { bpf_probe_read_kernel(i_rdev_src) }.map_err(|_| 0i32)?;

    // probe_read #8: file->f_inode (re-read for ino)
    // SAFETY: reading kernel struct field via probe_read
    let inode_ptr4: u64 = unsafe { bpf_probe_read_kernel(f_inode_src) }.map_err(|_| 0i32)?;

    // probe_read #9: inode->i_ino
    let i_ino_src = (inode_ptr4 as usize as *const u8).wrapping_add(OFF_INODE_I_INO) as *const u64;
    // SAFETY: reading kernel struct field via probe_read
    let ino: u64 = unsafe { bpf_probe_read_kernel(i_ino_src) }.map_err(|_| 0i32)?;

    let key = FileId { inode: ino, dev, rdev, pid, tid };

    let existing = ENTRIES.get_ptr_mut(&key);

    if existing.is_none() {
        ENTRIES.insert(&key, &zero_value, 0).map_err(|_| 0i32)?;

        let val_ptr = ENTRIES.get_ptr_mut(&key).ok_or(0i32)?;
        let base = val_ptr as *mut u8;

        // SAFETY: writing pid to map entry at offset 32
        unsafe { core::ptr::write(base.wrapping_add(32) as *mut u32, pid) };
        // SAFETY: writing tid to map entry at offset 36
        unsafe { core::ptr::write(base.wrapping_add(36) as *mut u32, tid) };

        let comm = bpf_get_current_comm().map_err(|_| 0i32)?;
        // SAFETY: copying 16-byte comm to map entry at offset 4136
        unsafe { core::ptr::copy_nonoverlapping(comm.as_ptr(), base.wrapping_add(4136), 16) };

        // probe_read #10: file->f_path.dentry
        let dentry_src = file_ptr.wrapping_add(OFF_FILE_F_PATH_DENTRY) as *const u64;
        // SAFETY: reading kernel struct field via probe_read
        let dentry_ptr: u64 = unsafe { bpf_probe_read_kernel(dentry_src) }.map_err(|_| 0i32)?;

        // probe_read #11: dentry->d_name (qstr, 16 bytes)
        let dname_src =
            (dentry_ptr as usize as *const u8).wrapping_add(OFF_DENTRY_D_NAME) as *const [u64; 2];
        // SAFETY: reading kernel struct field via probe_read
        let dname: [u64; 2] = unsafe { bpf_probe_read_kernel(dname_src) }.map_err(|_| 0i32)?;

        let name_ptr = dname[1] as usize as *const u8;

        // probe_read #12: filename (4096 bytes into map entry at offset 40)
        // SAFETY: creating mutable slice over map entry filename field
        let filename_buf = unsafe { core::slice::from_raw_parts_mut(base.wrapping_add(40), PATH_MAX) };
        // SAFETY: reading kernel filename data via probe_read
        unsafe { bpf_probe_read_kernel_buf(name_ptr, filename_buf) }.map_err(|_| 0i32)?;

        let type_char: u8 = if (mode & S_IFMT) == S_IFREG {
            b'R'
        } else if (mode & S_IFMT) == S_IFSOCK {
            b'S'
        } else {
            b'O'
        };
        // SAFETY: writing type to map entry at offset 4152
        unsafe { core::ptr::write(base.wrapping_add(4152), type_char) };

        if op == 0 {
            // SAFETY: writing reads count to map entry at offset 0
            unsafe { core::ptr::write(base as *mut u64, 1u64) };
            // SAFETY: writing read_bytes to map entry at offset 8
            unsafe { core::ptr::write(base.wrapping_add(8) as *mut u64, count) };
        } else {
            // SAFETY: writing writes count to map entry at offset 16
            unsafe { core::ptr::write(base.wrapping_add(16) as *mut u64, 1u64) };
            // SAFETY: writing write_bytes to map entry at offset 24
            unsafe { core::ptr::write(base.wrapping_add(24) as *mut u64, count) };
        }
    } else {
        let val_ptr = existing.unwrap();
        let base = val_ptr as *mut u8;

        if op == 0 {
            // SAFETY: reading reads count from map entry at offset 0
            let reads = unsafe { core::ptr::read(base as *const u64) };
            // SAFETY: writing incremented reads count to map entry at offset 0
            unsafe { core::ptr::write(base as *mut u64, reads + 1) };

            // SAFETY: reading read_bytes from map entry at offset 8
            let rb = unsafe { core::ptr::read(base.wrapping_add(8) as *const u64) };
            // SAFETY: writing updated read_bytes to map entry at offset 8
            unsafe { core::ptr::write(base.wrapping_add(8) as *mut u64, rb + count) };
        } else {
            // SAFETY: reading writes count from map entry at offset 16
            let writes = unsafe { core::ptr::read(base.wrapping_add(16) as *const u64) };
            // SAFETY: writing incremented writes count to map entry at offset 16
            unsafe { core::ptr::write(base.wrapping_add(16) as *mut u64, writes + 1) };

            // SAFETY: reading write_bytes from map entry at offset 24
            let wb = unsafe { core::ptr::read(base.wrapping_add(24) as *const u64) };
            // SAFETY: writing updated write_bytes to map entry at offset 24
            unsafe { core::ptr::write(base.wrapping_add(24) as *mut u64, wb + count) };
        }
    }

    Ok(0)
}

#[kprobe]
pub fn vfs_read_entry(ctx: ProbeContext) -> u32 {
    match probe_entry(&ctx, 0) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[kprobe]
pub fn vfs_write_entry(ctx: ProbeContext) -> u32 {
    match probe_entry(&ctx, 1) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
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
