#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::programs::*;

const S_READ: usize = 0;
const S_WRITE: usize = 1;
const S_FSYNC: usize = 2;
const S_OPEN: usize = 3;
const S_CREATE: usize = 4;
const S_UNLINK: usize = 5;
const S_MKDIR: usize = 6;
const S_RMDIR: usize = 7;

#[no_mangle]
#[link_section = ".bss"]
static stats: [u64; 8] = [0u64; 8];

#[inline(always)]
fn inc_stats(key: usize) -> i32 {
    let base = &stats as *const [u64; 8] as *const u64;
    // SAFETY: key is a compile-time constant in [0, 8), pointer arithmetic is valid
    let elem_ptr = unsafe { base.add(key) } as *mut u64;
    // SAFETY: creating atomic from valid .bss map pointer
    let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(elem_ptr) };
    atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    0
}

#[kprobe(function = "vfs_read")]
pub fn kprobe_vfs_read(_ctx: ProbeContext) -> i32 {
    inc_stats(S_READ)
}

#[kprobe(function = "vfs_write")]
pub fn kprobe_vfs_write(_ctx: ProbeContext) -> i32 {
    inc_stats(S_WRITE)
}

#[kprobe(function = "vfs_fsync")]
pub fn kprobe_vfs_fsync(_ctx: ProbeContext) -> i32 {
    inc_stats(S_FSYNC)
}

#[kprobe(function = "vfs_open")]
pub fn kprobe_vfs_open(_ctx: ProbeContext) -> i32 {
    inc_stats(S_OPEN)
}

#[kprobe(function = "vfs_create")]
pub fn kprobe_vfs_create(_ctx: ProbeContext) -> i32 {
    inc_stats(S_CREATE)
}

#[kprobe(function = "vfs_unlink")]
pub fn kprobe_vfs_unlink(_ctx: ProbeContext) -> i32 {
    inc_stats(S_UNLINK)
}

#[kprobe(function = "vfs_mkdir")]
pub fn kprobe_vfs_mkdir(_ctx: ProbeContext) -> i32 {
    inc_stats(S_MKDIR)
}

#[kprobe(function = "vfs_rmdir")]
pub fn kprobe_vfs_rmdir(_ctx: ProbeContext) -> i32 {
    inc_stats(S_RMDIR)
}

#[fentry(function = "vfs_read")]
pub fn fentry_vfs_read(_ctx: FEntryContext) -> i32 {
    inc_stats(S_READ)
}

#[fentry(function = "vfs_write")]
pub fn fentry_vfs_write(_ctx: FEntryContext) -> i32 {
    inc_stats(S_WRITE)
}

#[fentry(function = "vfs_fsync")]
pub fn fentry_vfs_fsync(_ctx: FEntryContext) -> i32 {
    inc_stats(S_FSYNC)
}

#[fentry(function = "vfs_open")]
pub fn fentry_vfs_open(_ctx: FEntryContext) -> i32 {
    inc_stats(S_OPEN)
}

#[fentry(function = "vfs_create")]
pub fn fentry_vfs_create(_ctx: FEntryContext) -> i32 {
    inc_stats(S_CREATE)
}

#[fentry(function = "vfs_unlink")]
pub fn fentry_vfs_unlink(_ctx: FEntryContext) -> i32 {
    inc_stats(S_UNLINK)
}

#[fentry(function = "vfs_mkdir")]
pub fn fentry_vfs_mkdir(_ctx: FEntryContext) -> i32 {
    inc_stats(S_MKDIR)
}

#[fentry(function = "vfs_rmdir")]
pub fn fentry_vfs_rmdir(_ctx: FEntryContext) -> i32 {
    inc_stats(S_RMDIR)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
