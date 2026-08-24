#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::cty::*;

const TASK_COMM_LEN: usize = 16;

#[repr(C)]
struct Event {
    comm: [u8; TASK_COMM_LEN],
    ts_us: u64,
    sys: i32,
}

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline(always)]
fn __syscall(ctx: &TracePointContext, sys: i32) {
    // SAFETY: zeroing repr(C) struct with valid all-zero representation
    let mut event: Event = unsafe { core::mem::zeroed() };

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }
    // SAFETY: calling BPF helper to get current time
    event.ts_us = unsafe { bpf_ktime_get_ns() } / 1000;
    event.sys = sys;
    EVENTS.output(ctx, &event, 0);
}

#[tracepoint(category = "syscalls", name = "sys_enter_sync")]
pub fn tracepoint__syscalls__sys_enter_sync(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 1);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_fsync")]
pub fn tracepoint__syscalls__sys_enter_fsync(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 2);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_fdatasync")]
pub fn tracepoint__syscalls__sys_enter_fdatasync(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 3);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_msync")]
pub fn tracepoint__syscalls__sys_enter_msync(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 4);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_sync_file_range")]
pub fn tracepoint__syscalls__sys_enter_sync_file_range(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 5);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_sync_file_range2")]
pub fn tracepoint__syscalls__sys_enter_sync_file_range2(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 6);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_arm_sync_file_range")]
pub fn tracepoint__syscalls__sys_enter_arm_sync_file_range(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 7);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_syncfs")]
pub fn tracepoint__syscalls__sys_enter_syncfs(ctx: TracePointContext) -> i32 {
    __syscall(&ctx, 8);
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
