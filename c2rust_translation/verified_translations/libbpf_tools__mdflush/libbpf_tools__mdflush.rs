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
const TASK_COMM_LEN: usize = 16;
const DISK_NAME_LEN: usize = 32;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: u32,
    comm: [u8; TASK_COMM_LEN],
    disk: [u8; DISK_NAME_LEN],
}

#[map(name = "events")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[fentry(function = "md_flush_request")]
pub fn md_flush_request(ctx: FEntryContext) -> i32 {
    match try_md_flush_request(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_md_flush_request(ctx: &FEntryContext) -> Result<i32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut event = Event {
        pid: 0,
        comm: [0u8; TASK_COMM_LEN],
        disk: [0u8; DISK_NAME_LEN],
    };

    event.pid = pid;

    let bio: u64 = ctx.arg(1);

    // SAFETY: reading bio->bi_bdev at offset 0
    let bi_bdev: u64 = match unsafe { bpf_probe_read_kernel(bio as *const u64) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    // SAFETY: reading bi_bdev->bd_disk at offset 16
    let gendisk: u64 = match unsafe {
        bpf_probe_read_kernel((bi_bdev as *const u8).wrapping_add(16) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let disk_name_ptr = (gendisk as *const u8).wrapping_add(12);
    let mut tmp = [0u8; 1];
    // SAFETY: reading kernel string from gendisk->disk_name
    match unsafe { bpf_probe_read_kernel_str_bytes(disk_name_ptr, &mut tmp) } {
        Ok(_) => {}
        Err(_) => return Ok(0),
    }
    event.disk[0] = tmp[0];

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    event.comm = comm;

    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

#[kprobe]
pub fn kprobe_md_flush_request(ctx: ProbeContext) -> u32 {
    match try_kprobe_md_flush_request(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_kprobe_md_flush_request(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut event = Event {
        pid: 0,
        comm: [0u8; TASK_COMM_LEN],
        disk: [0u8; DISK_NAME_LEN],
    };

    event.pid = pid;

    let bio: u64 = ctx.arg(1).ok_or(1i64)?;

    // SAFETY: reading bio->bi_bdev at offset 0
    let bi_bdev: u64 = match unsafe { bpf_probe_read_kernel(bio as *const u64) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    // SAFETY: reading bi_bdev->bd_disk at offset 16
    let gendisk: u64 = match unsafe {
        bpf_probe_read_kernel((bi_bdev as *const u8).wrapping_add(16) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let disk_name_ptr = (gendisk as *const u8).wrapping_add(12);
    let mut tmp = [0u8; 1];
    // SAFETY: reading kernel string from gendisk->disk_name
    match unsafe { bpf_probe_read_kernel_str_bytes(disk_name_ptr, &mut tmp) } {
        Ok(_) => {}
        Err(_) => return Ok(0),
    }
    event.disk[0] = tmp[0];

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };
    event.comm = comm;

    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
