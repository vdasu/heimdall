#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[repr(C)]
#[derive(Clone, Copy)]
struct counter {
    last_sector: u64,
    bytes: u64,
    sequential: u32,
    random: u32,
}

#[no_mangle]
static filter_dev: Global<u8> = Global::new(0);

#[no_mangle]
static targ_dev: Global<u32> = Global::new(0);

#[map(name = "counters")]
static COUNTERS: HashMap<u32, counter> = HashMap::with_max_entries(64, 0);

#[tracepoint]
pub fn handle__block_rq_complete(ctx: TracePointContext) -> i32 {
    match try_handle(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_handle(ctx: TracePointContext) -> Result<i32, i64> {
    // SAFETY: reading sector from tracepoint context at offset 8
    let sector: u64 = unsafe { ctx.read_at(8) }?;
    // SAFETY: reading nr_sector from tracepoint context at offset 16
    let nr_sector: u32 = unsafe { ctx.read_at(16) }?;
    // SAFETY: reading dev from tracepoint context at offset 0
    let dev: u32 = unsafe { ctx.read_at(0) }?;

    let fd = filter_dev.load();
    if fd == 1 {
        let td = targ_dev.load();
        if td != dev {
            return Ok(0);
        }
    }

    let p = match COUNTERS.get_ptr_mut(&dev) {
        Some(p) => p,
        None => {
            let zero = counter {
                last_sector: 0,
                bytes: 0,
                sequential: 0,
                random: 0,
            };
            match COUNTERS.insert(&dev, &zero, 1) {
                Ok(()) => {}
                Err(-17) => {}
                Err(_) => return Ok(0),
            }
            match COUNTERS.get_ptr_mut(&dev) {
                Some(p) => p,
                None => return Ok(0),
            }
        }
    };

    // SAFETY: reading last_sector from map entry at offset 0
    let last_sector_val = unsafe { *(p as *const u64) };

    if last_sector_val != 0 {
        let counter_base = p as *mut u8;
        let field_offset = if last_sector_val == sector { 16usize } else { 20usize };
        // SAFETY: computing field pointer within valid map entry
        let field_ptr = unsafe { counter_base.add(field_offset) } as *mut u32;
        // SAFETY: creating atomic from valid map pointer
        unsafe { AtomicU32::from_ptr(field_ptr) }
            .fetch_add(1, Ordering::Relaxed);

        let nr_bytes = (nr_sector << 9) as u64;
        // SAFETY: computing bytes field pointer within valid map entry
        let bytes_ptr = unsafe { counter_base.add(8) } as *mut u64;
        // SAFETY: creating atomic from valid map pointer
        unsafe { AtomicU64::from_ptr(bytes_ptr) }
            .fetch_add(nr_bytes, Ordering::Relaxed);
    }

    // SAFETY: writing last_sector to map entry at offset 0
    unsafe { *(p as *mut u64) = sector + nr_sector as u64 };

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
