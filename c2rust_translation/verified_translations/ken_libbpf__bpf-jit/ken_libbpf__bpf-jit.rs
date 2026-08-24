#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::Array;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::Global;

#[no_mangle]
static kaddr_bpf_jit_current: Global<u64> = Global::new(0);

#[map]
static bpf_jit_pages_currently_allocated: Array<u64> = Array::with_max_entries(1, 0);

#[inline(always)]
fn update_current() -> Result<u32, i64> {
    let kaddr = kaddr_bpf_jit_current.load();

    if kaddr == 0 {
        return Ok(0);
    }

    // SAFETY: reading kernel memory at loader-provided address
    let current_value = unsafe { bpf_probe_read_kernel(kaddr as *const i64) }
        .unwrap_or(0);

    let ptr = bpf_jit_pages_currently_allocated.get_ptr_mut(0).ok_or(1i64)?;
    // SAFETY: pointer valid from successful array map lookup
    unsafe { *ptr = current_value as u64; }

    Ok(0)
}

#[kprobe(function = "bpf_jit_binary_alloc")]
pub fn trace_change(_ctx: ProbeContext) -> u32 {
    match update_current() {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[uprobe]
pub fn do_init(_ctx: ProbeContext) -> u32 {
    match update_current() {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
