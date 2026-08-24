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

const CACHE_NAME_SIZE: usize = 32;
const MAX_ENTRIES: u32 = 10240;

#[repr(C)]
#[derive(Clone, Copy)]
struct SlabRateInfo {
    name: [u8; CACHE_NAME_SIZE],
    count: u64,
    size: u64,
}

#[no_mangle]
static target_pid: Global<i32> = Global::new(0);

#[no_mangle]
#[link_section = ".bss"]
static slab_zero_value: SlabRateInfo = SlabRateInfo {
    name: [0u8; CACHE_NAME_SIZE],
    count: 0,
    size: 0,
};

#[map(name = "slab_entries")]
static SLAB_ENTRIES: HashMap<u64, SlabRateInfo> = HashMap::with_max_entries(MAX_ENTRIES, 0);

fn probe_entry(ctx: ProbeContext) -> Result<i32, i32> {
    let cachep: u64 = ctx.arg(0).ok_or(0i32)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: reading cachep->name pointer at offset 96
    let name_ptr: u64 = unsafe {
        bpf_probe_read_kernel::<u64>((cachep as *const u8).add(96) as *const u64)
    }
    .map_err(|_| 0i32)?;

    let tpid = target_pid.load();
    if tpid != 0 && tpid as u32 != (pid_tgid >> 32) as u32 {
        return Ok(0);
    }

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let existing = unsafe { SLAB_ENTRIES.get(&name_ptr) };

    if let Some(val_ref) = existing {
        let mut info = *val_ref;
        info.count += 1;
        // SAFETY: reading cachep->size (u32) at offset 24
        let cache_size: u32 = unsafe {
            bpf_probe_read_kernel::<u32>((cachep as *const u8).add(24) as *const u32)
        }
        .map_err(|_| 0i32)?;
        info.size += cache_size as u64;
        SLAB_ENTRIES.insert(&name_ptr, &info, 0).ok();
    } else {
        SLAB_ENTRIES.insert(&name_ptr, &slab_zero_value, 0).ok();

        // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
        let val_ref = match unsafe { SLAB_ENTRIES.get(&name_ptr) } {
            Some(r) => r,
            None => return Ok(0),
        };
        let mut info = *val_ref;

        let mut name_buf = [0u8; CACHE_NAME_SIZE];
        // SAFETY: reading NUL-terminated string from valid kernel pointer
        unsafe {
            bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, &mut name_buf)
        }
        .map_err(|_| 0i32)?;
        info.name = name_buf;

        info.count += 1;
        // SAFETY: reading cachep->size (u32) at offset 24
        let cache_size: u32 = unsafe {
            bpf_probe_read_kernel::<u32>((cachep as *const u8).add(24) as *const u32)
        }
        .map_err(|_| 0i32)?;
        info.size += cache_size as u64;
        SLAB_ENTRIES.insert(&name_ptr, &info, 0).ok();
    }

    Ok(0)
}

#[kprobe(function = "kmem_cache_alloc")]
pub fn kmem_cache_alloc(ctx: ProbeContext) -> u32 {
    match probe_entry(ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[kprobe(function = "kmem_cache_alloc_noprof")]
pub fn kmem_cache_alloc_noprof(ctx: ProbeContext) -> u32 {
    match probe_entry(ctx) {
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
