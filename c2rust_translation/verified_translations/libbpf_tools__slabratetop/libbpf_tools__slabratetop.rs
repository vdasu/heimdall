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
use aya_ebpf::Global;

const MAX_ENTRIES: u32 = 10240;
const CACHE_NAME_SIZE: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct slabrate_info {
    name: [u8; CACHE_NAME_SIZE],
    count: u64,
    size: u64,
}

#[no_mangle]
static target_pid: Global<u32> = Global::new(0);

#[no_mangle]
#[link_section = ".bss"]
static slab_zero_value: slabrate_info = slabrate_info {
    name: [0u8; CACHE_NAME_SIZE],
    count: 0,
    size: 0,
};

#[map(name = "slab_entries")]
static SLAB_ENTRIES: HashMap<u64, slabrate_info> = HashMap::with_max_entries(MAX_ENTRIES, 0);

fn probe_entry(ctx: &ProbeContext) -> Result<i32, i32> {
    let cachep: u64 = ctx.arg(0).ok_or(0i32)?;
    let cachep_ptr = cachep as *const u8;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // SAFETY: reading name pointer from kernel kmem_cache struct at offset 96
    let name_ptr: u64 = unsafe {
        bpf_probe_read_kernel(cachep_ptr.add(96) as *const u64)
    }.map_err(|_| 0i32)?;

    let tgt_pid = target_pid.load();
    if tgt_pid != 0 && tgt_pid != pid {
        return Ok(0);
    }

    // SAFETY: map lookup requires unsafe
    let existing = unsafe { SLAB_ENTRIES.get(&name_ptr) };

    let mut val = match existing {
        Some(v) => *v,
        None => {
            SLAB_ENTRIES.insert(&name_ptr, &slab_zero_value, 0).ok();
            // SAFETY: map lookup after insert
            match unsafe { SLAB_ENTRIES.get(&name_ptr) } {
                Some(v) => {
                    let mut entry = *v;
                    // SAFETY: reading name string from kernel memory
                    let name_bytes: [u8; CACHE_NAME_SIZE] = unsafe {
                        bpf_probe_read_kernel(name_ptr as *const [u8; CACHE_NAME_SIZE])
                    }.unwrap_or([0u8; CACHE_NAME_SIZE]);
                    entry.name = name_bytes;
                    entry
                }
                None => return Ok(0),
            }
        }
    };

    val.count += 1;

    // SAFETY: reading size field from kernel kmem_cache struct at offset 24
    let cache_size: u32 = unsafe {
        bpf_probe_read_kernel(cachep_ptr.add(24) as *const u32)
    }.unwrap_or(0);

    val.size += cache_size as u64;

    SLAB_ENTRIES.insert(&name_ptr, &val, 0).ok();

    Ok(0)
}

#[kprobe]
pub fn kmem_cache_alloc(ctx: ProbeContext) -> u32 {
    match probe_entry(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[kprobe]
pub fn kmem_cache_alloc_noprof(ctx: ProbeContext) -> u32 {
    match probe_entry(&ctx) {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
