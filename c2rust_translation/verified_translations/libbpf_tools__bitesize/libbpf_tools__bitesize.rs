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

const TASK_COMM_LEN: usize = 16;
const MAX_SLOTS: usize = 20;

#[repr(C)]
#[derive(Clone, Copy)]
struct hist_key {
    comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct hist {
    slots: [u32; MAX_SLOTS],
}

#[no_mangle]
static targ_comm: Global<[u8; TASK_COMM_LEN]> = Global::new([0u8; TASK_COMM_LEN]);

#[no_mangle]
static filter_dev: Global<u8> = Global::new(0);

#[no_mangle]
static targ_dev: Global<u32> = Global::new(0);

extern "C" {
    #[link_name = "LINUX_KERNEL_VERSION"]
    static LINUX_KERNEL_VERSION: u32;
}

#[no_mangle]
#[link_section = ".bss"]
static initial_hist: hist = hist { slots: [0u32; MAX_SLOTS] };

#[map(name = "hists")]
static HISTS: HashMap<hist_key, hist> = HashMap::with_max_entries(10240, 0);

#[inline(always)]
fn log2_u32(v: u32) -> u32 {
    let mut v = v;
    let r = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    let shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    let r = r | shift;
    let shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    let r = r | shift;
    let shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r | shift | (v >> 1)
}

#[inline(always)]
fn log2l(v: u64) -> u64 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi) as u64 + 32
    } else {
        log2_u32(v as u32) as u64
    }
}

#[inline(always)]
fn trace_rq_issue(rq: u64) -> i32 {
    if filter_dev.load() != 0 {
        return 0;
    }

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let tc = targ_comm.load();
    for i in 0..TASK_COMM_LEN {
        if tc[i] == 0 {
            break;
        }
        if comm[i] != tc[i] {
            return 0;
        }
    }

    let hkey = hist_key { comm };

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let first = unsafe { HISTS.get(&hkey) };
    let hist_ref = match first {
        Some(h) => h,
        None => {
            let _ = HISTS.insert(&hkey, &initial_hist, 0);
            // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
            match unsafe { HISTS.get(&hkey) } {
                Some(h) => h,
                None => return 0,
            }
        }
    };

    // SAFETY: reading __data_len field from kernel request struct at offset 44
    let data_len: u32 = unsafe { *((rq as *const u8).add(44) as *const u32) };

    let mut slot = log2l((data_len / 1024) as u64);
    if slot >= MAX_SLOTS as u64 {
        slot = (MAX_SLOTS - 1) as u64;
    }

    let mut h = *hist_ref;
    h.slots[slot as usize] += 1;
    let _ = HISTS.insert(&hkey, &h, 0);

    0
}

#[btf_tracepoint(function = "block_rq_issue")]
pub fn block_rq_issue(ctx: BtfTracePointContext) -> i32 {
    // SAFETY: reading extern __kconfig kernel version variable
    let kver = unsafe { LINUX_KERNEL_VERSION };

    let rq = if kver >= 330377 {
        ctx.arg::<u64>(0)
    } else {
        ctx.arg::<u64>(1)
    };

    trace_rq_issue(rq)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
