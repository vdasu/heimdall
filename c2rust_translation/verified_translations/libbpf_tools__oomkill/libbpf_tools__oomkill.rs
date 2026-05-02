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

const TASK_COMM_LEN: usize = 16;
const MAX_EVENT_SIZE: usize = 10240;

// oom_control field offsets (from compiled C binary disassembly)
const OC_TOTALPAGES_OFF: usize = 32;
const OC_CHOSEN_OFF: usize = 40;

// task_struct field offsets
const TASK_TGID_OFF: usize = 2492;
const TASK_COMM_OFF: usize = 3032;

#[repr(C)]
struct DataT {
    fpid: u32,
    tpid: u32,
    pages: u64,
    fcomm: [u8; TASK_COMM_LEN],
    tcomm: [u8; TASK_COMM_LEN],
}

#[map(name = "heap")]
static HEAP: PerCpuArray<[u8; MAX_EVENT_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[kprobe]
pub fn oom_kill_process(ctx: ProbeContext) -> u32 {
    match try_oom_kill_process(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_oom_kill_process(ctx: ProbeContext) -> Result<u32, c_long> {
    let oc: usize = ctx.arg(0).ok_or(1i64)?;
    let oc = oc as *const u8;

    // CO-RE resolves to ringbuf path in compiled binary (r1=1, so ringbuf branch taken)
    if let Some(mut entry) = EVENTS.reserve::<DataT>(0) {
        let data = entry.as_mut_ptr();

        // SAFETY: zero-initialize reserved ringbuf memory to prevent stale data leaks
        unsafe {
            core::ptr::write_bytes(data as *mut u8, 0u8, core::mem::size_of::<DataT>());
        }

        // fpid = bpf_get_current_pid_tgid() >> 32
        let pid_tgid = bpf_get_current_pid_tgid();
        // SAFETY: writing fpid to reserved ringbuf entry
        unsafe { (*data).fpid = (pid_tgid >> 32) as u32 };

        // BPF_CORE_READ(oc, chosen, tgid): read oc->chosen pointer, then chosen->tgid
        // SAFETY: reading oc->chosen pointer via probe_read_kernel
        let chosen: usize = unsafe {
            bpf_probe_read_kernel(oc.add(OC_CHOSEN_OFF) as *const usize)
        }
        .unwrap_or(0);
        let chosen = chosen as *const u8;

        // SAFETY: reading chosen->tgid via probe_read_kernel
        let tpid: u32 = unsafe {
            bpf_probe_read_kernel(chosen.add(TASK_TGID_OFF) as *const u32)
        }
        .unwrap_or(0);
        // SAFETY: writing tpid to reserved ringbuf entry
        unsafe { (*data).tpid = tpid };

        // BPF_CORE_READ(oc, totalpages): read oc->totalpages
        // SAFETY: reading oc->totalpages via probe_read_kernel
        let pages: u64 = unsafe {
            bpf_probe_read_kernel(oc.add(OC_TOTALPAGES_OFF) as *const u64)
        }
        .unwrap_or(0);
        // SAFETY: writing pages to reserved ringbuf entry
        unsafe { (*data).pages = pages };

        // bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm))
        let fcomm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        // SAFETY: writing fcomm to reserved ringbuf entry
        unsafe { (*data).fcomm = fcomm };

        // Re-read oc->chosen for comm access (matches C binary which re-reads oc->chosen)
        // SAFETY: re-reading oc->chosen pointer via probe_read_kernel
        let chosen2: usize = unsafe {
            bpf_probe_read_kernel(oc.add(OC_CHOSEN_OFF) as *const usize)
        }
        .unwrap_or(0);
        let chosen2 = chosen2 as *const u8;

        // bpf_probe_read_kernel(&data->tcomm, 16, chosen->comm)
        // C binary does: probe_read chosen->comm to stack, then probe_read stack to data->tcomm
        // First read: chosen->comm into local buffer
        // SAFETY: reading chosen->comm via probe_read_kernel
        let tcomm_buf: [u8; TASK_COMM_LEN] = unsafe {
            bpf_probe_read_kernel(chosen2.add(TASK_COMM_OFF) as *const [u8; TASK_COMM_LEN])
        }
        .unwrap_or([0u8; TASK_COMM_LEN]);

        // Second read: copy from local buffer to data->tcomm (matches C binary's double probe_read)
        // SAFETY: copying tcomm buffer to reserved ringbuf entry via probe_read_kernel
        let tcomm: [u8; TASK_COMM_LEN] = unsafe {
            bpf_probe_read_kernel(&tcomm_buf as *const [u8; TASK_COMM_LEN])
        }
        .unwrap_or([0u8; TASK_COMM_LEN]);
        // SAFETY: writing tcomm to reserved ringbuf entry
        unsafe { (*data).tcomm = tcomm };

        // Submit ringbuf entry (CO-RE resolves to ringbuf submit path)
        entry.submit(0);
    }

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
