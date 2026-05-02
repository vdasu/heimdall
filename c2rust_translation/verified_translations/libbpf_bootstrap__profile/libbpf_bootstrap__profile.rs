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
use aya_ebpf::EbpfContext;

const TASK_COMM_LEN: usize = 16;
const MAX_STACK_DEPTH: usize = 128;
const BPF_F_USER_STACK: u64 = 1 << 8;

#[repr(C)]
struct stacktrace_event {
    pid: u32,
    cpu_id: u32,
    comm: [u8; TASK_COMM_LEN],
    kstack_sz: i32,
    ustack_sz: i32,
    kstack: [u64; MAX_STACK_DEPTH],
    ustack: [u64; MAX_STACK_DEPTH],
}

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[perf_event]
pub fn profile(ctx: PerfEventContext) -> u32 {
    match try_profile(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_profile(ctx: &PerfEventContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: calling BPF helper to get current CPU id
    let cpu_id = unsafe { aya_ebpf::helpers::generated::bpf_get_smp_processor_id() };

    let mut entry = match EVENTS.reserve::<stacktrace_event>(0) {
        Some(e) => e,
        None => return Ok(1),
    };

    // SAFETY: zero-initializing reserved ringbuf memory to prevent stale data leaks
    unsafe {
        core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, 0u8, core::mem::size_of::<stacktrace_event>())
    };

    let e = entry.as_mut_ptr();

    // SAFETY: writing pid field to valid ringbuf entry
    unsafe { (*e).pid = pid };
    // SAFETY: writing cpu_id field to valid ringbuf entry
    unsafe { (*e).cpu_id = cpu_id };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => {
            entry.discard(0);
            return Ok(0);
        }
    };
    // SAFETY: writing comm field to valid ringbuf entry
    unsafe { (*e).comm = comm };

    let ctx_ptr = ctx.as_ptr();
    // SAFETY: computing address of kstack field in ringbuf entry
    let kstack_ptr = unsafe { core::ptr::addr_of_mut!((*e).kstack) } as *mut c_void;

    // SAFETY: calling bpf_get_stack to capture kernel stack trace
    let kstack_sz = unsafe {
        aya_ebpf::helpers::generated::bpf_get_stack(
            ctx_ptr,
            kstack_ptr,
            core::mem::size_of::<[u64; MAX_STACK_DEPTH]>() as u32,
            0,
        )
    };
    // SAFETY: writing kstack_sz to valid ringbuf entry
    unsafe { (*e).kstack_sz = kstack_sz as i32 };

    // SAFETY: computing address of ustack field in ringbuf entry
    let ustack_ptr = unsafe { core::ptr::addr_of_mut!((*e).ustack) } as *mut c_void;

    // SAFETY: calling bpf_get_stack to capture user stack trace
    let ustack_sz = unsafe {
        aya_ebpf::helpers::generated::bpf_get_stack(
            ctx_ptr,
            ustack_ptr,
            core::mem::size_of::<[u64; MAX_STACK_DEPTH]>() as u32,
            BPF_F_USER_STACK,
        )
    };
    // SAFETY: writing ustack_sz to valid ringbuf entry
    unsafe { (*e).ustack_sz = ustack_sz as i32 };

    entry.submit(0);
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
