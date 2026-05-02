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
use aya_ebpf::EbpfContext;
use aya_ebpf::Global;

#[repr(C)]
#[derive(Clone, Copy)]
struct alloc_info {
    size: u64,
    timestamp_ns: u64,
    stack_id: i32,
}

#[no_mangle]
static min_size: Global<u64> = Global::new(0);
#[no_mangle]
static max_size: Global<u64> = Global::new(u64::MAX);
#[no_mangle]
static page_size: Global<u64> = Global::new(4096);
#[no_mangle]
static sample_rate: Global<u64> = Global::new(1);
#[no_mangle]
static trace_all: Global<u8> = Global::new(0);
#[no_mangle]
static stack_flags: Global<u64> = Global::new(0);
#[no_mangle]
static wa_missing_free: Global<u8> = Global::new(0);
#[no_mangle]
static combined_only: Global<u8> = Global::new(0);

#[no_mangle]
#[link_section = ".bss"]
static initial_cinfo: u64 = 0;

#[map(name = "sizes")]
static SIZES: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "allocs")]
static ALLOCS: HashMap<u64, alloc_info> = HashMap::with_max_entries(1000000, 0);

#[map(name = "combined_allocs")]
static COMBINED_ALLOCS: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "memptrs")]
static MEMPTRS: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "stack_traces")]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(10240, 0);

#[inline(always)]
fn update_statistics_add(stack_id_val: u64, sz: u64) {
    let ptr = match COMBINED_ALLOCS.get_ptr_mut(&stack_id_val) {
        Some(p) => p,
        None => {
            match COMBINED_ALLOCS.insert(&stack_id_val, &initial_cinfo, 1) {
                Ok(()) => {}
                Err(e) => {
                    if e != -17 {
                        return;
                    }
                }
            }
            match COMBINED_ALLOCS.get_ptr_mut(&stack_id_val) {
                Some(p) => p,
                None => return,
            }
        }
    };
    let incremental_bits: u64 = (sz & 0xFF_FFFF_FFFF) | (1u64 << 40);
    // SAFETY: atomic add on valid map pointer for combined alloc tracking
    let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
    atomic.fetch_add(incremental_bits, core::sync::atomic::Ordering::Relaxed);
}

#[inline(always)]
fn update_statistics_del(stack_id_val: u64, sz: u64) {
    let ptr = match COMBINED_ALLOCS.get_ptr_mut(&stack_id_val) {
        Some(p) => p,
        None => return,
    };
    let decremental_bits: u64 = (sz & 0xFF_FFFF_FFFF) | (1u64 << 40);
    let neg_bits = 0u64.wrapping_sub(decremental_bits);
    // SAFETY: atomic add on valid map pointer for combined alloc tracking
    let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
    atomic.fetch_add(neg_bits, core::sync::atomic::Ordering::Relaxed);
}

#[inline(always)]
fn gen_alloc_enter(size: u64) -> i32 {
    if size < min_size.load() || size > max_size.load() {
        return 0;
    }
    let sr = sample_rate.load();
    if sr > 1 {
        // SAFETY: getting current monotonic time for sampling
        let ts = unsafe { bpf_ktime_get_ns() };
        if ts % sr != 0 {
            return 0;
        }
    }
    let tid = bpf_get_current_pid_tgid() as u32;
    SIZES.insert(&tid, &size, 0).ok();
    0
}

#[inline(always)]
fn gen_alloc_exit2<C: EbpfContext>(ctx: &C, address: u64) -> i32 {
    let tid = bpf_get_current_pid_tgid() as u32;

    let size_val = match unsafe { SIZES.get(&tid) } {
        // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
        Some(s) => *s,
        None => return 0,
    };

    SIZES.remove(&tid).ok();

    if address != 0 && address != u64::MAX {
        // SAFETY: getting current monotonic time
        let timestamp_ns = unsafe { bpf_ktime_get_ns() };

        // SAFETY: getting stack trace ID from stack map
        let stack_id = match unsafe { STACK_TRACES.get_stackid::<C>(ctx, stack_flags.load()) } {
            Ok(id) => id as i32,
            Err(_) => return 0,
        };

        // SAFETY: alloc_info is repr(C) with integer fields, all-zero is valid
        let mut info: alloc_info = unsafe { core::mem::zeroed() };
        info.size = size_val;
        info.timestamp_ns = timestamp_ns;
        info.stack_id = stack_id;

        ALLOCS.insert(&address, &info, 0).ok();

        if combined_only.load() != 0 {
            update_statistics_add(stack_id as u64, size_val);
        }
    }

    0
}

#[inline(always)]
fn gen_alloc_exit(ctx: &RetProbeContext) -> i32 {
    let address = ctx.ret::<u64>();
    gen_alloc_exit2(ctx, address)
}

#[inline(always)]
fn gen_free_enter(address: u64) -> i32 {
    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let info = match unsafe { ALLOCS.get(&address) } {
        Some(i) => *i,
        None => return 0,
    };

    ALLOCS.remove(&address).ok();

    if combined_only.load() != 0 {
        update_statistics_del(info.stack_id as u64, info.size);
    }

    0
}

// --- Uprobe entry points ---

#[uprobe]
pub fn malloc_enter(ctx: ProbeContext) -> i32 {
    let size: u64 = ctx.arg(0).unwrap_or(0);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn malloc_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn free_enter(ctx: ProbeContext) -> i32 {
    let address: u64 = ctx.arg(0).unwrap_or(0);
    gen_free_enter(address)
}

#[uprobe]
pub fn calloc_enter(ctx: ProbeContext) -> i32 {
    let nmemb: u64 = ctx.arg(0).unwrap_or(0);
    let size: u64 = ctx.arg(1).unwrap_or(0);
    gen_alloc_enter(nmemb.wrapping_mul(size))
}

#[uretprobe]
pub fn calloc_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn realloc_enter(ctx: ProbeContext) -> i32 {
    let ptr: u64 = ctx.arg(0).unwrap_or(0);
    let size: u64 = ctx.arg(1).unwrap_or(0);
    gen_free_enter(ptr);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn realloc_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn mmap_enter(ctx: ProbeContext) -> i32 {
    let size: u64 = ctx.arg(1).unwrap_or(0);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn mmap_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn munmap_enter(ctx: ProbeContext) -> i32 {
    let address: u64 = ctx.arg(0).unwrap_or(0);
    gen_free_enter(address)
}

#[uprobe]
pub fn mremap_enter(ctx: ProbeContext) -> i32 {
    let old_address: u64 = ctx.arg(0).unwrap_or(0);
    let new_size: u64 = ctx.arg(2).unwrap_or(0);
    gen_free_enter(old_address);
    gen_alloc_enter(new_size)
}

#[uretprobe]
pub fn mremap_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn posix_memalign_enter(ctx: ProbeContext) -> i32 {
    let memptr: u64 = ctx.arg(0).unwrap_or(0);
    let size: u64 = ctx.arg(2).unwrap_or(0);
    let tid = bpf_get_current_pid_tgid() as u32;
    MEMPTRS.insert(&tid, &memptr, 0).ok();
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn posix_memalign_exit(ctx: RetProbeContext) -> i32 {
    match try_posix_memalign_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_posix_memalign_exit(ctx: &RetProbeContext) -> Result<i32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;

    // SAFETY: HashMap::get is pub unsafe fn in aya-ebpf
    let memptr64 = match unsafe { MEMPTRS.get(&tid) } {
        Some(v) => *v,
        None => return Ok(0),
    };

    MEMPTRS.remove(&tid).ok();

    // SAFETY: reading user pointer from memptr location
    let addr: u64 = unsafe { bpf_probe_read_user(memptr64 as *const u64)? };

    Ok(gen_alloc_exit2(ctx, addr))
}

#[uprobe]
pub fn aligned_alloc_enter(ctx: ProbeContext) -> i32 {
    let size: u64 = ctx.arg(1).unwrap_or(0);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn aligned_alloc_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn valloc_enter(ctx: ProbeContext) -> i32 {
    let size: u64 = ctx.arg(0).unwrap_or(0);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn valloc_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn memalign_enter(ctx: ProbeContext) -> i32 {
    let size: u64 = ctx.arg(1).unwrap_or(0);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn memalign_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

#[uprobe]
pub fn pvalloc_enter(ctx: ProbeContext) -> i32 {
    let size: u64 = ctx.arg(0).unwrap_or(0);
    gen_alloc_enter(size)
}

#[uretprobe]
pub fn pvalloc_exit(ctx: RetProbeContext) -> i32 {
    gen_alloc_exit(&ctx)
}

// --- Tracepoint entry points (CO-RE: bpf_probe_read_kernel at offsets 0/8) ---

#[tracepoint(category = "kmem", name = "kmalloc")]
pub fn memleak__kmalloc(ctx: TracePointContext) -> i32 {
    match try_memleak__kmalloc(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memleak__kmalloc(ctx: &TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr from tracepoint context via probe_read_kernel
    let ptr: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(0) as *const u64)? };
    // SAFETY: reading bytes_alloc from tracepoint context via probe_read_kernel
    let bytes_alloc: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(8) as *const u64)? };

    if wa_missing_free.load() != 0 {
        gen_free_enter(ptr);
    }
    gen_alloc_enter(bytes_alloc);
    Ok(gen_alloc_exit2(ctx, ptr))
}

#[tracepoint(category = "kmem", name = "kmalloc_node")]
pub fn memleak__kmalloc_node(ctx: TracePointContext) -> i32 {
    match try_memleak__kmalloc_node(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memleak__kmalloc_node(ctx: &TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr from tracepoint context via probe_read_kernel
    let ptr: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(0) as *const u64)? };
    // SAFETY: reading bytes_alloc from tracepoint context via probe_read_kernel
    let bytes_alloc: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(8) as *const u64)? };

    if wa_missing_free.load() != 0 {
        gen_free_enter(ptr);
    }
    gen_alloc_enter(bytes_alloc);
    Ok(gen_alloc_exit2(ctx, ptr))
}

#[tracepoint(category = "kmem", name = "kfree")]
pub fn memleak__kfree(ctx: TracePointContext) -> i32 {
    match try_memleak__kfree(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memleak__kfree(ctx: &TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr from tracepoint context via probe_read_kernel
    let ptr: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr as *const u64)? };
    Ok(gen_free_enter(ptr))
}

#[tracepoint(category = "kmem", name = "kmem_cache_alloc")]
pub fn memleak__kmem_cache_alloc(ctx: TracePointContext) -> i32 {
    match try_memleak__kmem_cache_alloc(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memleak__kmem_cache_alloc(ctx: &TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr from tracepoint context via probe_read_kernel
    let ptr: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(0) as *const u64)? };
    // SAFETY: reading bytes_alloc from tracepoint context via probe_read_kernel
    let bytes_alloc: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(8) as *const u64)? };

    if wa_missing_free.load() != 0 {
        gen_free_enter(ptr);
    }
    gen_alloc_enter(bytes_alloc);
    Ok(gen_alloc_exit2(ctx, ptr))
}

#[tracepoint(category = "kmem", name = "kmem_cache_alloc_node")]
pub fn memleak__kmem_cache_alloc_node(ctx: TracePointContext) -> i32 {
    match try_memleak__kmem_cache_alloc_node(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memleak__kmem_cache_alloc_node(ctx: &TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr from tracepoint context via probe_read_kernel
    let ptr: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(0) as *const u64)? };
    // SAFETY: reading bytes_alloc from tracepoint context via probe_read_kernel
    let bytes_alloc: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr.wrapping_add(8) as *const u64)? };

    if wa_missing_free.load() != 0 {
        gen_free_enter(ptr);
    }
    gen_alloc_enter(bytes_alloc);
    Ok(gen_alloc_exit2(ctx, ptr))
}

#[tracepoint(category = "kmem", name = "kmem_cache_free")]
pub fn memleak__kmem_cache_free(ctx: TracePointContext) -> i32 {
    match try_memleak__kmem_cache_free(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memleak__kmem_cache_free(ctx: &TracePointContext) -> Result<i32, i64> {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr from tracepoint context via probe_read_kernel
    let ptr: u64 = unsafe { bpf_probe_read_kernel(ctx_ptr as *const u64)? };
    Ok(gen_free_enter(ptr))
}

// --- Tracepoint entry points (non-CO-RE: direct reads) ---

#[tracepoint(category = "kmem", name = "mm_page_alloc")]
pub fn memleak__mm_page_alloc(ctx: TracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading order at offset 16 from tracepoint context
    let order: u32 = unsafe { *(ctx_ptr.wrapping_add(16) as *const u32) };
    let size = page_size.load() << (order as u64);
    gen_alloc_enter(size);
    // SAFETY: reading pfn at offset 8 from tracepoint context
    let pfn: u64 = unsafe { *(ctx_ptr.wrapping_add(8) as *const u64) };
    gen_alloc_exit2(&ctx, pfn)
}

#[tracepoint(category = "kmem", name = "mm_page_free")]
pub fn memleak__mm_page_free(ctx: TracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading pfn at offset 8 from tracepoint context
    let pfn: u64 = unsafe { *(ctx_ptr.wrapping_add(8) as *const u64) };
    gen_free_enter(pfn)
}

#[tracepoint(category = "percpu", name = "percpu_alloc_percpu")]
pub fn memleak__percpu_alloc_percpu(ctx: TracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading bytes_alloc at offset 64 from tracepoint context
    let bytes_alloc: u64 = unsafe { *(ctx_ptr.wrapping_add(64) as *const u64) };
    gen_alloc_enter(bytes_alloc);
    // SAFETY: reading ptr at offset 56 from tracepoint context
    let ptr: u64 = unsafe { *(ctx_ptr.wrapping_add(56) as *const u64) };
    gen_alloc_exit2(&ctx, ptr)
}

#[tracepoint(category = "percpu", name = "percpu_free_percpu")]
pub fn memleak__percpu_free_percpu(ctx: TracePointContext) -> i32 {
    let ctx_ptr = ctx.as_ptr() as *const u8;
    // SAFETY: reading ptr at offset 24 from tracepoint context
    let ptr: u64 = unsafe { *(ctx_ptr.wrapping_add(24) as *const u64) };
    gen_free_enter(ptr)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
