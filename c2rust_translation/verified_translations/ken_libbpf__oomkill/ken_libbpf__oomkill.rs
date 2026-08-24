#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;

#[map(name = "oom_kills_total")]
static OOM_KILLS_TOTAL: PerfEventArray<u64> = PerfEventArray::new(0);

#[kprobe]
pub fn kprobe__oom_kill_process(ctx: ProbeContext) -> u32 {
    match try_kprobe__oom_kill_process(&ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 0,
    }
}

fn try_kprobe__oom_kill_process(ctx: &ProbeContext) -> Result<i32, i64> {
    let mut cgroup_id: u64 = 0;

    // arg0 = struct oom_control *oc
    let oc: *const c_void = ctx.arg(0).ok_or(1i64)?;

    // Read oc->memcg (offset depends on kernel, but BPF_CORE_READ resolves it)
    // In non-CO-RE eBPF, we read the pointer field at a known offset
    // BPF_CORE_READ(oc, memcg) -> probe_read_kernel(&oc->memcg)
    // SAFETY: reading memcg pointer from oom_control struct
    let mcg: *const c_void = unsafe { bpf_probe_read_kernel(&(*(oc as *const OomControl)).memcg as *const *const c_void)? };

    if !mcg.is_null() {
        // BPF_CORE_READ(mcg, css.cgroup, kn, id)
        // Read mcg->css.cgroup
        // SAFETY: reading css.cgroup pointer from mem_cgroup
        let cgroup: *const c_void = unsafe { bpf_probe_read_kernel(&(*(mcg as *const MemCgroup)).css_cgroup as *const *const c_void)? };
        // Read cgroup->kn
        // SAFETY: reading kn pointer from cgroup
        let kn: *const c_void = unsafe { bpf_probe_read_kernel(&(*(cgroup as *const Cgroup)).kn as *const *const c_void)? };
        // Read kn->id
        // SAFETY: reading id from kernfs_node
        cgroup_id = unsafe { bpf_probe_read_kernel(&(*(kn as *const KernfsNode)).id as *const u64)? };
    }

    OOM_KILLS_TOTAL.output(ctx, &cgroup_id, 0);

    Ok(0)
}

// Struct layout stubs for field offset access
// These must match the kernel struct layouts
#[repr(C)]
struct OomControl {
    _pad: [u8; 8],         // zonelist pointer
    _pad2: [u8; 8],        // nodemask pointer
    memcg: *const c_void,  // struct mem_cgroup *
}

#[repr(C)]
struct MemCgroup {
    css_cgroup: *const c_void, // css.cgroup - first field of cgroup_subsys_state is a pointer to cgroup
}

#[repr(C)]
struct Cgroup {
    _pad: [u8; 0],
    kn: *const c_void, // struct kernfs_node *
}

#[repr(C)]
struct KernfsNode {
    _pad: [u8; 0],
    id: u64,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
