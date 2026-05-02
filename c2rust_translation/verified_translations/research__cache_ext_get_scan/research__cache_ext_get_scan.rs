#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::helpers;
use aya_ebpf::programs::FExitContext;
use aya_ebpf::cty::*;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const INT64_MAX: i64 = 9223372036854775807;
const FMODE_CREATED: u32 = 0x100000;
const BPF_PATH_MAX: usize = 128;

#[repr(C)]
#[derive(Copy, Clone)]
struct FolioMetadata {
    accesses: u64,
    last_access_time: u64,
    touched_by_scan: u8,
}

#[repr(C)]
struct SamplingOptions {
    sample_size: u32,
}

#[map(name = "scan_pids")]
static SCAN_PIDS: HashMap<i32, u8> = HashMap::with_max_entries(100, 0);

#[map(name = "folio_metadata_map")]
static FOLIO_METADATA_MAP: HashMap<u64, FolioMetadata> = HashMap::with_max_entries(4000000, 0);

#[map(name = "sampling_list_map")]
static SAMPLING_LIST_MAP: Array<u64> = Array::with_max_entries(2, 0);

#[map(name = "stats")]
static STATS: HashMap<[u8; 256], i64> = HashMap::with_max_entries(256, 0);

#[map(name = "inode_watchlist")]
static INODE_WATCHLIST: HashMap<u64, u8> = HashMap::with_max_entries(200000, 0);

const fn stat_key(s: &[u8]) -> [u8; 256] {
    let mut arr = [0u8; 256];
    let mut i = 0;
    while i < s.len() {
        arr[i] = s[i];
        i += 1;
    }
    arr
}

#[no_mangle]
#[link_section = ".data"]
static STAT_SCAN_PAGES: [u8; 256] = stat_key(b"scan_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_TOTAL_PAGES: [u8; 256] = stat_key(b"total_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_EVICTED_SCAN_PAGES: [u8; 256] = stat_key(b"evicted_scan_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_EVICTED_TOTAL_PAGES: [u8; 256] = stat_key(b"evicted_total_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_INSERTED_SCAN_PAGES: [u8; 256] = stat_key(b"inserted_scan_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_INSERTED_TOTAL_PAGES: [u8; 256] = stat_key(b"inserted_total_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_ACCESSED_SCAN_PAGES: [u8; 256] = stat_key(b"accessed_scan_pages");
#[no_mangle]
#[link_section = ".data"]
static STAT_ACCESSED_TOTAL_PAGES: [u8; 256] = stat_key(b"accessed_total_pages");

#[no_mangle]
#[link_section = ".bss"]
static mut scan_pages: i64 = 0;

#[no_mangle]
#[link_section = ".rodata"]
static watch_dir_path: [u8; BPF_PATH_MAX] = [0u8; BPF_PATH_MAX];

#[no_mangle]
static watch_dir_path_len: Global<u64> = Global::new(0);

extern "C" {
    fn bpf_cache_ext_ds_registry_new_list(memcg: *const c_void) -> u64;
    fn bpf_cache_ext_list_add_tail(list: u64, folio: *const c_void) -> c_int;
    fn bpf_cache_ext_list_del(folio: *const c_void) -> c_int;
    fn bpf_cache_ext_list_sample(
        memcg: *const c_void,
        list: u64,
        score_fn: unsafe extern "C" fn(*const c_void) -> i64,
        opts: *const SamplingOptions,
        eviction_ctx: *const c_void,
    ) -> c_int;
}

#[inline(always)]
fn inode_in_watchlist(inode_no: u64) -> bool {
    // SAFETY: HashMap::get is pub unsafe fn
    unsafe { INODE_WATCHLIST.get(&inode_no) }.is_some()
}

#[inline(always)]
fn is_folio_relevant(folio: u64) -> bool {
    if folio == 0 {
        return false;
    }
    // SAFETY: reading folio->mapping at kernel struct offset 24
    let mapping = unsafe { *((folio + 24) as *const u64) };
    if mapping == 0 {
        return false;
    }
    // SAFETY: reading mapping->host at kernel struct offset 0
    let host = unsafe { *(mapping as *const u64) };
    if host == 0 {
        return false;
    }
    // SAFETY: reading inode->i_ino at kernel struct offset 80
    let i_ino = unsafe { *((host + 80) as *const u64) };
    inode_in_watchlist(i_ino)
}

#[inline(always)]
fn is_scanning_pid() -> bool {
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFFFFFF) as i32;
    // SAFETY: HashMap::get is pub unsafe fn
    unsafe { SCAN_PIDS.get(&pid) }.is_some()
}

#[inline(always)]
fn get_sampling_list(list_type: u32) -> u64 {
    match SAMPLING_LIST_MAP.get_ptr(list_type) {
        Some(p) => {
            // SAFETY: reading u64 from valid array map pointer
            unsafe { *p }
        }
        None => 0,
    }
}

#[inline(never)]
unsafe extern "C" fn bpf_lfu_score_fn(a: *const c_void) -> i64 {
    // SAFETY: reading cache_ext_list_node->folio at offset 0
    let folio = unsafe { *(a as *const u64) };
    let key = folio;
    // SAFETY: HashMap::get is pub unsafe fn
    let meta = match unsafe { FOLIO_METADATA_MAP.get(&key) } {
        Some(m) => m,
        None => return INT64_MAX,
    };
    let mut score = meta.accesses as i64;

    // SAFETY: reading folio->mapping at offset 24
    let mapping = unsafe { *((folio + 24) as *const u64) };
    if mapping != 0 {
        // SAFETY: reading mapping->host at offset 0
        let host = unsafe { *(mapping as *const u64) };
        if host != 0 {
            // SAFETY: reading folio->page.flags at offset 0
            let flags = unsafe { *(folio as *const u64) };
            if flags & 64 == 0 {
                // SAFETY: reading folio->index at offset 32
                let page_index = unsafe { *((folio + 32) as *const u64) };
                // SAFETY: reading inode->i_size at offset 96
                let file_size = unsafe { *((host + 96) as *const u64) };
                let last_page_index = (file_size + 4095) / 4096 - 1;
                if page_index == last_page_index {
                    score += 100000;
                }
            }
        }
    }

    score
}

#[no_mangle]
#[link_section = "struct_ops.s/mixed_init"]
pub fn mixed_init(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (memcg) from struct_ops context
    let memcg = unsafe { *(ctx as *const u64) } as *const c_void;

    let mut list_type: u32 = 0;
    while list_type < 2 {
        // SAFETY: calling kernel kfunc to create sampling list
        let sampling_list = unsafe { bpf_cache_ext_ds_registry_new_list(memcg) };
        if sampling_list == 0 {
            return -1;
        }
        match SAMPLING_LIST_MAP.get_ptr_mut(list_type) {
            Some(p) => {
                // SAFETY: writing sampling list handle to valid array map pointer
                unsafe { *p = sampling_list };
            }
            None => return -1,
        }
        list_type += 1;
    }
    0
}

#[no_mangle]
#[link_section = "struct_ops/mixed_folio_added"]
pub fn mixed_folio_added(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (folio) from struct_ops context
    let folio = unsafe { *(ctx as *const u64) };

    if !is_folio_relevant(folio) {
        return 0;
    }

    let mut list_type: u32 = 0;
    let touched_by_scan = is_scanning_pid();
    if touched_by_scan {
        list_type = 1;
    }

    let sampling_list = get_sampling_list(list_type);
    if sampling_list == 0 {
        return 0;
    }

    // SAFETY: calling kernel kfunc to add folio to list
    let ret = unsafe { bpf_cache_ext_list_add_tail(sampling_list, folio as *const c_void) };
    if ret != 0 {
        return 0;
    }

    if touched_by_scan {
        // SAFETY: creating atomic from BSS global pointer
        let atomic = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(scan_pages)) };
        atomic.fetch_add(1, Ordering::Relaxed);
    }

    let key = folio;
    // SAFETY: calling bpf_ktime_get_ns
    let ktime = unsafe { helpers::bpf_ktime_get_ns() };
    let new_meta = FolioMetadata {
        accesses: 1,
        last_access_time: ktime,
        touched_by_scan: touched_by_scan as u8,
    };
    FOLIO_METADATA_MAP.insert(&key, &new_meta, 0).ok();

    0
}

#[no_mangle]
#[link_section = "struct_ops/mixed_folio_accessed"]
pub fn mixed_folio_accessed(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (folio) from struct_ops context
    let folio = unsafe { *(ctx as *const u64) };

    if !is_folio_relevant(folio) {
        return 0;
    }

    let key = folio;
    // SAFETY: HashMap::get is pub unsafe fn
    if unsafe { FOLIO_METADATA_MAP.get(&key) }.is_none() {
        let new_meta = FolioMetadata {
            accesses: 0,
            last_access_time: 0,
            touched_by_scan: 0,
        };
        if FOLIO_METADATA_MAP.insert(&key, &new_meta, 0).is_err() {
            return 0;
        }
        // SAFETY: HashMap::get is pub unsafe fn
        if unsafe { FOLIO_METADATA_MAP.get(&key) }.is_none() {
            return 0;
        }
    }

    let ptr = match FOLIO_METADATA_MAP.get_ptr_mut(&key) {
        Some(p) => p as *mut u8,
        None => return 0,
    };
    // SAFETY: accesses is at offset 0 of FolioMetadata, creating atomic from valid map pointer
    let accesses_atomic = unsafe { AtomicU64::from_ptr(ptr as *mut u64) };
    accesses_atomic.fetch_add(1, Ordering::Relaxed);
    // SAFETY: last_access_time is at offset 8 of FolioMetadata, writing to valid map pointer
    unsafe { *((ptr as *mut u64).add(1)) = helpers::bpf_ktime_get_ns() };

    0
}

#[no_mangle]
#[link_section = "struct_ops/mixed_folio_evicted"]
pub fn mixed_folio_evicted(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (folio) from struct_ops context
    let folio = unsafe { *(ctx as *const u64) };

    // SAFETY: calling kernel kfunc to delete folio from list
    unsafe { bpf_cache_ext_list_del(folio as *const c_void) };

    let key = folio;
    let mut touched_by_scan = false;
    // SAFETY: HashMap::get is pub unsafe fn
    if let Some(meta) = unsafe { FOLIO_METADATA_MAP.get(&key) } {
        touched_by_scan = meta.touched_by_scan != 0;
    }
    FOLIO_METADATA_MAP.remove(&key).ok();

    if touched_by_scan {
        // SAFETY: creating atomic from BSS global pointer
        let atomic = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(scan_pages)) };
        atomic.fetch_sub(1, Ordering::Relaxed);
    }

    0
}

#[no_mangle]
#[link_section = "struct_ops/mixed_evict_folios"]
pub fn mixed_evict_folios(ctx: *mut c_void) -> c_int {
    // SAFETY: reading BSS global
    let num_scan_pages = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(scan_pages)) };
    if num_scan_pages == 0 {
        return 0;
    }

    // SAFETY: reading first arg (eviction_ctx) from struct_ops context
    let eviction_ctx = unsafe { *(ctx as *const u64) } as *const c_void;
    // SAFETY: reading second arg (memcg) from struct_ops context
    let memcg = unsafe { *((ctx as *const u64).add(1)) } as *const c_void;

    let mut list_type: u32 = 1;
    if num_scan_pages < 5000 {
        list_type = 0;
    }

    let sampling_list = get_sampling_list(list_type);
    if sampling_list == 0 {
        return 0;
    }

    let sampling_opts = SamplingOptions { sample_size: 5 };

    // SAFETY: calling kernel kfunc with callback
    unsafe {
        bpf_cache_ext_list_sample(
            memcg,
            sampling_list,
            bpf_lfu_score_fn,
            &sampling_opts,
            eviction_ctx,
        )
    };

    0
}

#[fexit(function = "vfs_open")]
pub fn vfs_open_exit(ctx: FExitContext) -> i32 {
    match try_vfs_open_exit(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_open_exit(ctx: FExitContext) -> Result<i32, i64> {
    let ret: i64 = ctx.arg(2);
    if ret != 0 {
        return Ok(0);
    }

    let file: u64 = ctx.arg(1);
    // SAFETY: reading file->f_mode at kernel struct offset 20
    let f_mode: u32 = unsafe { *((file + 20) as *const u32) };
    if f_mode & FMODE_CREATED == 0 {
        return Ok(0);
    }

    let path_ptr: u64 = ctx.arg(0);

    let mut filepath = [0u8; BPF_PATH_MAX];
    // SAFETY: calling bpf_d_path helper
    let err = unsafe {
        helpers::bpf_d_path(
            path_ptr as *mut _,
            filepath.as_mut_ptr() as *mut _,
            BPF_PATH_MAX as u32,
        )
    };
    if err < 0 {
        return Ok(0);
    }

    // SAFETY: reading file->f_inode at kernel struct offset 168
    let f_inode: u64 = unsafe { *((file + 168) as *const u64) };
    // SAFETY: reading inode->i_ino at kernel struct offset 80
    let i_ino: u64 = unsafe { *((f_inode + 80) as *const u64) };

    // SAFETY: HashMap::get is pub unsafe fn
    if unsafe { INODE_WATCHLIST.get(&i_ino) }.is_some() {
        match INODE_WATCHLIST.remove(&i_ino) {
            Ok(()) => {}
            Err(_) => return Ok(0),
        }
    }

    let dir_len = watch_dir_path_len.load();
    if dir_len == 0 {
        return Ok(0);
    }

    let fp = filepath.as_ptr();
    let wp = watch_dir_path.as_ptr();
    let n = if dir_len > BPF_PATH_MAX as u64 {
        BPF_PATH_MAX
    } else {
        dir_len as usize
    };
    let mut matched = true;
    for i in 0..BPF_PATH_MAX {
        if i >= n {
            break;
        }
        // SAFETY: reading byte from stack filepath buffer within bounds
        let c1 = unsafe { *fp.add(i) };
        // SAFETY: reading byte from rodata watch_dir_path within bounds
        let c2 = unsafe { *wp.add(i) };
        if c1 != c2 {
            matched = false;
            break;
        }
        if c1 == 0 {
            break;
        }
    }

    if !matched {
        return Ok(0);
    }

    let zero: u8 = 0;
    INODE_WATCHLIST.insert(&i_ino, &zero, 0).ok();

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
