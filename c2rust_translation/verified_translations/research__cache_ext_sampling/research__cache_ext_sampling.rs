#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::*;
use aya_ebpf::cty::*;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicU64, Ordering};

const FMODE_CREATED: u32 = 0x100000;
const BPF_PATH_MAX: usize = 128;
const INT64_MAX: i64 = 0x7FFFFFFFFFFFFFFF;
const PG_UPTODATE_MASK: u64 = 1 << 3;
const PG_LRU_MASK: u64 = 1 << 5;
const PG_DIRTY_MASK: u64 = 1 << 4;
const PG_WRITEBACK_MASK: u64 = 1 << 1;

#[repr(C)]
#[derive(Copy, Clone)]
struct FolioMetadata {
    accesses: u64,
}

#[repr(C)]
struct SamplingOpts {
    sample_size: u32,
}

#[map(name = "folio_metadata_map")]
static FOLIO_METADATA_MAP: HashMap<u64, FolioMetadata> = HashMap::with_max_entries(4000000, 0);

#[map(name = "stats")]
static STATS: HashMap<[u8; 256], i64> = HashMap::with_max_entries(256, 0);

#[map(name = "inode_watchlist")]
static INODE_WATCHLIST: HashMap<u64, u8> = HashMap::with_max_entries(200000, 0);

const fn make_stat_name(s: &[u8]) -> [u8; 256] {
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
static mut STAT_SCAN_PAGES: [u8; 256] = make_stat_name(b"scan_pages");

#[no_mangle]
#[link_section = ".data"]
static mut STAT_TOTAL_PAGES: [u8; 256] = make_stat_name(b"total_pages");

#[no_mangle]
#[link_section = ".data"]
static mut STAT_EVICTED_SCAN_PAGES: [u8; 256] = make_stat_name(b"evicted_scan_pages");

#[no_mangle]
#[link_section = ".data"]
static mut STAT_EVICTED_TOTAL_PAGES: [u8; 256] = make_stat_name(b"evicted_total_pages");

#[no_mangle]
#[link_section = ".bss"]
static mut sampling_list: u64 = 0;

#[no_mangle]
static watch_dir_path: [u8; BPF_PATH_MAX] = [0u8; BPF_PATH_MAX];

#[no_mangle]
static watch_dir_path_len: Global<u64> = Global::new(0);

extern "C" {
    fn bpf_cache_ext_ds_registry_new_list(memcg: *mut c_void) -> u64;
    fn bpf_cache_ext_list_add_tail(list: u64, folio: *mut c_void) -> c_int;
    fn bpf_cache_ext_list_sample(
        memcg: *mut c_void,
        list: u64,
        score_fn: *const c_void,
        opts: *mut c_void,
        ctx: *mut c_void,
    ) -> c_int;
    fn bpf_d_path(path: *mut c_void, buf: *mut c_void, sz: u32) -> c_long;
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
    // SAFETY: reading folio->mapping at offset 24
    let mapping: u64 = unsafe { *((folio + 24) as *const u64) };
    if mapping == 0 {
        return false;
    }
    // SAFETY: reading mapping->host at offset 0
    let host: u64 = unsafe { *(mapping as *const u64) };
    if host == 0 {
        return false;
    }
    // SAFETY: reading host->i_ino at offset 80
    let i_ino: u64 = unsafe { *((host + 80) as *const u64) };
    inode_in_watchlist(i_ino)
}

#[no_mangle]
#[link_section = "struct_ops.s/sampling_init"]
pub fn sampling_init(ctx: *mut c_void) -> i32 {
    // SAFETY: reading first arg (memcg) from struct_ops context
    let memcg = unsafe { *(ctx as *const u64) } as *mut c_void;
    // SAFETY: calling kfunc to create new list
    let list = unsafe { bpf_cache_ext_ds_registry_new_list(memcg) };
    let ptr = core::ptr::addr_of_mut!(sampling_list);
    // SAFETY: writing to BSS global sampling_list
    unsafe { ptr.write_volatile(list) };
    if list == 0 {
        return -1;
    }
    0
}

#[no_mangle]
#[link_section = "struct_ops/sampling_folio_added"]
pub fn sampling_folio_added(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (folio) from struct_ops context
    let folio = unsafe { *(ctx as *const u64) };
    if !is_folio_relevant(folio) {
        return 0;
    }
    let list_ptr = core::ptr::addr_of!(sampling_list);
    // SAFETY: reading BSS global sampling_list
    let list = unsafe { list_ptr.read_volatile() };
    // SAFETY: calling kfunc to add folio to list
    let ret = unsafe { bpf_cache_ext_list_add_tail(list, folio as *mut c_void) };
    if ret != 0 {
        return 0;
    }
    let key = folio;
    let new_meta = FolioMetadata { accesses: 1 };
    let _ = FOLIO_METADATA_MAP.insert(&key, &new_meta, 0);
    0
}

#[no_mangle]
#[link_section = "struct_ops/sampling_folio_accessed"]
pub fn sampling_folio_accessed(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (folio) from struct_ops context
    let folio = unsafe { *(ctx as *const u64) };
    if !is_folio_relevant(folio) {
        return 0;
    }
    let key = folio;
    // SAFETY: HashMap::get is pub unsafe fn
    let found = unsafe { FOLIO_METADATA_MAP.get(&key) }.is_some();
    if !found {
        let new_meta = FolioMetadata { accesses: 0 };
        match FOLIO_METADATA_MAP.insert(&key, &new_meta, 0) {
            Ok(()) => {}
            Err(_) => return 0,
        }
        // SAFETY: HashMap::get to verify entry was created
        if unsafe { FOLIO_METADATA_MAP.get(&key) }.is_none() {
            return 0;
        }
    }
    if let Some(ptr) = FOLIO_METADATA_MAP.get_ptr_mut(&key) {
        // SAFETY: creating atomic from valid map pointer for accesses field
        let atomic = unsafe { AtomicU64::from_ptr(ptr as *mut u64) };
        atomic.fetch_add(1, Ordering::Relaxed);
    }
    0
}

#[no_mangle]
#[link_section = "struct_ops/sampling_folio_evicted"]
pub fn sampling_folio_evicted(ctx: *mut c_void) -> c_int {
    // SAFETY: reading first arg (folio) from struct_ops context
    let folio = unsafe { *(ctx as *const u64) };
    let _ = FOLIO_METADATA_MAP.remove(&folio);
    0
}

#[no_mangle]
fn bpf_lfu_score_fn(node: *mut c_void) -> i64 {
    // SAFETY: reading node->folio at offset 0
    let folio = unsafe { *(node as *const u64) };
    let key = folio;
    // SAFETY: HashMap::get is pub unsafe fn
    let meta = match unsafe { FOLIO_METADATA_MAP.get(&key) } {
        Some(m) => m,
        None => return INT64_MAX,
    };
    let score = meta.accesses as i64;
    // SAFETY: reading page flags at folio offset 0 (page[0].flags)
    let flags: u64 = unsafe { *(folio as *const u64) };
    if flags & PG_UPTODATE_MASK == 0 {
        return INT64_MAX;
    }
    if flags & PG_LRU_MASK == 0 {
        return INT64_MAX;
    }
    if flags & PG_DIRTY_MASK != 0 {
        return INT64_MAX;
    }
    if flags & PG_WRITEBACK_MASK != 0 {
        return INT64_MAX;
    }
    score
}

#[no_mangle]
#[link_section = "struct_ops/sampling_evict_folios"]
pub fn sampling_evict_folios(ctx: *mut c_void) -> c_int {
    // SAFETY: reading second arg (memcg) from struct_ops context at offset 8
    let memcg = unsafe { *((ctx as usize + 8) as *const u64) } as *mut c_void;
    // SAFETY: reading first arg (eviction_ctx) from struct_ops context
    let eviction_ctx = unsafe { *(ctx as *const u64) } as *mut c_void;
    let mut opts = SamplingOpts { sample_size: 20 };
    let list_ptr = core::ptr::addr_of!(sampling_list);
    // SAFETY: reading BSS global sampling_list
    let list = unsafe { list_ptr.read_volatile() };
    // SAFETY: calling kfunc to sample and evict folios
    unsafe {
        bpf_cache_ext_list_sample(
            memcg,
            list,
            bpf_lfu_score_fn as *const c_void,
            &mut opts as *mut SamplingOpts as *mut c_void,
            eviction_ctx,
        )
    };
    0
}

#[fexit(function = "vfs_open")]
pub fn vfs_open_exit(ctx: FExitContext) -> i32 {
    match try_vfs_open_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_vfs_open_exit(ctx: FExitContext) -> Result<i32, i64> {
    let ret: i64 = ctx.arg(2);
    if ret != 0 {
        return Ok(0);
    }
    let file: u64 = ctx.arg(1);
    // SAFETY: reading file->f_mode at offset 20
    let f_mode: u32 = unsafe { *((file + 20) as *const u32) };
    if f_mode & FMODE_CREATED == 0 {
        return Ok(0);
    }
    let path_ptr: u64 = ctx.arg(0);
    let mut filepath = [0u8; BPF_PATH_MAX];
    // SAFETY: calling bpf_d_path helper to get file path
    let err = unsafe {
        bpf_d_path(
            path_ptr as *mut c_void,
            filepath.as_mut_ptr() as *mut c_void,
            BPF_PATH_MAX as u32,
        )
    };
    if err < 0 {
        return Ok(0);
    }
    // SAFETY: reading file->f_inode at offset 168
    let f_inode: u64 = unsafe { *((file + 168) as *const u64) };
    // SAFETY: reading inode->i_ino at offset 80
    let inode_no: u64 = unsafe { *((f_inode + 80) as *const u64) };
    // SAFETY: HashMap::get to check if inode was previously in watchlist
    if unsafe { INODE_WATCHLIST.get(&inode_no) }.is_some() {
        match INODE_WATCHLIST.remove(&inode_no) {
            Ok(()) => {}
            Err(_) => return Ok(0),
        }
    }
    let path_len = watch_dir_path_len.load();
    if path_len == 0 {
        return Ok(0);
    }
    if !strncmp_eq(&filepath, path_len as u32) {
        return Ok(0);
    }
    let zero: u8 = 0;
    let _ = INODE_WATCHLIST.insert(&inode_no, &zero, 0);
    Ok(0)
}

#[inline(always)]
fn strncmp_eq(s1: &[u8; BPF_PATH_MAX], mut n: u32) -> bool {
    let base = watch_dir_path.as_ptr();
    let mut i: usize = 0;
    while n > 0 && i < BPF_PATH_MAX {
        let c1 = s1[i];
        // SAFETY: reading byte i from .rodata watch_dir_path within bounds
        let c2 = unsafe { core::ptr::read_volatile(base.wrapping_add(i)) };
        if c1 == 0 {
            return c2 == 0;
        }
        if c1 != c2 {
            return false;
        }
        i += 1;
        n -= 1;
    }
    n == 0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
