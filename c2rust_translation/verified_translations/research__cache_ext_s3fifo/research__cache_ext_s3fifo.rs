#![no_std]
#![no_main]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unused_unsafe)]
#![deny(unused_must_use)]

use aya_ebpf::macros::*;
use aya_ebpf::maps::*;
use aya_ebpf::programs::FExitContext;
use aya_ebpf::cty::*;
use aya_ebpf::Global;
use core::sync::atomic::{AtomicI64, Ordering};

const CACHE_EXT_CONTINUE_ITER: i32 = 0;
const CACHE_EXT_EVICT_NODE: i32 = 1;
const CACHE_EXT_ITERATE_SELF: u64 = 0;
const CACHE_EXT_ITERATE_TAIL: u64 = 1;
const FMODE_CREATED: u32 = 0x100000;
const BPF_PATH_MAX: usize = 128;

const PG_UPTODATE_MASK: u64 = 1 << 3;
const PG_WRITEBACK_MASK: u64 = 1 << 1;
const PG_DIRTY_MASK: u64 = 1 << 4;
const PG_LRU_MASK: u64 = 1 << 5;

#[repr(C)]
#[derive(Copy, Clone)]
struct FolioMetadata {
    freq: i64,
    in_main: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct GhostEntry {
    address_space: u64,
    offset: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CacheExtIterateOpts {
    continue_list: u64,
    continue_mode: u64,
    evict_list: u64,
    evict_mode: u32,
    nr_folios_continue: i32,
}

#[map(name = "folio_metadata_map")]
static FOLIO_METADATA_MAP: HashMap<u64, FolioMetadata> = HashMap::with_max_entries(4_000_000, 0);

#[map(name = "ghost_map")]
static GHOST_MAP: LruHashMap<GhostEntry, u8> = LruHashMap::with_max_entries(51200, 2);

#[map(name = "inode_watchlist")]
static INODE_WATCHLIST: HashMap<u64, u8> = HashMap::with_max_entries(200_000, 0);

#[no_mangle]
#[link_section = ".bss"]
static mut main_list: u64 = 0;

#[no_mangle]
#[link_section = ".bss"]
static mut small_list: u64 = 0;

#[no_mangle]
#[link_section = ".bss"]
static mut small_list_size: i64 = 0;

#[no_mangle]
#[link_section = ".bss"]
static mut main_list_size: i64 = 0;

#[no_mangle]
static cache_size: Global<u64> = Global::new(0);

#[no_mangle]
static watch_dir_path: Global<[u8; BPF_PATH_MAX]> = Global::new([0u8; BPF_PATH_MAX]);

#[no_mangle]
static watch_dir_path_len: Global<u64> = Global::new(0);

extern "C" {
    fn bpf_cache_ext_ds_registry_new_list(memcg: *mut c_void) -> u64;
    fn bpf_cache_ext_list_add_tail(list: u64, folio: *mut c_void) -> c_int;
    fn bpf_cache_ext_list_del(folio: *mut c_void) -> c_int;
    fn bpf_cache_ext_list_iterate_extended(
        memcg: *mut c_void,
        list: u64,
        iter_fn: *const c_void,
        opts: *mut CacheExtIterateOpts,
        ctx: *mut c_void,
    ) -> c_int;
}

#[inline(always)]
fn inode_in_watchlist(inode_no: u64) -> bool {
    // SAFETY: HashMap::get is pub unsafe fn
    unsafe { INODE_WATCHLIST.get(&inode_no) }.is_some()
}

#[inline(always)]
fn is_folio_relevant(folio: *const c_void) -> bool {
    if folio.is_null() {
        return false;
    }
    // SAFETY: reading mapping at folio offset 24
    let mapping = unsafe { *((folio as usize + 24) as *const u64) };
    if mapping == 0 {
        return false;
    }
    // SAFETY: reading host at mapping offset 0
    let host = unsafe { *(mapping as *const u64) };
    if host == 0 {
        return false;
    }
    // SAFETY: reading i_ino at inode offset 80
    let i_ino = unsafe { *((host as usize + 80) as *const u64) };
    inode_in_watchlist(i_ino)
}

#[inline(always)]
fn folio_in_ghost(folio: *const c_void) -> bool {
    // SAFETY: reading mapping at folio offset 24
    let mapping = unsafe { *((folio as usize + 24) as *const u64) };
    // SAFETY: reading host at mapping offset 0
    let host = unsafe { *(mapping as *const u64) };
    // SAFETY: reading index at folio offset 32
    let index = unsafe { *((folio as usize + 32) as *const u64) };

    let ghost_key = GhostEntry {
        address_space: host,
        offset: index,
    };

    match GHOST_MAP.remove(&ghost_key) {
        Ok(()) => true,
        Err(e) => e != -2,
    }
}

#[inline(always)]
fn folio_test_flags_ok(folio: *const c_void) -> bool {
    // SAFETY: reading page flags at folio offset 0
    let flags = unsafe { *(folio as *const u64) };
    if flags & PG_UPTODATE_MASK == 0 || flags & PG_LRU_MASK == 0 {
        return false;
    }
    if flags & PG_DIRTY_MASK != 0 || flags & PG_WRITEBACK_MASK != 0 {
        return false;
    }
    true
}

#[inline(always)]
fn strncmp_ptr(s1: &[u8; BPF_PATH_MAX], s2: *const u8, n: usize) -> i32 {
    let limit = if n < BPF_PATH_MAX { n } else { BPF_PATH_MAX };
    let mut i = 0usize;
    while i < limit {
        // SAFETY: s2 points to a valid [u8; BPF_PATH_MAX] global
        let b = unsafe { core::ptr::read_volatile(s2.add(i)) };
        if s1[i] == 0 || s1[i] != b {
            return s1[i] as i32 - b as i32;
        }
        i += 1;
    }
    0
}

#[inline(always)]
fn score_main_iter_impl(node: *mut c_void, threshold: i64) -> i32 {
    // SAFETY: reading folio pointer at node offset 0
    let folio = unsafe { *(node as *const u64) } as *const c_void;
    if !folio_test_flags_ok(folio) {
        return CACHE_EXT_CONTINUE_ITER;
    }

    let key = folio as u64;
    let data_ptr = match FOLIO_METADATA_MAP.get_ptr_mut(&key) {
        Some(ptr) => ptr,
        None => return CACHE_EXT_CONTINUE_ITER,
    };

    // SAFETY: reading freq before atomic subtract
    let old_freq = unsafe { core::ptr::read_volatile(data_ptr as *const i64) };
    // SAFETY: atomic subtract on freq field via map pointer
    let atomic_freq = unsafe { AtomicI64::from_ptr(data_ptr as *mut i64) };
    atomic_freq.fetch_add(-1, Ordering::Relaxed);
    let new_freq = old_freq - 1;

    if new_freq < threshold {
        return CACHE_EXT_EVICT_NODE;
    }

    CACHE_EXT_CONTINUE_ITER
}

#[no_mangle]
fn bpf_s3fifo_score_small_fn(_idx: i32, node: *mut c_void) -> i32 {
    // SAFETY: reading folio pointer at node offset 0
    let folio = unsafe { *(node as *const u64) } as *const c_void;
    if !folio_test_flags_ok(folio) {
        return CACHE_EXT_CONTINUE_ITER;
    }

    let key = folio as u64;
    // SAFETY: HashMap::get is pub unsafe fn
    let data_ref = match unsafe { FOLIO_METADATA_MAP.get(&key) } {
        Some(d) => d,
        None => return CACHE_EXT_CONTINUE_ITER,
    };

    if data_ref.freq > 1 {
        let mut data_copy = *data_ref;
        data_copy.in_main = 1;
        let _ = FOLIO_METADATA_MAP.insert(&key, &data_copy, 0);
        return CACHE_EXT_CONTINUE_ITER;
    }

    CACHE_EXT_EVICT_NODE
}

#[no_mangle]
fn bpf_s3fifo_score_main_iter_fn_0(_idx: i32, node: *mut c_void) -> i32 {
    score_main_iter_impl(node, 0)
}

#[no_mangle]
fn bpf_s3fifo_score_main_iter_fn_1(_idx: i32, node: *mut c_void) -> i32 {
    score_main_iter_impl(node, 1)
}

#[no_mangle]
fn bpf_s3fifo_score_main_iter_fn_2(_idx: i32, node: *mut c_void) -> i32 {
    score_main_iter_impl(node, 2)
}

#[no_mangle]
fn bpf_s3fifo_score_main_iter_fn_3(_idx: i32, node: *mut c_void) -> i32 {
    score_main_iter_impl(node, 3)
}

#[inline(always)]
fn evict_small(eviction_ctx: *mut c_void, memcg: *mut c_void) {
    // SAFETY: reading BSS global main_list
    let ml = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list)) };
    // SAFETY: reading BSS global small_list
    let sl = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(small_list)) };

    let mut opts = CacheExtIterateOpts {
        continue_list: ml,
        continue_mode: CACHE_EXT_ITERATE_TAIL,
        evict_list: CACHE_EXT_ITERATE_SELF,
        evict_mode: CACHE_EXT_ITERATE_TAIL as u32,
        nr_folios_continue: 0,
    };

    // SAFETY: calling kfunc bpf_cache_ext_list_iterate_extended
    let ret = unsafe {
        bpf_cache_ext_list_iterate_extended(
            memcg,
            sl,
            bpf_s3fifo_score_small_fn as *const c_void,
            &mut opts as *mut CacheExtIterateOpts,
            eviction_ctx,
        )
    };
    if ret < 0 {
        return;
    }

    // SAFETY: kfunc modifies nr_folios_continue via pointer; must use read_volatile
    let nr_folios = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(opts.nr_folios_continue))
    } as i64;

    // SAFETY: reading BSS global small_list_size
    let old_sls = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(small_list_size)) };
    // SAFETY: atomic subtract on BSS global small_list_size
    let atomic_sls = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(small_list_size)) };
    atomic_sls.fetch_add(-nr_folios, Ordering::Relaxed);
    if old_sls - nr_folios < 0 {
        // SAFETY: clamping BSS global small_list_size to 0
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(small_list_size), 0) };
    }

    // SAFETY: reading BSS global main_list_size
    let old_mls = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list_size)) };
    // SAFETY: atomic add on BSS global main_list_size
    let atomic_mls = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(main_list_size)) };
    atomic_mls.fetch_add(nr_folios, Ordering::Relaxed);
    if old_mls + nr_folios < 0 {
        // SAFETY: clamping BSS global main_list_size to nr_folios
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(main_list_size), nr_folios) };
    }
}

#[inline(always)]
fn evict_main_iter(eviction_ctx: *mut c_void, memcg: *mut c_void) {
    let mut opts = CacheExtIterateOpts {
        continue_list: CACHE_EXT_ITERATE_SELF,
        continue_mode: CACHE_EXT_ITERATE_TAIL,
        evict_list: CACHE_EXT_ITERATE_SELF,
        evict_mode: CACHE_EXT_ITERATE_TAIL as u32,
        nr_folios_continue: 0,
    };

    // SAFETY: reading BSS global main_list
    let ml = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list)) };
    // SAFETY: calling kfunc (round 0)
    let ret = unsafe {
        bpf_cache_ext_list_iterate_extended(
            memcg,
            ml,
            bpf_s3fifo_score_main_iter_fn_0 as *const c_void,
            &mut opts as *mut CacheExtIterateOpts,
            eviction_ctx,
        )
    };
    if ret < 0 {
        return;
    }

    // SAFETY: reading request_nr_folios_to_evict at eviction_ctx offset 0
    let request = unsafe { *(eviction_ctx as *const i64) };
    // SAFETY: reading nr_folios_to_evict at eviction_ctx offset 8
    let evicted = unsafe { *((eviction_ctx as usize + 8) as *const i64) };
    if evicted >= request {
        return;
    }

    // SAFETY: reading BSS global main_list
    let ml = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list)) };
    // SAFETY: calling kfunc (round 1)
    let ret = unsafe {
        bpf_cache_ext_list_iterate_extended(
            memcg,
            ml,
            bpf_s3fifo_score_main_iter_fn_1 as *const c_void,
            &mut opts as *mut CacheExtIterateOpts,
            eviction_ctx,
        )
    };
    if ret < 0 {
        return;
    }

    // SAFETY: reading request_nr_folios_to_evict at eviction_ctx offset 0
    let request = unsafe { *(eviction_ctx as *const i64) };
    // SAFETY: reading nr_folios_to_evict at eviction_ctx offset 8
    let evicted = unsafe { *((eviction_ctx as usize + 8) as *const i64) };
    if evicted >= request {
        return;
    }

    // SAFETY: reading BSS global main_list
    let ml = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list)) };
    // SAFETY: calling kfunc (round 2)
    let ret = unsafe {
        bpf_cache_ext_list_iterate_extended(
            memcg,
            ml,
            bpf_s3fifo_score_main_iter_fn_2 as *const c_void,
            &mut opts as *mut CacheExtIterateOpts,
            eviction_ctx,
        )
    };
    if ret < 0 {
        return;
    }

    // SAFETY: reading request_nr_folios_to_evict at eviction_ctx offset 0
    let request = unsafe { *(eviction_ctx as *const i64) };
    // SAFETY: reading nr_folios_to_evict at eviction_ctx offset 8
    let evicted = unsafe { *((eviction_ctx as usize + 8) as *const i64) };
    if evicted >= request {
        return;
    }

    // SAFETY: reading BSS global main_list
    let ml = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list)) };
    // SAFETY: calling kfunc (round 3)
    unsafe {
        bpf_cache_ext_list_iterate_extended(
            memcg,
            ml,
            bpf_s3fifo_score_main_iter_fn_3 as *const c_void,
            &mut opts as *mut CacheExtIterateOpts,
            eviction_ctx,
        )
    };
}

#[no_mangle]
#[link_section = "struct_ops.s/s3fifo_init"]
pub fn s3fifo_init(ctx: *mut u64) -> i32 {
    // SAFETY: reading arg 0 (memcg) from struct_ops context
    let memcg = unsafe { *ctx } as *mut c_void;

    // SAFETY: calling kfunc to create main_list
    let ml = unsafe { bpf_cache_ext_ds_registry_new_list(memcg) };
    // SAFETY: writing BSS global main_list
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(main_list), ml) };
    if ml == 0 {
        return -1;
    }

    // SAFETY: calling kfunc to create small_list
    let sl = unsafe { bpf_cache_ext_ds_registry_new_list(memcg) };
    // SAFETY: writing BSS global small_list
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(small_list), sl) };
    if sl == 0 {
        return -1;
    }

    0
}

#[no_mangle]
#[link_section = "struct_ops/s3fifo_evict_folios"]
pub fn s3fifo_evict_folios(ctx: *mut u64) {
    // SAFETY: reading arg 0 (eviction_ctx) from struct_ops context
    let eviction_ctx = unsafe { *ctx } as *mut c_void;
    // SAFETY: reading arg 1 (memcg) from struct_ops context
    let memcg = unsafe { *ctx.add(1) } as *mut c_void;

    // SAFETY: reading BSS global small_list_size
    let sls = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(small_list_size)) };
    // SAFETY: reading BSS global main_list_size
    let mls = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list_size)) };
    let cs = cache_size.load();

    if (sls as u64) >= cs / 15 || mls <= 2 * sls {
        evict_small(eviction_ctx, memcg);
    } else {
        evict_main_iter(eviction_ctx, memcg);
    }
}

#[no_mangle]
#[link_section = "struct_ops/s3fifo_folio_accessed"]
pub fn s3fifo_folio_accessed(ctx: *mut u64) {
    // SAFETY: reading arg 0 (folio) from struct_ops context
    let folio = unsafe { *ctx } as *mut c_void;

    if !is_folio_relevant(folio) {
        return;
    }

    let key = folio as u64;
    let data_ptr = match FOLIO_METADATA_MAP.get_ptr_mut(&key) {
        Some(ptr) => ptr,
        None => return,
    };

    // SAFETY: reading freq before atomic add
    let old_freq = unsafe { core::ptr::read_volatile(data_ptr as *const i64) };
    // SAFETY: atomic add on freq field via map pointer
    let atomic_freq = unsafe { AtomicI64::from_ptr(data_ptr as *mut i64) };
    atomic_freq.fetch_add(1, Ordering::Relaxed);
    if old_freq + 1 > 3 {
        // SAFETY: clamping freq to 3
        unsafe { core::ptr::write_volatile(data_ptr as *mut i64, 3) };
    }
}

#[no_mangle]
#[link_section = "struct_ops/s3fifo_folio_evicted"]
pub fn s3fifo_folio_evicted(ctx: *mut u64) {
    // SAFETY: reading arg 0 (folio) from struct_ops context
    let folio = unsafe { *ctx } as *mut c_void;
    let key = folio as u64;

    // SAFETY: reading mapping at folio offset 24
    let mapping = unsafe { *((folio as usize + 24) as *const u64) };
    // SAFETY: reading host at mapping offset 0
    let host = unsafe { *(mapping as *const u64) };
    // SAFETY: reading index at folio offset 32
    let index = unsafe { *((folio as usize + 32) as *const u64) };

    let ghost_key = GhostEntry {
        address_space: host,
        offset: index,
    };
    let ghost_val: u8 = 0;
    let _ = GHOST_MAP.insert(&ghost_key, &ghost_val, 0);

    // SAFETY: HashMap::get is pub unsafe fn
    let data_ref = match unsafe { FOLIO_METADATA_MAP.get(&key) } {
        Some(d) => d,
        None => return,
    };

    let in_main = data_ref.in_main;

    if in_main != 0 {
        // SAFETY: atomic subtract on BSS global main_list_size
        let atomic = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(main_list_size)) };
        atomic.fetch_add(-1, Ordering::Relaxed);
    } else {
        // SAFETY: atomic subtract on BSS global small_list_size
        let atomic = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(small_list_size)) };
        atomic.fetch_add(-1, Ordering::Relaxed);
    }

    let _ = FOLIO_METADATA_MAP.remove(&key);
}

#[no_mangle]
#[link_section = "struct_ops/s3fifo_folio_added"]
pub fn s3fifo_folio_added(ctx: *mut u64) {
    // SAFETY: reading arg 0 (folio) from struct_ops context
    let folio = unsafe { *ctx } as *mut c_void;

    if !is_folio_relevant(folio) {
        return;
    }

    let key = folio as u64;
    let mut new_meta = FolioMetadata {
        freq: 0,
        in_main: 0,
    };

    let list_to_add;
    if folio_in_ghost(folio) {
        // SAFETY: reading BSS global main_list
        list_to_add = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(main_list)) };
        new_meta.in_main = 1;
        // SAFETY: atomic add on BSS global main_list_size
        let atomic = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(main_list_size)) };
        atomic.fetch_add(1, Ordering::Relaxed);
    } else {
        // SAFETY: reading BSS global small_list
        list_to_add = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(small_list)) };
        new_meta.in_main = 0;
        // SAFETY: atomic add on BSS global small_list_size
        let atomic = unsafe { AtomicI64::from_ptr(core::ptr::addr_of_mut!(small_list_size)) };
        atomic.fetch_add(1, Ordering::Relaxed);
    }

    // SAFETY: calling kfunc bpf_cache_ext_list_add_tail
    let ret = unsafe { bpf_cache_ext_list_add_tail(list_to_add, folio) };
    if ret != 0 {
        return;
    }

    if FOLIO_METADATA_MAP.insert(&key, &new_meta, 0).is_err() {
        // SAFETY: calling kfunc bpf_cache_ext_list_del
        unsafe { bpf_cache_ext_list_del(folio) };
        return;
    }
}

#[fexit(function = "vfs_open")]
pub fn vfs_open_exit(ctx: FExitContext) -> i32 {
    match try_vfs_open_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_vfs_open_exit(ctx: &FExitContext) -> Result<i32, i64> {
    let ret: i64 = ctx.arg(2);
    if ret != 0 {
        return Ok(0);
    }

    let file: u64 = ctx.arg(1);
    // SAFETY: reading f_mode at file offset 20
    let f_mode = unsafe { *((file as usize + 20) as *const u32) };
    if f_mode & FMODE_CREATED == 0 {
        return Ok(0);
    }

    let path: u64 = ctx.arg(0);

    let mut filepath = [0u8; BPF_PATH_MAX];
    // SAFETY: calling bpf_d_path helper
    let err = unsafe {
        aya_ebpf::helpers::bpf_d_path(
            path as *mut _,
            filepath.as_mut_ptr() as *mut _,
            BPF_PATH_MAX as u32,
        )
    };
    if err < 0 {
        return Ok(0);
    }

    // SAFETY: reading f_inode at file offset 168
    let f_inode = unsafe { *((file as usize + 168) as *const u64) };
    // SAFETY: reading i_ino at inode offset 80
    let inode_no = unsafe { *((f_inode as usize + 80) as *const u64) };

    // SAFETY: HashMap::get is pub unsafe fn
    if unsafe { INODE_WATCHLIST.get(&inode_no) }.is_some() {
        if INODE_WATCHLIST.remove(&inode_no).is_err() {
            return Ok(0);
        }
    }

    let path_len = watch_dir_path_len.load();
    if path_len == 0 {
        return Ok(0);
    }

    let watch_path_ptr = core::ptr::addr_of!(watch_dir_path) as *const u8;
    if strncmp_ptr(&filepath, watch_path_ptr, path_len as usize) != 0 {
        return Ok(0);
    }

    let zero: u8 = 0;
    if INODE_WATCHLIST.insert(&inode_no, &zero, 0).is_err() {
        return Ok(0);
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
