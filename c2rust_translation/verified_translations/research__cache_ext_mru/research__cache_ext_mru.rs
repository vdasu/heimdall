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

const BPF_PATH_MAX: usize = 128;
const FMODE_CREATED: u32 = 0x100000;

// Read-only globals filled by loader
#[no_mangle]
#[link_section = ".rodata"]
pub static watch_dir_path: [u8; BPF_PATH_MAX] = [0u8; BPF_PATH_MAX];

#[no_mangle]
#[link_section = ".rodata"]
pub static watch_dir_path_len: u64 = 0;

// Global for mru_list
#[no_mangle]
static mut mru_list: u64 = 0;

// Map declaration
#[map(name = "inode_watchlist")]
static INODE_WATCHLIST: HashMap<u64, u8> = HashMap::with_max_entries(200000, 0);

// kfunc declarations
extern "C" {
    fn bpf_cache_ext_ds_registry_new_list(memcg: *const c_void) -> u64;
    fn bpf_cache_ext_list_add(list: u64, folio: *const c_void) -> c_int;
    fn bpf_cache_ext_list_move(list: u64, folio: *const c_void, tail: bool) -> c_int;
    fn bpf_cache_ext_list_del(folio: *const c_void) -> c_int;
    fn bpf_cache_ext_list_iterate(
        memcg: *const c_void,
        list: u64,
        iter_fn: *const c_void,
        ctx: *const c_void,
    ) -> c_int;
}

// Helper: check if folio's inode is in watchlist
#[inline(always)]
fn is_folio_relevant(folio: u64) -> bool {
    if folio == 0 {
        return false;
    }

    // folio->mapping at offset 24
    // SAFETY: reading mapping pointer from folio struct
    let mapping = unsafe { *((folio + 24) as *const u64) };
    if mapping == 0 {
        return false;
    }

    // mapping->host at offset 0
    // SAFETY: reading host pointer from address_space struct
    let host = unsafe { *(mapping as *const u64) };
    if host == 0 {
        return false;
    }

    // host->i_ino at offset 80
    // SAFETY: reading i_ino from inode struct
    let inode_no = unsafe { *((host + 80) as *const u64) };

    // Check if inode is in watchlist
    // SAFETY: looking up inode in map
    unsafe { INODE_WATCHLIST.get(&inode_no) }.is_some()
}

// Eviction callback
#[no_mangle]
fn iterate_mru(idx: c_int, node: *const c_void) -> c_int {
    if node.is_null() {
        return 1; // CACHE_EXT_EVICT_NODE
    }

    // SAFETY: reading folio pointer from cache_ext_list_node (offset 0)
    let folio = unsafe { *(node as *const u64) };
    if folio == 0 {
        return 1; // CACHE_EXT_EVICT_NODE
    }

    // Read folio->page.flags (offset 0 from folio)
    // SAFETY: reading page flags from folio
    let flags = unsafe { *(folio as *const u64) };

    // PG_uptodate = 6, PG_lru = 5
    let pg_uptodate = 1u64 << 6;
    let pg_lru = 1u64 << 5;

    // if idx < 200 AND (not uptodate OR not lru), continue iterating
    if (idx < 200) && ((flags & pg_uptodate) == 0 || (flags & pg_lru) == 0) {
        return 0; // CACHE_EXT_CONTINUE_ITER
    }

    1 // CACHE_EXT_EVICT_NODE
}

// ---- fexit/vfs_open ----
#[fexit(function = "vfs_open")]
pub fn vfs_open_exit(ctx: FExitContext) -> i32 {
    // arg2 = return value of vfs_open
    let ret: i64 = ctx.arg(2);
    if ret != 0 {
        return 0;
    }

    // arg1 = file
    let file: u64 = ctx.arg(1);

    // file->f_mode at offset 20 (u32)
    // SAFETY: reading f_mode field from file struct
    let f_mode: u32 = unsafe { *((file + 20) as *const u32) };
    if f_mode & FMODE_CREATED == 0 {
        return 0;
    }

    // arg0 = path
    let path: u64 = ctx.arg(0);

    // Zero-init filepath buffer on stack
    let mut filepath = [0u8; BPF_PATH_MAX];

    // Call bpf_d_path(path, filepath, 128)
    // SAFETY: calling bpf_d_path BPF helper
    let err: i64 = unsafe {
        bpf_d_path(
            path as *mut _,
            filepath.as_mut_ptr() as *mut c_char,
            BPF_PATH_MAX as u32,
        )
    };
    if err < 0 {
        // SAFETY: calling bpf_printk helper
        unsafe { bpf_printk!(b"Failed to get file path: %ld\n", err) };
        return 0;
    }

    // file->f_inode at offset 168
    // SAFETY: reading f_inode pointer from file struct
    let f_inode: u64 = unsafe { *((file + 168) as *const u64) };

    // inode->i_ino at offset 80
    // SAFETY: reading i_ino from inode struct
    let inode_no: u64 = unsafe { *((f_inode + 80) as *const u64) };

    // Check if inode was previously in watchlist
    // SAFETY: looking up inode in map
    if unsafe { INODE_WATCHLIST.get(&inode_no) }.is_some() {
        if INODE_WATCHLIST.remove(&inode_no).is_err() {
            // SAFETY: calling bpf_printk helper
            unsafe {
                bpf_printk!(
                    b"Failed to delete inode from inode_watchlist: %ld\n",
                    0i64
                )
            };
            return 0;
        }
    }

    // Check watch_dir_path_len
    if watch_dir_path_len == 0 {
        // SAFETY: calling bpf_printk helper
        unsafe { bpf_printk!(b"watch_dir_path_len is 0!!\n") };
        return 0;
    }

    // strncmp(filepath, watch_dir_path, watch_dir_path_len)
    let n = watch_dir_path_len as usize;
    let mut si = 0usize;
    while si < n {
        if filepath[si] == 0 {
            break;
        }
        if filepath[si] != watch_dir_path[si] {
            break;
        }
        si += 1;
    }
    if si < n {
        let c1 = filepath[si];
        let c2 = watch_dir_path[si];
        if c1 != c2 {
            return 0;
        }
    }

    // Add inode to watchlist
    let zero: u8 = 0;
    if INODE_WATCHLIST.insert(&inode_no, &zero, 0).is_err() {
        // SAFETY: calling bpf_printk helper
        unsafe {
            bpf_printk!(
                b"Failed to add inode to inode_watchlist: %ld\n",
                0i64
            )
        };
        return 0;
    }

    0
}

// ---- struct_ops.s/mru_init ----
#[no_mangle]
#[link_section = "struct_ops.s/mru_init"]
pub extern "C" fn mru_init(ctx: *const u64) -> i32 {
    // SAFETY: reading memcg pointer from BPF context
    let memcg = unsafe { *ctx };

    // SAFETY: calling kfunc to create new list
    let list = unsafe { bpf_cache_ext_ds_registry_new_list(memcg as *const c_void) };

    // SAFETY: writing to global mru_list
    unsafe { mru_list = list };

    if list == 0 {
        // SAFETY: calling bpf_printk helper
        unsafe { bpf_printk!(b"cache_ext: Failed to create mru_list\n") };
        return -1;
    }

    // SAFETY: calling bpf_printk helper
    unsafe { bpf_printk!(b"cache_ext: Created mru_list: %llu\n", list) };
    0
}

// ---- struct_ops/mru_folio_added ----
#[no_mangle]
#[link_section = "struct_ops/mru_folio_added"]
pub extern "C" fn mru_folio_added(ctx: *const u64) {
    // SAFETY: reading folio pointer from BPF context
    let folio = unsafe { *ctx };

    if !is_folio_relevant(folio) {
        return;
    }

    // SAFETY: reading mru_list global
    let list = unsafe { mru_list };

    // SAFETY: calling kfunc to add folio to list (head, not tail)
    let ret = unsafe { bpf_cache_ext_list_add(list, folio as *const c_void) };
    if ret != 0 {
        // SAFETY: calling bpf_printk helper
        unsafe { bpf_printk!(b"cache_ext: Failed to add folio to mru_list\n") };
    }
}

// ---- struct_ops/mru_folio_accessed ----
#[no_mangle]
#[link_section = "struct_ops/mru_folio_accessed"]
pub extern "C" fn mru_folio_accessed(ctx: *const u64) {
    // SAFETY: reading folio pointer from BPF context
    let folio = unsafe { *ctx };

    if !is_folio_relevant(folio) {
        return;
    }

    // SAFETY: reading mru_list global
    let list = unsafe { mru_list };

    // SAFETY: calling kfunc to move folio to head (tail=false)
    let ret = unsafe { bpf_cache_ext_list_move(list, folio as *const c_void, false) };
    if ret != 0 {
        // SAFETY: calling bpf_printk helper
        unsafe { bpf_printk!(b"cache_ext: Failed to move folio to mru_list head\n") };
    }
}

// ---- struct_ops/mru_folio_evicted ----
#[no_mangle]
#[link_section = "struct_ops/mru_folio_evicted"]
pub extern "C" fn mru_folio_evicted(ctx: *const u64) {
    // SAFETY: reading folio pointer from BPF context
    let folio = unsafe { *ctx };

    // SAFETY: calling kfunc to delete folio from list
    unsafe { bpf_cache_ext_list_del(folio as *const c_void) };
}

// ---- struct_ops/mru_evict_folios ----
#[no_mangle]
#[link_section = "struct_ops/mru_evict_folios"]
pub extern "C" fn mru_evict_folios(ctx: *const u64) {
    // SAFETY: reading eviction_ctx from BPF context (arg0)
    let eviction_ctx = unsafe { *ctx };

    // SAFETY: reading memcg from BPF context (arg1)
    let memcg = unsafe { *ctx.add(1) };

    // SAFETY: reading mru_list global
    let list = unsafe { mru_list };

    // SAFETY: calling kfunc to iterate list
    let ret = unsafe {
        bpf_cache_ext_list_iterate(
            memcg as *const c_void,
            list,
            iterate_mru as *const c_void,
            eviction_ctx as *const c_void,
        )
    };

    if ret < 0 {
        // SAFETY: calling bpf_printk helper
        unsafe { bpf_printk!(b"cache_ext: Failed to evict folios\n") };
    }

    // Check eviction counts:
    // eviction_ctx->request_nr_folios_to_evict at some offset
    // eviction_ctx->nr_folios_to_evict at some offset
    // SAFETY: reading request_nr_folios_to_evict from eviction_ctx (offset 0)
    let request_nr = unsafe { *(eviction_ctx as *const u32) };
    // SAFETY: reading nr_folios_to_evict from eviction_ctx (offset 4)
    let nr = unsafe { *((eviction_ctx + 4) as *const u32) };

    if request_nr > nr {
        // SAFETY: calling bpf_printk helper
        unsafe {
            bpf_printk!(
                b"cache_ext: Didn't evict enough folios. Requested: %d, Evicted: %d\n",
                request_nr,
                nr
            )
        };
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
