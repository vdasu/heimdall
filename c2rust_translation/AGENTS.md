# Claude Code: C eBPF → Aya Rust Translation Protocol

You are translating eBPF programs from C (libbpf) to Rust (Aya) and verifying equivalence via symbolic execution.

---

## Step 1: Read and Understand the C Program

Read the C source file. Identify:
- All `SEC()` entry points and their program types
- All map declarations (type, key, value, max_entries)
- All BPF helper calls used
- Struct definitions needed
- Overall program logic (what does each entry point do?)

## Step 2: Translate to Aya Rust

Write the Rust translation to `aya-ebpf/src/main.rs`.

Follow all rules in this file. Get it compiling before worrying about equivalence.

## Step 3: Compile

```bash
cd aya-ebpf && \
    RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf -C target-cpu=v3" \
    cargo +nightly build --target=bpfel-unknown-none-atomic.json -Zbuild-std=core --release -Zjson-target-spec
```

If compile errors: read them, fix the code, recompile. Repeat until compilation succeeds (up to 20 attempts).

The compiled binary is at:
`aya-ebpf/target/bpfel-unknown-none-atomic/release/aya-ebpf-translated`

## Step 3b: Kernel Verifier Check

After successful compilation, run the kernel verifier on the compiled `.o`:

```bash
sudo env PATH="$PATH" python3 verify_ebpf_kernel.py <rust_binary.o> --verbose
```

- If the kernel verifier **accepts** all programs: proceed to Step 4.
- If it **rejects**: read the verifier error, fix the Rust code, recompile (Step 3), and re-verify. Repeat until accepted (up to 20 attempts, shared with the compile loop).

Log each kernel verify attempt:
```
KERNEL_VERIFY <attempt_num> <pass|fail> <one-line summary>
```

This catches issues the Rust compiler cannot: stack frame too large, invalid memory access patterns, unbounded loops, etc.

---

## Step 3c: Safety Check

After compilation and kernel verification succeed, run the framework safety checker on the Rust source:

```bash
python3 safety_check.py aya-ebpf/src/main.rs
```

- If the safety checker reports a blocking violation: fix the Rust code, then go back to Step 3.
- If it reports audit warnings only: prefer fixing them when practical, but they are not blocking.
- Treat the safety checker output as authoritative guidance on which Aya-safe helper or map API should replace the raw/generated call.
- For read-only loader-initialized globals, especially C `.rodata` / `const volatile` configuration values, prefer `aya_ebpf::Global<T>` plus `NAME.load()` over raw `unsafe { core::ptr::read_volatile(...) }` at the call site.

Log each safety check:
```
SAFETY_CHECK <attempt_num> <pass|fail> <one-line summary>
```

---

## Step 4: Equivalence Check

Run the equivalence checker with all entry points:

```bash
python3 verify_mixed_entries.py <c_binary.o> <rust_binary.o> <c_entry> <rust_entry> <map1:type> [map2:type ...]
```

- If **UNSAT** (equivalent): done, the translation is correct.
- If **SAT** (mismatch): read the counter-example carefully, understand which branch or map operation diverges, fix the Rust code, recompile, re-run the kernel verifier, re-run the safety checker, and re-check equivalence. Repeat up to 10 attempts.
- For multi-entry programs, check each entry point.

## Step 5: Save Results

- Copy final Rust source to the output directory
- Copy the compiled `.o` file
- Write a `result.txt` with `EQUIVALENT` or `FAILED: <reason>`

---

## Required Boilerplate

Every translation MUST start with:

```rust
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

// ... maps, functions ...

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
```

---

## Unsafe Rules

The four `#![deny(...)]` lint guards are mandatory. They enforce:

1. **One unsafe op per block** — Each `unsafe {}` may contain only ONE unsafe operation. Split multiple ops into separate blocks.
2. **Documented unsafe** — Every `unsafe` block MUST have a `// SAFETY:` comment directly above it.
3. **No unnecessary unsafe** — Do NOT wrap safe operations in `unsafe`. This causes a compile error.
4. **No ignored Results** — Every `Result` return value MUST be handled (with `?`, `match`, `unwrap_or`, etc.). Bare `expr;` without binding is a compile error. Do NOT use `let _ =` on helper Results, and do NOT hide them in underscore bindings like `let _probe_ret = ...`, unless the `Result` is immediately consumed by `unwrap_or`, `match`, or similar handling.

**CRITICAL: Do NOT use `core::mem::transmute` to call BPF helpers directly.**
Always use Aya's safe wrapper functions from `aya_ebpf::helpers` (e.g., `bpf_probe_read_kernel`, `bpf_probe_read_user_str_bytes`, `bpf_get_current_comm`).
Raw transmute bypasses all type safety and error handling guarantees.
If a safe wrapper is not available for a helper, use the binding from `aya_ebpf::bindings` — never transmute a helper ID.
Do NOT call `aya_ebpf::helpers::generated::*` directly for helpers that already have Aya wrapper functions.

### Safe Wrapper Reference — Use These Instead of Raw Helpers

| C Helper | Aya Safe Wrapper | Return Type | Notes |
|----------|-----------------|-------------|-------|
| `bpf_probe_read_user(dst, sz, src)` | `bpf_probe_read_user::<T>(src)` | `Result<T, i32>` | Returns a copy, not a pointer |
| `bpf_probe_read_user_str(dst, sz, src)` | `bpf_probe_read_user_str_bytes(src, &mut buf)` | `Result<&[u8], i32>` | Writes into buf, returns slice |
| `bpf_probe_read_kernel(dst, sz, src)` | `bpf_probe_read_kernel::<T>(src)` | `Result<T, i32>` | Returns a copy |
| `bpf_probe_read_kernel_str(dst, sz, src)` | `bpf_probe_read_kernel_str_bytes(src, &mut buf)` | `Result<&[u8], i32>` | Writes into buf |
| `bpf_get_current_comm(buf, sz)` | `bpf_get_current_comm()` | `Result<[u8; 16], i32>` | Returns array, no buffer needed |
| `bpf_get_stackid(ctx, map, flags)` | `StackTrace::get_stackid(ctx, flags)` | `Result<i64, i64>` | Error encapsulated in Err |
| `bpf_ringbuf_reserve(map, sz, flags)` | `RingBuf::reserve::<T>(flags)` | `Option<RingBufEntry<T>>` | Typed, ownership-based |
| `bpf_ringbuf_submit(ptr, flags)` | `RingBufEntry::submit(self, flags)` | `()` | Consumes entry — no pointer arg |
| `bpf_ringbuf_discard(ptr, flags)` | `RingBufEntry::discard(self, flags)` | `()` | Consumes entry |
| `bpf_ringbuf_output(map, data, sz, flags)` | `RingBuf::output(data, flags)` | `Result<(), i64>` | One-shot output |
| `bpf_perf_event_output(ctx, map, flags, data, sz)` | `PerfEventArray::<T>::output(ctx, data, flags)` | `()` | Typed output |
| `bpf_get_stack(ctx, buf, sz, flags)` | No safe wrapper — use `aya_ebpf::bindings::bpf_get_stack` | `c_long` | Handle return manually |

### Ring Buffer reserve-write-submit Pattern

Use Aya's typed `reserve` instead of raw `bpf_ringbuf_reserve`:

```rust
// CORRECT: Aya safe API
if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
    let evt = entry.as_mut_ptr();
    // SAFETY: writing to reserved ring buffer entry
    unsafe { (*evt).pid = pid };
    // SAFETY: writing comm to reserved entry
    unsafe { (*evt).comm = bpf_get_current_comm()? };
    entry.submit(0);
}

// WRONG: Do NOT do this
let ptr = core::mem::transmute::<usize, fn(...)>(131usize);  // BANNED
```

### Operations that REQUIRE `unsafe`
- Dereferencing raw pointers: `*ptr`, `*mut_ptr = val`
- `core::sync::atomic::AtomicU64::from_ptr(ptr)`
- `ctx.as_ptr()` casts and field reads
- `bpf_probe_read_kernel()`, `bpf_probe_read_user()`
- Writing into `RingBufEntry` via `as_mut_ptr()`: `(*evt).field = value`
- `HashMap::get(&k)` — declared `pub unsafe fn` in aya-ebpf; wrap in a minimal `unsafe { ... }`
- `bpf_ktime_get_ns()`, `bpf_get_smp_processor_id()`, `bpf_get_current_task()`,
  `bpf_get_current_cgroup_id()` — re-exported directly from `aya-ebpf-bindings`
  as `pub unsafe fn`; wrap the call

### Operations that are SAFE (do NOT wrap in unsafe)
- `HashMap::insert(&k, &v, flags)`, `HashMap::remove(&k)`, `HashMap::get_ptr_mut(&k)`
- `Array::get()`, `Array::get_ptr()`, `Array::get_ptr_mut()`
- `PerfEventArray::output()`, `RingBuf::reserve()`, `RingBuf::output()`, `entry.submit()`, `entry.discard()`
- `bpf_get_current_pid_tgid()`, `bpf_get_current_comm()`, `bpf_get_current_uid_gid()`
  (safe wrappers live in `aya_ebpf::helpers`, shadowing the raw bindings)
- `ProbeContext::arg::<T>(n)` — returns `Option<T>`, safe
- `TracePointContext::read_at::<T>(offset)` — returns `Result<T>`, safe

### When to use `?` vs `.ok()`
- **Helper calls** (probe_read, get_current_comm, get_stack): always use `?` — failure means data is wrong, abort the function.
- **Map operations** (insert, remove): `.ok()` is fine — "key not found" is expected and harmless.
- If a ringbuf entry has already been reserved and a helper fails, discard the entry before returning.

### Example
```rust
// SAFETY: pointer from get_ptr is valid for the BPF program lifetime
let val = unsafe { *ptr };

// SAFETY: creating atomic from valid map pointer
let atomic = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
```

---

## Program Type Mapping

| C SEC() | Aya Macro |
|---------|-----------|
| `SEC("tracepoint/...")` or `SEC("tp/...")` | `#[tracepoint]` → `TracePointContext` |
| `SEC("raw_tracepoint/...")` or `SEC("raw_tp/...")` | `#[raw_tracepoint(tracepoint = "...")]` → `RawTracePointContext` |
| `SEC("kprobe/...")` | `#[kprobe]` → `ProbeContext` |
| `SEC("kretprobe/...")` | `#[kretprobe]` → `RetProbeContext` |
| `SEC("fentry/func")` | `#[fentry(function = "func")]` → `FEntryContext` |
| `SEC("fexit/func")` | `#[fexit(function = "func")]` → `FExitContext` |
| `SEC("xdp")` | `#[xdp]` → `XdpContext` |
| `SEC("classifier")` or `SEC("tc")` | `#[classifier]` → `TcContext` |
| `SEC("socket_filter")` | `#[socket_filter]` → `SkBuffContext` |
| `SEC("cgroup_skb/...")` | `#[cgroup_skb]` → `SkBuffContext` |
| `SEC("sockops")` | `#[sock_ops]` → `SockOpsContext` |
| `SEC("lsm/...")` | `#[lsm]` → `LsmContext` |
| `SEC("perf_event")` | `#[perf_event]` → `PerfEventContext` |
| `SEC("iter/...")` | Not supported by Aya |
| `SEC("usdt/...")` | Not supported by Aya |

---

## Map Type Mapping

### Declarations
```rust
#[map(name = "my_hash")]
static MY_HASH: HashMap<KeyType, ValueType> = HashMap::with_max_entries(1024, 0);

#[map(name = "my_array")]
static MY_ARRAY: Array<ValueType> = Array::with_max_entries(256, 0);

#[map(name = "my_percpu_array")]
static MY_PERCPU_ARRAY: PerCpuArray<ValueType> = PerCpuArray::with_max_entries(256, 0);

#[map(name = "my_perf")]
static MY_PERF: PerfEventArray<ValueType> = PerfEventArray::new(0);

#[map(name = "my_ringbuf")]
static MY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map(name = "my_lru")]
static MY_LRU: LruHashMap<KeyType, ValueType> = LruHashMap::with_max_entries(1024, 0);

#[map(name = "my_stack")]
static MY_STACK: StackTraceMap = StackTraceMap::with_max_entries(1024, 0);
```

### Map Operations
```rust
// HashMap / LruHashMap lookup — returns Option<&V>
let val = MY_HASH.get(&key);

// HashMap / LruHashMap insert
MY_HASH.insert(&key, &value, 0).ok();

// HashMap / LruHashMap delete
MY_HASH.remove(&key).ok();

// Array / PerCpuArray lookup — returns Option<*const T> or Option<*mut T>
let ptr = MY_ARRAY.get_ptr(index);       // Option<*const T>
let ptr = MY_ARRAY.get_ptr_mut(index);   // Option<*mut T>

// Perf event output
MY_PERF.output(ctx, &data, 0);

// RingBuf reserve + write + submit
if let Some(mut entry) = MY_RINGBUF.reserve::<EventType>(0) {
    // SAFETY: writing to reserved ringbuf entry
    unsafe { entry.write(event) };
    entry.submit(0);
}

// StackTraceMap — get stack ID
let stack_id = MY_STACK.get_stackid(ctx, 0);  // returns Result<i64, i64>
```

---

## Context Field Access

### Tracepoint
Fields are at byte offsets in the tracepoint format. Use `ctx.read_at::<T>(offset)`:
```rust
// Read a u64 field at byte offset 8
let val: u64 = ctx.read_at(8).map_err(|_| 1i64)?;

// Read a u32 field at byte offset 16
let pid: u32 = ctx.read_at(16).map_err(|_| 1i64)?;
```

### Kprobe / Kretprobe
```rust
// Read function arguments
let arg0: u64 = ctx.arg(0).ok_or(1u32)?;
let arg1: *const c_void = ctx.arg(1).ok_or(1u32)?;

// Kretprobe: read return value
let ret: i64 = ctx.ret().ok_or(1u32)?;
```

### Fentry / Fexit
```rust
// Read arguments by index (0-based)
let arg0: u64 = unsafe { ctx.arg(0) };
```

### XDP
```rust
let data = ctx.data();
let data_end = ctx.data_end();
let eth_hdr: *const EthHdr = data as *const EthHdr;
if (eth_hdr as usize) + core::mem::size_of::<EthHdr>() > data_end as usize {
    return Ok(XDP_DROP);
}
```

---

## Common Helper Mappings

| C Helper | Aya Rust |
|----------|----------|
| `bpf_get_current_pid_tgid()` | `bpf_get_current_pid_tgid()` → `u64` |
| `bpf_get_current_uid_gid()` | `bpf_get_current_uid_gid()` → `u64` |
| `bpf_ktime_get_ns()` | `bpf_ktime_get_ns()` → `u64` |
| `bpf_get_current_comm(&buf, size)` | `bpf_get_current_comm()` → `Result<[u8; 16], i64>` |
| `bpf_get_smp_processor_id()` | `bpf_get_smp_processor_id()` → `u32` |
| `bpf_probe_read_kernel(&dst, size, src)` | `bpf_probe_read_kernel(src)` → `Result<T, i64>` |
| `bpf_probe_read_user(&dst, size, src)` | `bpf_probe_read_user(src)` → `Result<T, i64>` |
| `bpf_get_current_task()` | `bpf_get_current_task()` → `*mut c_void` (unsafe) |
| `bpf_get_stackid(ctx, map, flags)` | `map.get_stackid(ctx, flags)` → `Result<i64, i64>` |
| `bpf_printk(fmt, ...)` | `aya_ebpf::helpers::bpf_printk!(b"fmt", args...)` (unsafe) |
| `bpf_perf_event_output(ctx, map, flags, data, size)` | `map.output(ctx, &data, flags)` |
| `bpf_ringbuf_reserve(map, size, flags)` | `map.reserve::<T>(flags)` → `Option<RingBufEntry<T>>` |
| `bpf_ringbuf_submit(data, flags)` | `entry.submit(flags)` |
| `bpf_ringbuf_discard(data, flags)` | `entry.discard(flags)` |

---

## Common Patterns

### Error handling with Result
```rust
#[tracepoint]
pub fn my_prog(ctx: TracePointContext) -> i32 {
    match try_my_prog(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_my_prog(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = bpf_get_current_pid_tgid() >> 32;
    // ...
    Ok(0)
}
```

### Atomic counter increment
```rust
if let Some(ptr) = MY_ARRAY.get_ptr_mut(0) {
    // SAFETY: creating atomic from valid map pointer
    let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr as *mut u64) };
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}
```

**CRITICAL: Do NOT use inline assembly for atomics.** `core::arch::asm!`,
`core::arch::global_asm!`, and the `asm_experimental_arch` feature gate are
BANNED. `AtomicU64::from_ptr(..).fetch_add(.., Ordering::Relaxed)` lowers
directly to the BPF XADD instruction on `bpfel-unknown-none` — there is no
need for `asm!("lock *(u64 *)(r1 + 0) += r2", ...)` or `#![feature(asm_experimental_arch)]`.

For HashMap value atomics, use `HashMap::get_ptr_mut(&key)` to obtain
`*mut V` directly. Do NOT cast `&V` from `HashMap::get(&key)` to `*mut V`
and do NOT silence the resulting lint with `#![allow(invalid_reference_casting)]`.

```rust
// WRONG: inline-asm XADD (BANNED)
unsafe {
    core::arch::asm!("lock *(u64 *)(r1 + 0) += r2",
                     in("r1") ptr, in("r2") 1u64, options(nostack));
}

// WRONG: shared-ref → *mut cast, requires invalid_reference_casting allow
let val_ptr = match unsafe { COUNTS.get(&key) } {
    Some(v) => v as *const u64 as *mut u64,  // BANNED
    None => return,
};

// CORRECT: HashMap::get_ptr_mut returns *mut V directly
if let Some(ptr) = COUNTS.get_ptr_mut(&key) {
    // SAFETY: creating atomic from valid map pointer
    let counter = unsafe { core::sync::atomic::AtomicU64::from_ptr(ptr) };
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}
```

For BSS globals, declare them directly rather than emitting them via
`global_asm!`:

```rust
// WRONG: manual BSS emission via global_asm! (BANNED)
core::arch::global_asm!(
    ".section .bss,\"aw\",@nobits",
    ".globl scan_pages",
    "scan_pages: .zero 8",
);

// CORRECT: declared static mut with link_section
#[no_mangle]
#[link_section = ".bss"]
static mut scan_pages: i64 = 0;

// Atomic update via addr_of_mut!:
let atomic = unsafe { core::sync::atomic::AtomicI64::from_ptr(
    core::ptr::addr_of_mut!(scan_pages)
) };
atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
```

**Caveat: `fetch_add`'s return value on BPF is not the previous value.**
Rust's `AtomicI64::fetch_add` on the `bpfel-unknown-none-atomic` target
lowers to `BPF_ATOMIC | BPF_ADD` *without* the `BPF_FETCH` flag. The
return value is whatever the compiler had in the source register
(typically the value you passed in), not the prior contents of `*ptr`.
This is fine for the common case where you ignore the return (simple
counter increment). If the C source uses `__sync_fetch_and_add` and
acts on the returned previous value (e.g., to clamp a counter that
may have gone negative), do a `read_volatile` *before* the atomic add
and use that read as the "old value". The read is racy relative to
the atomic add, but that matches the semantics the inline-asm
alternative would give, without reaching for `asm!`.

```rust
// CORRECT pattern when the C source needs the prior value for a check:
// SAFETY: volatile read from BSS global
let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(scan_pages)) };
// SAFETY: atomic add on BSS global
let atomic = unsafe { core::sync::atomic::AtomicI64::from_ptr(
    core::ptr::addr_of_mut!(scan_pages)
) };
atomic.fetch_add(delta, core::sync::atomic::Ordering::Relaxed);
if old + delta < 0 {
    // clamp — matches C's `if (__sync_fetch_and_add(...) + delta < 0) { x = 0; }`
    // SAFETY: writing BSS global
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(scan_pages), 0) };
}
```

### Filling a HashMap entry before emitting (stack-copy pattern)

When translating the C idiom of stashing an event in a hash map at entry
and finalizing a field (e.g. `.ret`) at exit before emitting to perf/ringbuf:
do NOT reach for `HashMap::get_ptr_mut(&k)` + `unsafe { (*p).field = ... }`.
Copy the value to the stack with `HashMap::get(&k)`, mutate the stack copy,
emit from the stack copy, then remove the map entry. This eliminates the
raw-pointer field write with no behavior change.

```rust
// CORRECT: stack-copy pattern (Event must derive Copy)
// SAFETY: HashMap::get is pub unsafe fn in aya-ebpf; the returned &Event is safe to copy.
let event_ref = match unsafe { VALUES.get(&tid) } {
    Some(r) => r,
    None => return 0,
};
let mut event = *event_ref;              // stack copy
event.ret = ret;
let _ = EVENTS.output(ctx, &event, 0);   // emit from stack
let _ = VALUES.remove(&tid);

// WRONG: raw-pointer mutation into the map entry you're about to remove
let eventp = match unsafe { VALUES.get(&tid) } {
    Some(p) => p as *const Event as *mut Event,
    None => return 0,
};
unsafe { (*eventp).ret = ret };          // avoidable
let event = unsafe { *eventp };          // avoidable
EVENTS.output(ctx, &event, 0);
let _ = VALUES.remove(&tid);
```

Use `HashMap::insert(&tid, &event, 0)` instead of `.remove()` if the
mutation should persist. For `Array<T>`-backed maps there is no
`insert`-style safe write — `get_ptr_mut(idx)` + `unsafe { (*p) = val }` is
the prescribed pattern there.

### Reading loader-initialized globals (`Global<T>::load()`)

When the C program uses a read-only loader-initialized global such as a
`.rodata` config variable or translated `const volatile` knob, do NOT expose
the volatile load with `unsafe { core::ptr::read_volatile(...) }` at each use
site. Model the symbol as `aya_ebpf::Global<T>` and read it with `.load()`.
This preserves the required volatile-read semantics while keeping the call site
safe and idiomatic.

```rust
// CORRECT: immutable global represented with Aya's safe Global<T> wrapper
use aya_ebpf::Global;

#[no_mangle]
static targ_tgid: Global<u32> = Global::new(0);

let target_tgid = targ_tgid.load();
if target_tgid != 0 && target_tgid != tgid {
    return 0;
}

// WRONG: avoidable raw volatile read from an immutable global
#[no_mangle]
static targ_tgid: u32 = 0;

let target_tgid = unsafe { core::ptr::read_volatile(&targ_tgid) };
```

If the value is just a fixed zero/default template rather than a real
loader-overridden configuration variable, prefer a direct stack value or
literal instead of `read_volatile`.

### Reading struct from context pointer
```rust
let task: *const task_struct = ctx.arg(0).ok_or(1u32)?;
// SAFETY: reading kernel field from valid task pointer
let pid = unsafe { bpf_probe_read_kernel(&(*task).pid as *const i32)? };
```

### Struct definitions (repr(C) required)
```rust
#[repr(C)]
struct Event {
    pid: u32,
    comm: [u8; 16],
    ts: u64,
}
```

---

## File Locations

| File | Purpose |
|------|---------|
| `aya-ebpf/src/main.rs` | Write Rust translation here |
| `aya-ebpf/target/bpfel-unknown-none-atomic/release/aya-ebpf-translated` | Compiled Rust .o |
| `verify_mixed_entries.py` | Equivalence checker |
| `generate_formula.py` | Formula generator |

---

## Important Notes

- Do NOT use `static mut` for maps. Use `#[map]` attribute on `static` items.
- Map names in `#[map(name = "...")]` must match the C map names exactly (used for relocation matching).
- Function names decorated with `#[tracepoint]`, `#[kprobe]`, etc. become the ELF symbol names. They must match what the equivalence checker expects.
- Return types: tracepoint/kprobe use `i32` or `u32`. XDP uses `u32` (XDP_PASS=2, XDP_DROP=1, XDP_ABORTED=0).
- For `perf_event_array` and `ringbuf` maps, the symbolic execution engine **tracks the emitted data** and compares it between C and Rust translations via synthetic `__perf_output` / `__ringbuf_output` maps. `bpf_ringbuf_reserve` reservations up to 512 bytes (configurable via `--ringbuf-track-max`) are tracked exactly; larger reservations fall back to no-op for Z3 scalability. Direct `bpf_map_update_elem` on these map types is still treated as no-op, but you should be using `perf_event_output` / `ringbuf_reserve+submit` / `ringbuf_output` anyway.
