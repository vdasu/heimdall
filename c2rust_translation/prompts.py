import os

def _prompt_cache_ttl():
    """Return the configured Anthropic prompt-cache TTL, or None when disabled."""
    ttl = os.environ.get("ANTHROPIC_CACHE_TTL", "5m").strip().lower()
    if ttl in {"", "0", "false", "none", "off"}:
        return None
    if ttl not in {"5m", "1h"}:
        return "5m"
    return ttl

def text_content_block(text, *, cache=False):
    """Build an Anthropic-compatible text block, optionally with cache control."""
    block = {
        "type": "text",
        "text": text,
    }
    ttl = _prompt_cache_ttl() if cache else None
    if ttl:
        block["cache_control"] = {
            "type": "ephemeral",
            "ttl": ttl,
        }
    return block

def user_text_message(text, *, cache=False):
    """Build a user message containing a single text block."""
    return {
        "role": "user",
        "content": [text_content_block(text, cache=cache)],
    }

_EQUIV_RUST_MARKER = "## Current Rust Translation:\n```rust\n{{rust_source}}\n```"

def build_equivalence_fix_user_message(c_source, rust_source, counter_example):
    """Build an equivalence-fix user message with a cached stable prefix."""
    prefix, suffix = equivalence_fix_prompt.split(_EQUIV_RUST_MARKER, 1)
    cached_prefix = (CONDENSED_TRANSLATION_RULES + "\n" + prefix).replace(
        "{{c_source}}",
        c_source,
    )
    dynamic_suffix = (
        _EQUIV_RUST_MARKER.replace("{{rust_source}}", rust_source)
        + suffix.replace("{{counter_example}}", counter_example)
    )
    return {
        "role": "user",
        "content": [
            text_content_block(cached_prefix, cache=True),
            text_content_block(dynamic_suffix),
        ],
    }

first_prompt = """
You are an expert eBPF programmer translating C libbpf programs to Rust using the Aya eBPF framework.

## Source C Program
```c
{{target_c_code}}
```

## Translation Rules

Translate the above C program to Rust. The output must:
- Be functionally identical to the C (verified via symbolic equivalence)
- The Rust eBPF entrypoint function name MUST be IDENTICAL to the C function name.
- Preserve all map names (use `#[map(name = "...")]` if the Rust identifier differs)

## Critical Import Rules

ALWAYS use the kernel-space crate `aya_ebpf`, NEVER use the userspace crate `aya`:
```rust
// CORRECT
use aya_ebpf::macros::{map, kprobe, tracepoint};
use aya_ebpf::maps::{Array, HashMap, hash_map_of_maps::HashMapOfMaps, array_of_maps::ArrayOfMaps};
use aya_ebpf::programs::ProbeContext;

// WRONG — these will not compile in eBPF
use aya::maps::Array;           // userspace crate
use aya_ebpf_macros::kprobe;    // use aya_ebpf::macros instead
```

## Hook Macros

Derive the hook type from the C `SEC("...")` string:

| C SEC string | Aya macro | Context type |
|---|---|---|
| `SEC("kprobe/...")` | `#[kprobe]` | `ProbeContext` |
| `SEC("kretprobe/...")` | `#[kretprobe]` | `RetProbeContext` |
| `SEC("fentry/<func>")` | `#[fentry(function="<func>")]` | `FEntryContext` |
| `SEC("fexit/<func>")` | `#[fexit(function="<func>")]` | `FExitContext` |
| `SEC("tracepoint/cat/name")` or `SEC("tp/cat/name")` | `#[tracepoint(category="cat", name="name")]` | `TracePointContext` |
| `SEC("raw_tracepoint/name")` or `SEC("raw_tp/name")` | `#[raw_tracepoint(tracepoint="name")]` | `RawTracePointContext` |
| `SEC("tp_btf/<event>")` | `#[btf_tracepoint(function="<event>")]` | `BtfTracePointContext` |
| `SEC("lsm/hook")` | `#[lsm(hook="hook")]` | `LsmContext` |
| `SEC("xdp")` | `#[xdp]` | `XdpContext` |
| `SEC("classifier")` or `SEC("tc")` | `#[classifier]` | `TcContext` |
| `SEC("perf_event")` or `SEC("perf_event/type=…")` | `#[perf_event]` | `PerfEventContext` |
| `SEC("usdt")` or `SEC("usdt/...")` | `#[uprobe]` | `ProbeContext` |

**CRITICAL — emit a separate Rust function for EVERY C `SEC()` block.** A C source
may define paired handlers for the same kernel event/function (e.g. a
`raw_tp/<event>` and a `tp_btf/<event>` block, or a `kprobe/<func>` and an
`fentry/<func>` block). The compiled C `.o` exposes EACH `SEC()` as its own
global symbol. If you only translate one of a pair, the Rust `.o` will be
missing entry symbols and the equivalence checker will report `error`
(symbol not found) on the missing entries. Translate every `SEC()` block,
and pick the macro from the table above based on the SEC prefix.

`fentry`/`fexit` use `function = "<kernel_func>"`. `FEntryContext::arg::<T>(n)`
returns `T` directly (NOT `Option<T>`/`Result`); same for `FExitContext`.

**USDT programs**: At the kernel level a USDT probe is just a uprobe attached to a
user-space address, so `SEC("usdt")` translates to `#[uprobe]` (`ProbeContext`).
Do NOT use `#[kprobe]` for USDT programs.

## Common BPF Helper → Aya Mapping

| C helper | Aya equivalent |
|---|---|
| `bpf_map_lookup_elem(&map, &key)` | `map.get_ptr(&key)` / `map.get_ptr_mut(&key)` → `Option<*const V>` / `Option<*mut V>` |
| `bpf_map_update_elem(&map, &key, &val, flags)` | Array: write through `get_ptr_mut`. HashMap: `map.insert(&key, &val, flags)` |
| `bpf_map_lookup_elem(&outer, &key)` then `bpf_map_lookup_elem(inner, &k2)` (map-of-maps) | `outer.get(&key)` → `Option<&InnerMap>`, then `inner.get_ptr(&k2)`. Or fused: `outer.get_value(&key, &k2)` |
| `bpf_probe_read_kernel(dst, sz, src)` | `aya_ebpf::helpers::bpf_probe_read_kernel_buf(src, dst)` |
| `bpf_probe_read(dst, sz, src)` | `ctx.read_at::<T>(offset)` for context fields, `bpf_probe_read_buf` otherwise |
| `bpf_get_current_pid_tgid()` | `aya_ebpf::helpers::bpf_get_current_pid_tgid()` → `u64` |
| `bpf_get_current_uid_gid()` | `aya_ebpf::helpers::bpf_get_current_uid_gid()` → `u64` |
| `bpf_get_current_comm(buf, sz)` | `aya_ebpf::helpers::bpf_get_current_comm()` → `Result<[u8; 16], i64>` |
| `bpf_ktime_get_ns()` | `aya_ebpf::helpers::bpf_ktime_get_ns()` → `u64` |
| `bpf_perf_event_output(ctx, map, flags, data, sz)` | `map.output(ctx, data, flags)` |
| `bpf_ringbuf_reserve(&rb, sz, flags)` | `RB.reserve::<T>(0)` → `Option<RingBufEntry<T>>` (zero-init reserved region before field writes — see RingBuf section) |
| `bpf_ringbuf_submit(entry, flags)` | `entry.submit(0)` (consumes the entry) |
| `bpf_ringbuf_discard(entry, flags)` | `entry.discard(0)` (consumes the entry; use on the early-return path after reserve) |
| `bpf_trace_printk(...)` | `aya_ebpf::helpers::bpf_printk!(...)` or use `aya_log_ebpf` macros |
| `bpf_get_smp_processor_id()` | `aya_ebpf::helpers::bpf_get_smp_processor_id()` → `u32` |

## Map Declarations

- ALWAYS use `static` (NOT `static mut`) for map declarations.
- ALWAYS import `map` from `aya_ebpf::macros` (e.g. `use aya_ebpf::macros::{map, perf_event};`).
- Maps use interior mutability — `get_ptr_mut()` takes `&self`, not `&mut self`.
- Map statics MUST use UPPER_SNAKE_CASE (e.g. `MY_COUNTER`, not `my_counter`).

```rust
// CORRECT
#[map(name = "my_map")]
static MY_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

// WRONG — static mut breaks #[map] and forces unsafe on every access
#[map(name = "my_map")]
static mut MY_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

// Map-of-maps: outer map whose values are references to inner maps
#[map]
static OUTER: HashMapOfMaps<u32, Array<u32>, 256, 0> = HashMapOfMaps::new();
// or
#[map]
static OUTER_ARR: ArrayOfMaps<HashMap<u32, u64>, 4, 0> = ArrayOfMaps::new();

// Lookup: two-step (get inner map ref, then lookup in it)
if let Some(inner) = unsafe { OUTER.get(&key) } {
    if let Some(val) = inner.get_ptr(&inner_key) { /* ... */ }
}
// Fused lookup (preferred — fewer instructions):
if let Some(val) = unsafe { OUTER.get_value(&key, &inner_key) } { /* ... */ }
```

## Atomic Operations

If the C uses `__sync_fetch_and_add` or other atomic builtins, use `core::sync::atomic`.
This is the exact pattern that compiles correctly:

```rust
use core::sync::atomic::{AtomicU64, Ordering};

// Inside your eBPF function:
let ptr = MY_MAP.get_ptr_mut(key).ok_or(0u32)?;
// SAFETY: map pointers are 8-byte aligned and valid for program lifetime
let atomic = unsafe { AtomicU64::from_ptr(ptr) };
atomic.fetch_add(1, Ordering::Relaxed);
```

## Read-only Loader-initialized Globals (`.rodata`)

C `const volatile` globals (the standard libbpf pattern for loader-patched
configuration values) are read-only at runtime: the userspace loader patches
them before `bpf()`-loading, and the kernel verifier sees them as immutable.
The Rust translation MUST model them as read-only.

**DO NOT** translate them as `static mut X: T = 0; ... unsafe { core::ptr::read_volatile(&X) }`.
That pattern is REJECTED by the safety checker: `static mut` advertises mutability
that isn't there, and the `unsafe { read_volatile }` is gratuitous. The build
system rejects any `read_volatile` on an otherwise-never-written `static mut`.

Use `aya_ebpf::Global<T>::load()` instead. It performs the volatile read internally,
exposes no `unsafe` at the call site, and matches the `.rodata` semantics. Preserve
the C identifier exactly:

```rust
use aya_ebpf::Global;

// C: const volatile <type> <NAME> = <init>;
#[no_mangle]
static <NAME>: Global<<type>> = Global::new();

// Inside your eBPF function:
let v = <NAME>.load();          // safe — no unsafe block needed
```

If a global is a fixed zero or template that the loader never patches (e.g. a
constant used only as a percpu_array key), prefer a stack literal instead of
introducing a `Global<T>` for it.

## RingBuf Output

For programs that emit events through `BPF_MAP_TYPE_RINGBUF`, use Aya's typed
`RingBuf` API. **Never** call `aya_ebpf::helpers::generated::bpf_ringbuf_reserve/submit/discard`
directly — the safety checker rejects those.

```rust
use aya_ebpf::maps::RingBuf;

#[map] static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Reserve a typed entry. MUST zero-initialize the reserved region BEFORE writing
// fields, otherwise stale bytes from prior records leak through to userspace.
let mut entry = match EVENTS.reserve::<MyEvent>(0) {
    Some(e) => e,
    None => return 0,                      // reserve failed — drop event
};
// SAFETY: zero entire reserved region to prevent stale-bytes leak.
unsafe {
    core::ptr::write_bytes(
        entry.as_mut_ptr() as *mut u8,
        0u8,
        core::mem::size_of::<MyEvent>(),
    );
}
// ... now write fields through entry.as_mut_ptr() or typed access ...
// On the success path:
entry.submit(0);
// On any early-return path AFTER reserve (e.g. helper failed mid-fill):
// entry.discard(0); return 0;
```

## Context Reads

Reading fields from the program context (tracepoint args, kprobe args):

```rust
// Reading a tracepoint argument at a known byte offset
let fd: i32 = ctx.read_at(16).unwrap_or(0);
```

For kprobes, to read function arguments:
```rust
let arg0: u64 = tx.arg(0).unwrap_or(0);
```

## Unsafe Policy

- Keep `unsafe` blocks as small as possible — wrap only the single operation that requires it.
- Add a `// SAFETY:` comment above each `unsafe` block.
- NOTE: `#![deny(unused_unsafe)]` and `#![deny(unused_must_use)]` are injected automatically at build time. Unnecessary unsafe blocks and unchecked `Result` values WILL cause compile errors.
- CRITICAL: Do NOT use `core::mem::transmute` to call BPF helpers. Always use Aya's safe wrappers from `aya_ebpf::helpers`. The build system will REJECT code containing transmute.
- CRITICAL: Do NOT define raw helper trampoline functions (`unsafe fn raw_bpf_*` or `let <var>: unsafe extern "C" fn`). The build system will REJECT these patterns.
  If a safe wrapper exists in `aya_ebpf::helpers`, use it. If not, use the binding from `aya_ebpf::bindings`.
- Handle ALL helper Result values with `?` (preferred), `match`, or `unwrap_or`. Bare `expr;` without binding is a compile error (`deny(unused_must_use)`). Do NOT use `let _ =` on failable helper Results, and do NOT hide them in underscore bindings like `let _probe_ret = ...`, unless the `Result` is immediately consumed by `unwrap_or`, `match`, or similar handling. When bpf_probe_read fails, the kernel zeroes the buffer — without checking, the program continues with incorrect data.
- Map operation discards ARE acceptable: `map.insert(...).ok()` and `map.remove(...).ok()` are fine because "key not found" is an expected condition.
- If a ringbuf entry has already been reserved and a helper fails, discard the entry before returning.
- Do NOT call `aya_ebpf::helpers::generated::*` directly for helpers that already have Aya wrapper functions.
- Operations that require `unsafe`:
  - Raw pointer dereference (`*ptr`)
  - `AtomicU64::from_ptr()`
  - `TracePointContext::read_at::<T>(offset)` → `Result<T, i32>`
  - All bindings-layer helpers (called via `aya_ebpf::helpers::`):
    `bpf_ktime_get_ns()`, `bpf_get_smp_processor_id()`, `bpf_get_prandom_u32()`,
    `bpf_get_current_task()`, `bpf_get_current_cgroup_id()`,
    `bpf_ktime_get_boot_ns()`, `bpf_ktime_get_coarse_ns()`
  - All probe_read/write variants:
    `bpf_probe_read()`, `bpf_probe_read_buf()`, `bpf_probe_read_user()`,
    `bpf_probe_read_user_buf()`, `bpf_probe_read_kernel()`, `bpf_probe_read_kernel_buf()`,
    `bpf_probe_read_str()`, `bpf_probe_read_user_str()`, `bpf_probe_read_kernel_str()`,
    `bpf_probe_write_user()`
  - `StackTrace::get_stackid(&self, ctx, flags)` → `Result<i64, i64>`
    (ctx must implement EbpfContext — add `use aya_ebpf::EbpfContext;`)
- Operations that do NOT require `unsafe`:
  - `map.get_ptr()`, `map.get_ptr_mut()` (returns `Option`)
  - `atomic.fetch_add()`, arithmetic, control flow
  - Safe wrapper helpers (called via `aya_ebpf::helpers::`):
    `bpf_get_current_pid_tgid()` → `u64`,
    `bpf_get_current_uid_gid()` → `u64`,
    `bpf_get_current_comm()` → `Result<[u8; 16], i64>`
  - `ProbeContext::arg::<T>(n)` → `Option<T>` (SAFE — do NOT wrap in unsafe)
  - `FEntryContext::arg::<T>(n)` → `T` (SAFE, returns T directly, NOT Option)
  - `FExitContext::arg::<T>(n)` → `T` (SAFE, returns T directly, NOT Option)
  - `RetProbeContext::ret::<T>()` → `T` (SAFE, returns T directly, NOT Option/Result — do NOT call .unwrap_or())

## Required Boilerplate

Every program must start with this exact structure:
```rust
#![no_std]
#![no_main]

// ... use statements ...

// ... maps ...

// ... program functions ...

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\\0";
```

## Complete Example

Here is a verified, compiling kprobe program with an Array map and atomic counter:
```rust
#![no_std]
#![no_main]

use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::ProbeContext;
use core::sync::atomic::{AtomicU64, Ordering};

#[map]
static MY_COUNTER: Array<u64> = Array::with_max_entries(16, 0);

#[kprobe]
pub fn count_calls(_ctx: ProbeContext) -> u32 {
    match try_count_calls() {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_count_calls() -> Result<u32, u32> {
    let key: u32 = 0;
    let ptr = MY_COUNTER.get_ptr_mut(key).ok_or(0u32)?;
    // SAFETY: Array map values are 8-byte aligned and valid after successful lookup
    let counter = unsafe { AtomicU64::from_ptr(ptr) };
    counter.fetch_add(1, Ordering::Relaxed);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\\0";
```

{{aya_api_docs}}

Now output ONLY the translated Rust code:
```rust
```
"""

error_prompt = """The following Rust eBPF code failed to compile:

```rust
{{rust_code}}
```

Compiler errors:
```
{{error_log}}
```

Fix the compilation errors and try to address all warnings. Output ONLY the corrected Rust code:

```rust
```"""

safety_fix_prompt = """The following Rust eBPF code compiles, but it violates the framework's safety policy.

You must preserve the program's semantics while replacing the unsafe/raw helper usage with the correct Aya-safe API when one exists.

```rust
{{rust_code}}
```

Safety checker report:
```
{{safety_report}}
```

Instructions:
- Fix every blocking safety violation reported above.
- Prefer Aya wrappers from `aya_ebpf::helpers` and typed map APIs over `helpers::generated::*`.
- Preserve function names, map names, hook points, and program behavior.
- If a helper returns `Result`, handle it explicitly with `?`, `match`, `unwrap_or`, or another deliberate checked pattern.
- Keep unsafe blocks minimal and documented with `// SAFETY:`.

## Common safety violations and the required fix pattern

If the report mentions any of the following, apply the matching pattern:

1. **`HashMap::get_ptr_mut` (or `unsafe { MAP.get() } as *mut T`) followed by
   `unsafe { (*p).field = ... }`** on a HashMap-backed map.
   Replace with stack-copy + insert/remove. Array / PerCpuArray still use
   `get_ptr_mut` + unsafe deref (prescribed for Array).
   ```rust
   match unsafe { MAP.get(&k) } {
       Some(r) => {
           let mut v = *r;
           v.field = ...;
           let _ = MAP.insert(&k, &v, 0);   // or MAP.remove(&k);
       }
       None => return 0,
   }
   ```

2. **`read_volatile` on a read-only `static mut`** (a `const volatile` C global
   translated as `static mut <NAME>: T = 0; unsafe { read_volatile(&<NAME>) }`).
   Replace with `aya_ebpf::Global<T>::load()`, preserving the C identifier:
   ```rust
   use aya_ebpf::Global;
   #[no_mangle]
   static <NAME>: Global<T> = Global::new();
   let v = <NAME>.load();       // no unsafe needed
   ```
   This rule does NOT apply to `static mut` state that is actually written
   (e.g. via `addr_of_mut!`, `&mut`, or `write_volatile`).

3. **`RingBuf::reserve::<T>(...)` followed by per-field writes WITHOUT
   zero-initializing the reserved region first.** Stale bytes from prior records
   leak. Add a `write_bytes` zero-init before any field writes:
   ```rust
   let mut entry = EVENTS.reserve::<T>(0).ok_or(0u32)?;
   // SAFETY: zero entire reserved region to prevent stale-bytes leak
   unsafe { core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, 0u8,
                                   core::mem::size_of::<T>()); }
   // ... field writes ...
   entry.submit(0);
   ```

4. **`core::mem::transmute` to call BPF helpers** or **`unsafe extern "C" fn raw_bpf_*`
   helper trampolines** — both are flat-banned. Use the safe Aya wrapper from
   `aya_ebpf::helpers`. If no safe wrapper exists, use the binding from
   `aya_ebpf::bindings`.

5. **`helpers::generated::bpf_<helper>` called directly** (probe_read, get_current_comm,
   ringbuf, etc.). Replace with the typed safe wrapper from `aya_ebpf::helpers`
   or `aya_ebpf::maps`.

Output ONLY the corrected Rust code:

```rust
```"""

CONDENSED_TRANSLATION_RULES = """Key Aya eBPF translation rules (reference):
- Use `aya_ebpf` (kernel-space), NOT `aya` (userspace). Macros from `aya_ebpf::macros`.
- `#![no_std]`, `#![no_main]`, no `main()` function.
- Maps: `#[map]` or `#[map(name = "...")]`. Do NOT add `#[link_section = ".maps"]`.
- Map statics MUST be UPPER_SNAKE_CASE. Use `#[map(name = "c_name")]` to preserve C names.
- Array `get_ptr`/`get_ptr_mut` takes bare `u32` key. HashMap takes `&K` reference.
- Hook macros must match C SEC() exactly. For tracepoints: provide BOTH name and category.
- For EVERY C `SEC()` block, emit a SEPARATE Rust function. C sources may pair
  `raw_tp/<e>` with `tp_btf/<e>` (or `kprobe/<f>` with `fentry/<f>`) for the same
  event/function. Translating only one leaves entry symbols missing in the Rust
  `.o` and the equivalence checker reports `error` (symbol not found).
- SEC mapping reference: `kprobe/<f>` → `#[kprobe]` (`ProbeContext`);
  `kretprobe/<f>` → `#[kretprobe]` (`RetProbeContext`);
  `fentry/<f>` → `#[fentry(function="<f>")]` (`FEntryContext`);
  `fexit/<f>` → `#[fexit(function="<f>")]` (`FExitContext`);
  `tracepoint/<c>/<n>` (or `tp/<c>/<n>`) → `#[tracepoint(category="<c>", name="<n>")]`;
  `raw_tracepoint/<n>` (or `raw_tp/<n>`) → `#[raw_tracepoint(tracepoint="<n>")]`;
  `tp_btf/<e>` → `#[btf_tracepoint(function="<e>")]` (`BtfTracePointContext`).
- Function names and map names MUST match the C program exactly.
- Atomics: CRITICAL — __sync_fetch_and_add compiles to BPF_ATOMIC (opcode 0xdb).
  Plain *ptr += val compiles to BPF_STX (opcode 0x7b). The equivalence checker scans
  compiled bytecode for these opcodes. If C has BPF_ATOMIC and Rust has BPF_STX, the
  translation is rejected regardless of Z3 equivalence.
  Use core::sync::atomic::AtomicU64::from_ptr(ptr) then .fetch_add(val, Ordering::Relaxed).
- Read-only globals (any C `const volatile <type> <NAME> = <init>;`): use
  `aya_ebpf::Global<T>::load()` — NEVER `static mut` + `unsafe { read_volatile(...) }`.
  The safety checker rejects `read_volatile` on a `static mut` that is only read.
- RingBuf reserves MUST be zero-initialized before field writes. After
  `EVENTS.reserve::<T>(0)`, call `core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8,
  0u8, size_of::<T>())` (in unsafe). Without this, stale bytes from prior records leak.
- HashMap-backed maps: do NOT do `unsafe { (*p).field = ... }` on a pointer obtained
  from `get_ptr_mut(&k)` or a raw cast of `MAP.get(&k)`. Use the stack-copy +
  `insert(&k, &v, 0)` (or `remove(&k)`) pattern. Array / PerCpuArray still use
  `get_ptr_mut + unsafe deref` (prescribed for those map types).
- Minimize unsafe; `// SAFETY:` comment above each unsafe block.
- No unbounded loops; stack < 512 bytes; always handle map lookup `None`.
- Preserve all control-flow, return codes, map update conditions, and error handling.
- Include panic handler and `static LICENSE: [u8; 4] = *b"GPL\\0";`.
- C unions: use `#[repr(C)] union` in Rust — NOT byte arrays with accessor methods.
  All variants must have the same size. Access fields via `unsafe { val.field }`.
  Mirror the C declaration directly: a C `union { struct <S> a; <T> b[N]; }` becomes
  `#[repr(C)] #[derive(Copy, Clone)] union <Name> { a: <S>, b: [<T>; N] }`.
"""

equivalence_fix_prompt = """The Rust translation compiles successfully but is NOT semantically equivalent to the original C program.

The symbolic equivalence checker found a counter-example input where the C and Rust programs produce different outputs.

## Original C Program:
```c
{{c_source}}
```

## Current Rust Translation:
```rust
{{rust_source}}
```

## Counter-Example (concrete input that causes divergence):
{{counter_example}}

## Instructions:
1. Analyze the counter-example to understand WHERE the Rust program diverges from C.
2. The counter-example shows specific input values that make the programs behave differently. Context fields are decomposed into named struct members (e.g., di_arg0, si_arg1 for kprobes).
3. The diverging outputs show the C and Rust values at each diverging map key, along with a diagnosis of the likely bug type. Use the diagnosis to guide your fix. The diagnosis is a hint, not a definitive label. Use your understanding of the code and the counter-example to identify the root cause.

## Diagnosis legend (the formatter emits one of these tags)

  - `MISSING_WRITE`            — Rust produced 0 where C produced a value. Likely a missed branch or skipped map update; check that every path that writes in C also writes in Rust.
  - `EXTRA_WRITE`              — Rust wrote where C didn't. An extra branch, an unguarded update, or a stale fall-through. Check the C control-flow guards and mirror them.
  - `SIGN_EXTENSION`           — Rust sign-extended a negative i32 to i64 where C zero-extended. Use `as u32 as u64`.
  - `MISSING_SIGN_EXTENSION`   — Inverse: C sign-extended but Rust zero-extended. Use `(x as i32 as i64)`.
  - `TRUNCATION`               — One side narrowed to 32 bits, losing high bits, while the other kept 64. Check cast widths (u64 vs u32).
  - `ATOMIC OPERATION MISMATCH`           — Bytecode-level mismatch: C uses `__sync_fetch_and_add` (BPF_ATOMIC opcode 0xdb) but Rust emits BPF_STX (0x7b). Use `core::sync::atomic::AtomicU64::from_ptr(p).fetch_add(v, Ordering::Relaxed)`. The check is on bytecode, not symbolic output — Z3 alone won't catch it.
  - `PARTIAL ATOMIC OPERATION MISMATCH`   — Some atomics matched, some didn't. Audit every `__sync_*` in the C source and confirm each one has a corresponding `AtomicU{32,64}::from_ptr(...).fetch_*(...)` in Rust.

4. If the Rust source has inline annotations (// ^^ counter-example: ...), use those concrete values to trace the execution path and find the divergence point.
5. Fix the Rust translation to match the C program's behavior exactly.
6. Do not change function names, map names, or hook points.
7. Do NOT introduce new safety violations while chasing the equivalence fix.
   In particular, do NOT regress to: `static mut X = ...; unsafe { read_volatile(&X) }`
   for `.rodata` config (use `Global<T>::load()`); raw `(*p).field = ...` on HashMap
   pointers (use stack-copy + insert/remove); or un-zeroed RingBuf reserves.

Provide the corrected Rust code:
```rust
```"""
