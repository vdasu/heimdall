"""
Safety policy constants for the eBPF C-to-Rust translation pipeline.

Single source of truth for banned patterns and failable helper patterns.
Imported by build.py (deterministic pipeline) and safety_check.py (agentic pipeline).
"""

import re

_STRING_BANS = [
    (
        "core::mem::transmute",
        "Do not use core::mem::transmute to call BPF helpers. "
        "Use Aya safe wrappers from aya_ebpf::helpers instead.",
    ),
    (
        "mem::transmute",
        "Do not use mem::transmute to call BPF helpers. "
        "Use Aya safe wrappers from aya_ebpf::helpers instead.",
    ),
    (
        "unsafe fn raw_bpf_",
        "Do not define raw_bpf_ trampoline functions. "
        "Use Aya safe wrappers from aya_ebpf::helpers, or bindings from "
        "aya_ebpf::bindings if no safe wrapper exists.",
    ),
    (
        "helpers::generated::bpf_probe_read_user(",
        "Do not call generated bpf_probe_read_user directly. "
        "Use aya_ebpf::helpers::bpf_probe_read_user::<T>() instead.",
    ),
    (
        "helpers::generated::bpf_probe_read_kernel(",
        "Do not call generated bpf_probe_read_kernel directly. "
        "Use aya_ebpf::helpers::bpf_probe_read_kernel::<T>() instead.",
    ),
    (
        "helpers::generated::bpf_probe_read_user_str(",
        "Do not call generated bpf_probe_read_user_str directly. "
        "Use aya_ebpf::helpers::bpf_probe_read_user_str_bytes instead.",
    ),
    (
        "helpers::generated::bpf_probe_read_kernel_str(",
        "Do not call generated bpf_probe_read_kernel_str directly. "
        "Use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes instead.",
    ),
    (
        "helpers::generated::bpf_get_current_comm(",
        "Do not call generated bpf_get_current_comm directly. "
        "Use aya_ebpf::helpers::bpf_get_current_comm() instead.",
    ),
    (
        "helpers::generated::bpf_ringbuf_reserve(",
        "Do not call generated ring buffer reserve helpers directly. "
        "Use aya_ebpf::maps::RingBuf::reserve or reserve_bytes instead.",
    ),
    (
        "helpers::generated::bpf_ringbuf_submit(",
        "Do not call generated ring buffer submit helpers directly. "
        "Use RingBufEntry::submit or RingBufBytes::submit instead.",
    ),
    (
        "helpers::generated::bpf_ringbuf_discard(",
        "Do not call generated ring buffer discard helpers directly. "
        "Use RingBufEntry::discard or RingBufBytes::discard instead.",
    ),

    (
        "transmute_copy",
        "Do not use core::mem::transmute_copy on RingBufEntry, MapData, or "
        "any output-buffer wrapper. Reserve as a typed struct via "
        "EVENTS.reserve::<MyEvent>(0) and access via entry.as_mut_ptr() "
        "which returns a typed *mut MyEvent directly.",
    ),
    (
        "RingBuf::reserve::<[u8",
        "Do not reserve a RingBuf entry as an untyped byte array "
        "(RingBuf::reserve::<[u8; N]>). Define a #[repr(C)] struct with "
        "named fields (including any padding as an explicit `_pad: [u8; N]` "
        "field) and reserve as RingBuf::reserve::<MyEvent>(0). This lets "
        "Rust's type system enforce field-level initialization and prevents "
        "the C-style partial-init bug class.",
    ),
    (
        ".reserve::<[u8",
        "Do not reserve a ringbuf entry as an untyped byte array. Define a "
        "#[repr(C)] struct with named fields and reserve as a typed entry, "
        "e.g. EVENTS.reserve::<MyEvent>(0). Untyped byte-array reservations "
        "force the use of raw-pointer arithmetic that replicates the C "
        "source's partial-initialization bug class.",
    ),
    (
        "RingBufEntry<[u8",
        "Do not type a RingBufEntry as <[u8; N]> (an untyped byte array). "
        "Use a typed event struct: define #[repr(C)] struct MyEvent { ... } "
        "and reserve as RingBufEntry<MyEvent>. Untyped byte-array entries "
        "are an unsafe escape hatch that defeats Aya's type safety.",
    ),

    (
        "core::arch::asm!",
        "Do not use inline assembly. For atomic updates on map values or "
        "BSS globals, use core::sync::atomic::AtomicU64::from_ptr(ptr)"
        ".fetch_add(.., Ordering::Relaxed) after obtaining a valid *mut "
        "via HashMap::get_ptr_mut(&key) or core::ptr::addr_of_mut!(STATIC). "
        "Inline asm bypasses Aya's safe-API surface and is the escape "
        "hatch the safe-Aya analyzer is designed to reject.",
    ),
    (
        "asm_experimental_arch",
        "Do not enable the unstable feature(asm_experimental_arch). "
        "Atomic operations on BPF targets are available via "
        "core::sync::atomic::AtomicU64::from_ptr(..)"
        ".fetch_add(.., Ordering::Relaxed); no nightly feature gate is "
        "required.",
    ),
    (
        "allow(invalid_reference_casting)",
        "Do not silence invalid_reference_casting. If you need a *mut to "
        "a map value for atomic updates, obtain it via "
        "HashMap::get_ptr_mut(&key) which returns *mut T directly, not "
        "&T cast to *mut T.",
    ),
]

_REGEX_BANS = [
    (
        re.compile(r'\blet\s+\w+\s*:\s*unsafe\s+extern\s+"C"\s+fn'),
        "Do not define raw helper trampoline bindings via let-bound unsafe extern C fn. "
        "Use Aya safe wrappers from aya_ebpf::helpers.",
    ),
    (

        re.compile(r'\buse\s+aya_ebpf::helpers::generated\b'),
        "Do not import helpers from aya_ebpf::helpers::generated, with or "
        "without aliasing (function alias, module alias, wildcard, or plain). "
        "The generated bindings are raw FFI trampolines that bypass Aya's "
        "typed safe wrappers; aliasing the function or the module defeats "
        "the per-call-site bans in this policy and lets translations preserve "
        "C-side buffer/size and pointer-cast bugs verbatim (e.g., biostacks "
        "aliased bpf_get_current_comm to bypass the call-site ban and emitted "
        "size=8 from C's sizeof(&ptr) bug). Use the typed wrappers from "
        "aya_ebpf::helpers instead — these derive byte counts from the typed "
        "return and eliminate caller-supplied size arguments.",
    ),
]

_UNDERSCORE_BIND_RE = re.compile(r"\blet\s+(_[A-Za-z0-9_]*)\s*=")
_HANDLED_RESULT_MARKERS = (

    ".map_or(",
    ".map_or_else(",
    ".unwrap(",
    ".expect(",
    ".is_ok()",
    ".is_err()",
    "?",
)

BANNED_PATTERNS = list(_STRING_BANS)

FAILABLE_HELPER_PATTERNS = [

    "bpf_probe_read_kernel",
    "bpf_probe_read_user",
    "bpf_get_current_comm",

    "bpf_probe_read_kernel_str_bytes",
    "bpf_probe_read_user_str_bytes",
    "bpf_probe_read_kernel_buf",
    "bpf_probe_read_user_buf",

    "get_stackid(",
    "_str_bytes(",
]
_SORTED_FAILABLE_HELPER_PATTERNS = sorted(
    FAILABLE_HELPER_PATTERNS, key=len, reverse=True
)

_BLOCK_COMMENT_RE = re.compile(r'/\*[\s\S]*?\*/')
_LINE_COMMENT_RE = re.compile(r'//[^\n]*')

def _strip_rust_comments(source_code):
    """Remove Rust line and block comments before pattern scanning.

    Banned-pattern checks should not fire on text that appears only inside
    a comment (e.g., a doc comment that mentions a forbidden pattern by name
    in order to contrast it with the safe alternative). This is a simple
    regex-based stripper that does not handle nested block comments or
    comment-like text inside string literals; both are rare enough in eBPF
    translations that we accept the imprecision.
    """

    stripped = _BLOCK_COMMENT_RE.sub(' ', source_code)
    stripped = _LINE_COMMENT_RE.sub(' ', stripped)
    return stripped

_SCALAR_RESERVE_TYPES = frozenset({
    "u8", "u16", "u32", "u64", "u128",
    "i8", "i16", "i32", "i64", "i128",
    "usize", "isize",
    "bool", "char", "f32", "f64",
})

_RESERVE_TYPE_RE = re.compile(r"reserve::<\s*([A-Za-z_]\w*)")

def _check_ringbuf_zero_init(code):
    """Require zero-initialization of ringbuf-reserved memory.

    If the source reserves a ringbuf entry (RingBuf::reserve or .reserve::<),
    it must also zero-initialize the reserved memory via write_bytes or
    ptr::write_bytes before submitting.  Without this, the reserved region
    contains stale ring-buffer data from previously-consumed records — the
    same partial-init leak class that affects mountsnoop.bpf.c and
    filelife.bpf.c in upstream libbpf-tools.

    Scalar-reservation exemption: `reserve::<T>(0)` where T is a primitive
    scalar (u32, u64, i32, bool, f64, …) followed by the typed
    `RingBufEntry::<T>::write(value)` call is already fully initialized —
    a scalar has no padding bytes and no sub-fields, so `ptr::write` of the
    full type overwrites every reserved byte. No explicit `write_bytes`
    zero-init is needed. The exemption only applies when *all* reserve
    call sites in the file use scalar types AND the file does not use
    `reserve_bytes(` (which returns an untyped byte buffer).
    """
    uses_reserve = ".reserve::<" in code or "RingBuf::reserve" in code
    if not uses_reserve:
        return None
    has_zero_init = "write_bytes(" in code
    if has_zero_init:
        return None

    if "reserve_bytes" not in code:
        reserved_types = set(_RESERVE_TYPE_RE.findall(code))
        if reserved_types and reserved_types.issubset(_SCALAR_RESERVE_TYPES):
            return None
    return {
        "pattern": "RingBuf::reserve without write_bytes zero-init",
        "message": (
            "Ring buffer reserved memory must be zero-initialized before use. "
            "After calling EVENTS.reserve::<MyEvent>(0), add: "
            "unsafe { core::ptr::write_bytes(entry.as_mut_ptr() as *mut u8, "
            "0u8, core::mem::size_of::<MyEvent>()); } "
            "Without this, the reserved region contains stale data from "
            "previously-consumed ring-buffer records (the partial-init leak "
            "class that affects mountsnoop.bpf.c in upstream libbpf-tools). "
            "Always add the write_bytes zero-init — this is a required safety "
            "improvement over the C original. If the equivalence check reports "
            "a mismatch on ringbuf output after adding write_bytes, re-run "
            "the equivalence check with --ringbuf-track-max 0 to treat "
            "ringbuf output as a write-only sink (not compared). Example: "
            "python3 verify_mixed_entries.py <c.o> <rust.o> <entry> <entry> "
            "<maps...> --ringbuf-track-max 0"
        ),
    }

_HASHMAP_BACKED_KINDS = (
    "HashMap",
    "LruHashMap",
    "PerCpuHashMap",
    "LruPerCpuHashMap",
)
_HASHMAP_DECL_RE = re.compile(
    r"static\s+([A-Z_][A-Z0-9_]*)\s*:\s*(" +
    "|".join(_HASHMAP_BACKED_KINDS) + r")\s*<"
)

_HASHMAP_GET_PTR_MUT_BIND_RE = re.compile(
    r"(?:let\s+Some\s*\(\s*(?:mut\s+)?(?P<iflet>\w+)\s*\)|"
    r"let\s+(?:mut\s+)?(?P<let>\w+))"
    r"\s*=\s*[^;]*?"
    r"(?P<map>[A-Z_][A-Z0-9_]*)\s*\.\s*get_ptr_mut\s*\("
)

_HASHMAP_MATCH_GET_CAST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<let>\w+)\s*=\s*"
    r"match\s+unsafe\s*\{\s*(?P<map>[A-Z_][A-Z0-9_]*)\s*\.\s*get\s*\([^)]*\)\s*\}"
)

_HASHMAP_IFLET_GET_RE = re.compile(
    r"if\s+let\s+Some\s*\(\s*(?:mut\s+)?(?P<ref_name>\w+)\s*\)"
    r"\s*=\s*unsafe\s*\{\s*(?P<map>[A-Z_][A-Z0-9_]*)\s*\.\s*get\s*\([^)]*\)\s*\}"
)

_CAST_TO_MUT_PTR_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<dst>\w+)\s*=\s*(?P<src>\w+)"
    r"(?:\s+as\s+\*\s*const\s+\w+)?\s+as\s+\*\s*mut\s+\w+"
)

_UNSAFE_FIELD_WRITE_RE = re.compile(
    r"unsafe\s*\{\s*\(\s*\*\s*(?P<var>\w+)\s*\)\s*\.\s*\w+\s*[+\-*/&|^]?="
)
_IMMUTABLE_STATIC_DECL_RE = re.compile(
    r"^\s*(?:pub\s+)?static(?!\s+mut\b)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:",
    re.MULTILINE,
)
_MUTABLE_STATIC_DECL_RE = re.compile(
    r"^\s*(?:pub\s+)?static\s+mut\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:",
    re.MULTILINE,
)
_IMMUTABLE_GLOBAL_READ_PATTERNS = (
    re.compile(r"read_volatile\(\s*&raw const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"),
    re.compile(r"read_volatile\(\s*&\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"),
    re.compile(
        r"read_volatile\(\s*(?:core::ptr::)?addr_of!\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)"
    ),
    re.compile(
        r"read_volatile\(\s*core::ptr::addr_of!\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)"
    ),
    re.compile(
        r"read_volatile\(\s*&\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+as\s+\*\s*const"
    ),
    re.compile(
        r"read_volatile\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\.as_ptr\s*\("
    ),
)

def _check_hashmap_unsafe_field_write(code):
    """Forbid raw-pointer field writes into HashMap-backed map entries.

    On ``HashMap<K, V>`` / ``LruHashMap`` / ``PerCpuHashMap`` / ``LruPerCpuHashMap``
    the idiomatic pattern for mutating a stored value is
    ``get(&k)`` -> stack copy -> mutate the copy -> ``insert(&k, &copy, 0)``
    (or ``remove`` if the mutation is discardable, as in the sigsnoop exit
    path). Reaching for ``get_ptr_mut(&k)`` + ``unsafe { (*p).field = ... }``
    is a compile-and-kernel-verifier-accepted but avoidable escape hatch:
    it mirrors the C source's raw-pointer mutation while bypassing the
    typed ``insert`` wrapper.

    This check flags the two observed forms:
      (A) direct:  ``let Some(p) = MAP.get_ptr_mut(&k) { unsafe { (*p).f = v } }``
      (B) cast:    ``match unsafe { MAP.get(&k) } { Some(p) => p as *const T
                        as *mut T, ... }`` followed by ``unsafe { (*p).f = v }``

    ``Array<T>`` / ``PerCpuArray<T>`` are NOT flagged — they have no safe
    ``insert`` method, so ``get_ptr_mut`` + unsafe deref is the prescribed
    Aya pattern. The check looks at the map's declared type, not the call
    site, so Array-backed sites pass untouched.
    """
    code_stripped = _strip_rust_comments(code)
    hashmap_names = set(
        m.group(1) for m in _HASHMAP_DECL_RE.finditer(code_stripped)
    )
    if not hashmap_names:
        return None

    hashmap_vars = {}

    for m in _HASHMAP_GET_PTR_MUT_BIND_RE.finditer(code_stripped):
        if m.group("map") not in hashmap_names:
            continue
        var = m.group("iflet") or m.group("let")
        if var:
            hashmap_vars[var] = m.group("map")

    for m in _HASHMAP_MATCH_GET_CAST_RE.finditer(code_stripped):
        if m.group("map") not in hashmap_names:
            continue

        if m.group("let"):
            hashmap_vars[m.group("let")] = m.group("map")

    for m in _HASHMAP_IFLET_GET_RE.finditer(code_stripped):
        if m.group("map") not in hashmap_names:
            continue

        if m.group("ref_name"):
            hashmap_vars[m.group("ref_name")] = m.group("map")

    for _ in range(3):
        grew = False
        for m in _CAST_TO_MUT_PTR_RE.finditer(code_stripped):
            src = m.group("src")
            dst = m.group("dst")
            if src in hashmap_vars and dst not in hashmap_vars:
                hashmap_vars[dst] = hashmap_vars[src]
                grew = True
        if not grew:
            break

    for m in _UNSAFE_FIELD_WRITE_RE.finditer(code_stripped):
        var = m.group("var")
        if var in hashmap_vars:
            map_name = hashmap_vars[var]
            return {
                "pattern": (
                    f"unsafe field write into HashMap entry (map: {map_name})"
                ),
                "message": (
                    f"Avoid `unsafe {{ (*{var}).field = ... }}` on a pointer "
                    f"obtained from `{map_name}.get_ptr_mut()` or "
                    f"`unsafe {{ {map_name}.get() }}` + raw cast. `{map_name}` "
                    "is a HashMap-backed map with a safe `insert()` wrapper. "
                    "Use the stack-copy pattern: "
                    f"`if let Some(r) = unsafe {{ {map_name}.get(&k) }} "
                    "{ let mut v = *r; v.field = ...; "
                    f"let _ = {map_name}.insert(&k, &v, 0); /* or remove */ }}`. "
                    "This eliminates the raw-pointer mutation; the only "
                    "remaining unsafe is the compiler-required `get()` wrap. "
                    "Does NOT apply to Array / PerCpuArray — their "
                    "get_ptr_mut pattern is legitimate because Array has no "
                    "safe insert()."
                ),
            }
    return None

def _check_immutable_global_read_volatile(code):
    """Forbid raw read_volatile loads from immutable global statics.

    Aya already provides a safe ``Global<T>::load()`` wrapper for ``T: Copy``.
    Translations that keep immutable loader-initialized globals as plain
    ``static`` bindings and then reach for ``unsafe { read_volatile(...) }``
    are using avoidable unsafe.  This check intentionally excludes
    ``static mut`` state — mutable global state and zero templates are a
    separate category from the read-only-global finding we want to enforce.
    """
    code_stripped = _strip_rust_comments(code)
    immutable_names = set(
        m.group("name") for m in _IMMUTABLE_STATIC_DECL_RE.finditer(code_stripped)
    )
    if not immutable_names:
        return None

    for regex in _IMMUTABLE_GLOBAL_READ_PATTERNS:
        for m in regex.finditer(code_stripped):
            name = m.group("name")
            if name not in immutable_names:
                continue
            return {
                "pattern": f"read_volatile on immutable global `{name}`",
                "message": (
                    f"Avoid `read_volatile` on immutable global `{name}`. "
                    "If this is a read-only loader-initialized global, model it "
                    "with `aya_ebpf::Global<T>` and read it with "
                    f"`{name}.load()` instead; Aya's `Global<T>::load()` already "
                    "performs the volatile load internally without exposing raw "
                    "unsafe at the call site. If this is just a fixed zero or "
                    "default template, use a direct stack value or literal "
                    "instead of `read_volatile`. This rule does NOT apply to "
                    "`static mut` state."
                ),
            }
    return None

def _has_write_to_static(name, code):
    """Return True if ``name`` appears in any write-like expression.

    A genuine ``static mut`` has at least one write somewhere in the file.
    The workaround pattern (``static mut`` used as a loader-overridable
    read-only constant to bypass the immutable-global check) has zero
    writes. We treat the presence of *any* of the following forms as
    sufficient evidence that ``name`` may be written, and therefore that
    the ``static mut`` declaration is legitimate:

    1. Direct assignment or compound assignment:
       ``NAME = ...``, ``NAME += ...``, etc.
    2. Mutable pointer construction (conservative — treat the pointer
       as potentially written through):
       ``addr_of_mut!(NAME)``, ``&raw mut NAME``, ``&mut NAME``.
    3. Explicit volatile writes:
       ``write_volatile(..NAME..)``, ``ptr::write(addr_of_mut!(NAME), ..)``.
    """
    n = re.escape(name)
    write_patterns = [
        rf"\baddr_of_mut!\s*\(\s*{n}\b",
        rf"&\s*raw\s+mut\s+{n}\b",
        rf"&\s*mut\s+{n}\b",

        rf"\b{n}\s*[+\-*/&|^%]?=(?!=)",
        rf"\bwrite_volatile\s*\([^)]*\b{n}\b",
        rf"\bptr::write(?:_volatile)?\s*\([^)]*\b{n}\b",
    ]
    combined = re.compile("|".join(f"(?:{p})" for p in write_patterns))
    return bool(combined.search(code))

def _check_readonly_static_mut_reads(code):
    """Forbid read-only use of ``static mut`` with ``read_volatile``.

    A legitimate ``static mut`` always has at least one write somewhere
    in the program — that is the reason to declare it ``mut`` in the
    first place. When a translation declares ``static mut NAME`` but
    never writes to it (no direct assignment, no ``addr_of_mut!``, no
    ``&mut``, no ``write_volatile``) and reads it via
    ``read_volatile(addr_of!(NAME))``-style expressions, the binding is
    semantically a loader-overridable read-only constant and should be
    modeled with ``aya_ebpf::Global<T>`` and read via ``NAME.load()``.

    This rule closes the escape hatch where translations sidestep the
    immutable-static-read check by adding ``mut`` to the declaration.
    """
    code_stripped = _strip_rust_comments(code)
    mutable_names = set(
        m.group("name") for m in _MUTABLE_STATIC_DECL_RE.finditer(code_stripped)
    )
    if not mutable_names:
        return None

    read_patterns = [
        *_IMMUTABLE_GLOBAL_READ_PATTERNS,
        re.compile(
            r"\b(?:core::ptr::)?addr_of!\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
        ),
        re.compile(r"&\s*raw\s+const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"),
    ]

    for regex in read_patterns:
        for m in regex.finditer(code_stripped):
            name = m.group("name")
            if name not in mutable_names:
                continue
            if _has_write_to_static(name, code_stripped):
                continue
            return {
                "pattern": f"read-only static mut `{name}` used with read_volatile",
                "message": (
                    f"`static mut {name}` is only read (via `read_volatile`), "
                    "never written. Adding `mut` does not justify the unsafe: "
                    "if the binding is a loader-overridable read-only "
                    "constant, model it with `aya_ebpf::Global<T>` and read "
                    f"it with `{name}.load()` (no unsafe, no SAFETY comment). "
                    "If `{name}` is meant to be mutable runtime state, at "
                    "least one write must be visible in the source "
                    "(`{name} = ...`, `addr_of_mut!({name})`, `&mut {name}`, "
                    "or `write_volatile(..{name}..)`). This rule closes the "
                    "`static mut`-as-loophole escape from the "
                    "immutable-global check."
                ),
            }
    return None

_STACKID_MATCH_RE = re.compile(
    r"match\s+(?:unsafe\s*\{\s*)?[^{};]*?\bget_stackid\b[^{}]*?\}?\s*\{",
    re.MULTILINE | re.DOTALL,
)

_STACKID_LOCAL_BINDING_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?\s*=\s*[^;]*?\bget_stackid\b[^;]*?;",
    re.DOTALL,
)
_STACKID_ERR_FOLD_RE = re.compile(
    r"\bErr\s*\(\s*(\w+)\s*\)\s*=>\s*(?:\1\s*(?:as\s+i(?:8|16|32|64))?\s*[,}])"
)
_STACKID_UNWRAP_OR_ELSE_RE = re.compile(
    r"\bget_stackid\b[^;]*?\.unwrap_or_else\s*\(\s*\|\s*(\w+)\s*\|\s*\1\s*\)",
    re.DOTALL,
)

_STACKID_UNWRAP_OR_RE = re.compile(
    r"\bget_stackid\b[^;]*?\.unwrap_or\s*\(",
    re.DOTALL,
)

_STACKID_ERR_ARM_START_RE = re.compile(
    r"\bErr\s*\([^)]*\)\s*=>"
)

def _err_arm_body(block, arm_match_start):
    """Extract the body of an `Err(...) => <body>` arm starting at the given
    offset within `block`. Walks forward across balanced `{ }` and stops at
    the next top-level `,` or `}`. Returns the body text (without the trailing
    delimiter)."""
    arrow = block.find("=>", arm_match_start)
    if arrow == -1:
        return ""
    i = arrow + 2
    while i < len(block) and block[i].isspace():
        i += 1
    body_start = i
    depth = 0
    while i < len(block):
        c = block[i]
        if c == "{":
            depth += 1
        elif c == "}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    return block[body_start:i]

def _check_stackid_err_fold(code):
    """Forbid folding the Err arm of `get_stackid` Result back into a typed
    slot AND require an early-exit (`return`) on every Err arm.

    The C bug is "negative errno reinterpreted as a huge unsigned u32, used as
    a map key, polluting the map with spurious entries." Two source-level
    shapes re-create this bug:

    1. Folding the errno itself (`Err(e) => e`, `Err(e) => e as i32`,
       `unwrap_or_else(|e| e)`) — many distinct spurious keys, one per errno.

    2. Substituting a sentinel constant (`Err(_) => -1`, `unwrap_or(-1)`) —
       one spurious key, but the failed event still pollutes the map.

    Only an explicit early exit (`Err(_) => return ...`, `?`-propagation, or a
    block body containing `return`) prevents the failed event from reaching
    the map. This rule rejects both shapes; the Prescribed shape is
    `Err(_) => return ...` (or `?`-propagation upstream of the match).
    """
    def _inspect_match_block(block):
        """Apply the fold + early-return checks to the body of a match block.
        Returns a violation dict if the body folds the errno or substitutes a
        sentinel without an early exit; otherwise None."""

        if _STACKID_ERR_FOLD_RE.search(block):
            return {
                "pattern": "stackid Err-fold",
                "message": (
                    "Do not fold the Err arm of an Aya `get_stackid` Result "
                    "back into the success-typed slot via `Err(e) => e` or "
                    "`Err(e) => e as iN`. This silently re-creates the C bug "
                    "of using a negative errno as a map key. Prescribed "
                    "shape: `Err(_) => return ...` (or `?`-propagation)."
                ),
            }

        for arm in _STACKID_ERR_ARM_START_RE.finditer(block):
            body = _err_arm_body(block, arm.start())
            if not re.search(r"\breturn\b", body):
                return {
                    "pattern": "stackid Err sentinel-substitution",
                    "message": (
                        "Every `get_stackid` Err arm must early-exit via "
                        "`return ...`. Substituting a sentinel constant "
                        "(`Err(_) => -1`, `Err(_) => 0`, etc.) lets the "
                        "failed event continue and write a spurious key into "
                        "the downstream map, partially preserving the C bug. "
                        "Prescribed shape: `Err(_) => return 0,` or "
                        "`Err(_) => return Ok(0),` (matched to the function's "
                        "return type)."
                    ),
                }
        return None

    def _read_match_body(start_idx):
        """Walk forward from a `match ... {` opening brace position and
        return the body text up to (but not including) the matching `}`."""
        depth = 1
        i = start_idx
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        return code[start_idx:i - 1]

    for m in _STACKID_MATCH_RE.finditer(code):
        block = _read_match_body(m.end())
        violation = _inspect_match_block(block)
        if violation:
            return violation

    for binding in _STACKID_LOCAL_BINDING_RE.finditer(code):
        var = binding.group(1)
        match_re = re.compile(r"\bmatch\s+" + re.escape(var) + r"\s*\{",
                              re.MULTILINE)
        for m in match_re.finditer(code, binding.end()):
            block = _read_match_body(m.end())
            violation = _inspect_match_block(block)
            if violation:

                violation["pattern"] = (
                    "indirect-match " + violation["pattern"]
                )
                violation["message"] = (
                    f"Indirect-match bypass detected: a `let {var} = "
                    f"...get_stackid(...)` binding feeds into a downstream "
                    f"`match {var} {{ ... }}` whose Err arm is unsafe.\n\n"
                    + violation["message"]
                )
                return violation

    if _STACKID_UNWRAP_OR_ELSE_RE.search(code):
        return {
            "pattern": "stackid unwrap_or_else(|e| e)",
            "message": (
                "Do not collapse `get_stackid` Result via "
                "`unwrap_or_else(|e| e)`. This bypasses the typed Err handle "
                "and re-creates the C bug of folding the error code into "
                "the success value. Use `match` with an early-return Err "
                "arm or `?`-propagation."
            ),
        }

    if _STACKID_UNWRAP_OR_RE.search(code):
        return {
            "pattern": "stackid unwrap_or(<expr>)",
            "message": (
                "Do not collapse `get_stackid` Result via "
                "`unwrap_or(<expr>)`. Even though the typed Err handle is "
                "discarded, the failed event still flows downstream with a "
                "sentinel stack-id and pollutes the map. Use `match` with "
                "an early-return Err arm: `Err(_) => return 0,`."
            ),
        }

    return None

_FAILABLE_HELPER_NAMES_FOR_MATCH_RE = (

    "bpf_probe_read_kernel",
    "bpf_probe_read_user",
    "bpf_probe_read_kernel_str_bytes",
    "bpf_probe_read_user_str_bytes",
    "bpf_probe_read_kernel_buf",
    "bpf_probe_read_user_buf",
    "bpf_get_current_comm",
)
_FAILABLE_HELPER_MATCH_RE = re.compile(
    r"match\s+(?:unsafe\s*\{\s*)?[^{};]*?\b("
    + "|".join(re.escape(h) for h in _FAILABLE_HELPER_NAMES_FOR_MATCH_RE)
    + r")\b[^{}]*?\}?\s*\{",
    re.MULTILINE | re.DOTALL,
)

def _check_failable_helper_err_must_return(code):
    """For every `match` block whose scrutinee is a failable BPF helper call,
    the Err arm body must contain a `return` (or `?`-propagation upstream).

    Catches `match bpf_X(...) { Ok(v) => ..., Err(_) => {} }` — the explicit-
    but-empty Err arm pattern that silently allows the surrounding code to
    continue with whatever default state the destination buffer holds. For
    helpers like `bpf_get_current_comm` and `bpf_probe_read_*`, this can
    let a partial-init or zero-content record flow downstream into a map
    insert / ringbuf submit.

    Mirror of `_check_stackid_err_fold`'s pattern (c) but applied to the
    broader failable-helper set. `bpf_get_stackid` is handled separately by
    `_check_stackid_err_fold` to preserve its stricter literal-echo and
    sentinel-substitution checks.
    """
    def _read_match_body(start_idx):
        depth = 1
        i = start_idx
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        return code[start_idx:i - 1]

    for m in _FAILABLE_HELPER_MATCH_RE.finditer(code):
        helper = m.group(1)
        block = _read_match_body(m.end())
        for arm in _STACKID_ERR_ARM_START_RE.finditer(block):
            body = _err_arm_body(block, arm.start())
            if not re.search(r"\breturn\b", body):
                return {
                    "pattern": f"failable-helper Err arm without return ({helper})",
                    "message": (
                        f"Every `match` block scrutinizing `{helper}` must "
                        f"early-exit on the Err arm via `return ...` (or "
                        f"propagate via `?`). Empty Err arms like "
                        f"`Err(_) => {{}}` let the surrounding code continue "
                        f"with a partial-init record (zero-content buffer "
                        f"from upstream init) and emit it downstream — "
                        f"silently masking helper failures. Prescribed "
                        f"shape: `Err(_) => return Ok(0),` or use "
                        f"`?`-propagation."
                    ),
                }
    return None

_CROSS_PATTERN_CHECKS = [
    _check_ringbuf_zero_init,
    _check_hashmap_unsafe_field_write,
    _check_immutable_global_read_volatile,
    _check_readonly_static_mut_reads,
    _check_stackid_err_fold,
    _check_failable_helper_err_must_return,
]

def _collect_banned_violations(source_code):
    """Collect banned-pattern violations as structured dicts.

    Comments are stripped before scanning so that doc/inline comments
    explaining what NOT to do do not trigger false positives.
    """
    code = _strip_rust_comments(source_code)
    violations = []

    for pattern, msg in _STRING_BANS:
        if pattern in code:
            violations.append({"pattern": pattern, "message": msg})

    for regex, msg in _REGEX_BANS:
        for line in code.splitlines():
            if regex.search(line):
                violations.append({"pattern": regex.pattern, "message": msg})
                break

    for check_fn in _CROSS_PATTERN_CHECKS:
        violation = check_fn(code)
        if violation:
            violations.append(violation)
    return violations

def _collect_statement(lines, line_idx):
    """Collect a rough statement around a target line for multiline audits.

    Stops backward at any of:
      - line ending with ';'         (statement terminator)
      - line whose stripped form ends with '}'  (block-expression close)
      - blank line                   (not part of the statement)

    This prevents the collector from drifting across earlier blocks and
    incorrectly attributing a `.ok()` on a map operation to a helper call
    inside an *adjacent but unrelated* `match` / `if let` block above.
    """
    def _is_boundary(line: str) -> bool:
        s = line.strip()
        if not s:
            return True
        if s.endswith(";"):
            return True
        if s.endswith("}") or s == "}":
            return True
        return False

    start = line_idx
    while start > 0 and not _is_boundary(lines[start - 1]):
        start -= 1

    end = line_idx
    while end + 1 < len(lines) and ";" not in lines[end]:
        end += 1

    return " ".join(line.strip() for line in lines[start : end + 1])

def _collect_safety_audit_warnings(source_code):
    """[Helper-Result-discard violations — now blocking, 2026-04-27].

    Checks for helper Result values discarded via `let _ = ...` /
    `let _foo = ...` / `.ok()` on a failable helper.  Returns a list of
    violation-shaped dicts (pattern + message), so analyze_safety() can
    merge them into the blocking-violation list.

    Rationale: the audit was previously non-blocking because we wanted
    faithful translation of C's silent-discard idiom.  Promoting these to
    blocking forces the agent to handle helper Results explicitly via
    control flow (e.g., `match h(...) {{ Ok(_) => ..., Err(_) => ... }}`).
    Equivalence under default symbex (helper_fail_mode=off) is unchanged
    — the failure branches are unreachable.  See
    ebpf-to-rust/helper_returns_audit_note.txt.
    """
    violations = []
    lines = source_code.splitlines()

    def _violation(helper, line_num, kind):
        return {
            "pattern": f"{helper} Result discarded",
            "message": (
                f"Line {line_num}: helper Result discarded with {kind} "
                f"({helper}). Replace with explicit handling such as "
                f"`match {helper}(...) {{ Ok(_) => {{}}, Err(_) => {{}} }};` "
                f"(no-op match preserves C's continue-on-failure semantics) "
                f"or take an early-return on Err if the surrounding code "
                f"should bail when the helper fails."
            ),
        }

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        bind_match = _UNDERSCORE_BIND_RE.search(stripped)
        if bind_match:
            stmt = _collect_statement(lines, line_num - 1)
            if not any(marker in stmt for marker in _HANDLED_RESULT_MARKERS):
                for helper in _SORTED_FAILABLE_HELPER_PATTERNS:
                    if helper in stmt:
                        binding = bind_match.group(1)
                        kind = "let _ =" if binding == "_" else f"underscore binding `{binding}`"
                        violations.append(_violation(helper, line_num, kind))
                        break

        if re.search(r"\.ok\s*\(\s*\)\s*;", stripped):
            stmt = _collect_statement(lines, line_num - 1)
            for helper in _SORTED_FAILABLE_HELPER_PATTERNS:
                if helper in stmt:
                    violations.append(_violation(helper, line_num, ".ok()"))
                    break

    for v in _collect_match_wildcard_drops(source_code):
        violations.append(v)

    return violations

def _walk_match_body(source_code, match_start):
    """Locate the matched-expression text and the body text for a `match`
    keyword at ``match_start``.  Handles ``match unsafe { ... } { ... }``
    where the matched expression itself contains a brace-delimited block.

    Returns ``(expr_text, body_text)`` or ``None`` if the source is malformed
    or doesn't fit the recognized shape.
    """
    i = match_start + len("match")
    while i < len(source_code) and source_code[i].isspace():
        i += 1
    expr_start = i
    if source_code[i:i + 6] == "unsafe":
        i += 6
        while i < len(source_code) and source_code[i].isspace():
            i += 1
        if i >= len(source_code) or source_code[i] != "{":
            return None
        depth = 1
        i += 1
        while i < len(source_code) and depth > 0:
            if source_code[i] == "{":
                depth += 1
            elif source_code[i] == "}":
                depth -= 1
            i += 1
    else:

        while i < len(source_code) and source_code[i] != "{":
            i += 1
    if i >= len(source_code):
        return None
    expr_text = source_code[expr_start:i]
    while i < len(source_code) and source_code[i].isspace():
        i += 1
    if i >= len(source_code) or source_code[i] != "{":
        return None
    body_start = i + 1
    depth = 1
    j = body_start
    while j < len(source_code) and depth > 0:
        if source_code[j] == "{":
            depth += 1
        elif source_code[j] == "}":
            depth -= 1
        j += 1
    if depth != 0:
        return None
    body_text = source_code[body_start:j - 1]
    return expr_text, body_text

def _collect_match_wildcard_drops(source_code):
    """Detect `match <failable-helper(...)> { _ => ... }` silent-drop idiom.

    The arm `_ => ...` collapses both Ok and Err into `()`, dropping the
    error case without distinguishing it.  Equivalent in effect to
    `let _ = helper(...);` but expressed via a `match` block, so the
    underscore-bind regex above misses it.
    """
    violations = []
    for m in re.finditer(r"\bmatch\b", source_code):
        result = _walk_match_body(source_code, m.start())
        if result is None:
            continue
        expr_text, body_text = result

        if "Ok(" in body_text or "Err(" in body_text:
            continue
        if not re.search(r"\b_\s*=>", body_text):
            continue

        for helper in _SORTED_FAILABLE_HELPER_PATTERNS:
            if helper in expr_text:
                line_num = source_code[: m.start()].count("\n") + 1
                violations.append({
                    "pattern": f"{helper} Result discarded via match wildcard arm",
                    "message": (
                        f"Line {line_num}: helper Result discarded with "
                        f"`match {{ _ => ... }}` ({helper}). The wildcard arm "
                        f"collapses both Ok and Err into `()`. Replace with "
                        f"explicit handling such as "
                        f"`match {helper}(...) {{ Ok(_) => {{}}, Err(_) => {{}} }};` "
                        f"(no-op-but-explicit) or branch on Err if the "
                        f"surrounding code should bail when the helper fails."
                    ),
                })
                break
    return violations

def _dedupe_preserve_order(items):
    """Return items with duplicates removed while preserving order."""
    deduped = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped

def analyze_safety(source_code):
    """Return a structured safety report for the given source.

    As of 2026-04-27, helper-Result-discard findings are merged into the
    blocking-violation list (previously they were non-blocking warnings).
    The `warnings` field stays in the return shape for backward compat
    but is now always empty.
    """
    violations = _collect_banned_violations(source_code)
    violations.extend(_collect_safety_audit_warnings(source_code))
    fix_hints = _dedupe_preserve_order(v["message"] for v in violations)
    return {
        "blocking": bool(violations),
        "summary": f"{len(violations)} blocking violation(s)",
        "violations": violations,
        "warnings": [],
        "fix_hints": fix_hints,
    }

def format_safety_report(report, rs_path="source", include_warnings=True):
    """Format a structured safety report for CLI or LLM feedback."""
    lines = []
    if report["violations"]:
        lines.append(f"[SAFETY CHECK] FAILED — banned patterns found in {rs_path}:")
        for violation in report["violations"]:
            lines.append(f"  Pattern: `{violation['pattern']}`")
            lines.append(f"  Reason:  {violation['message']}")
        if report["fix_hints"]:
            lines.append("")
            lines.append("[SAFETY CHECK] Suggested fixes:")
            for hint in report["fix_hints"]:
                lines.append(f"  - {hint}")
    else:
        lines.append(f"[SAFETY CHECK] PASSED — {rs_path}")

    if include_warnings and report["warnings"]:
        lines.append("")
        if report["violations"]:
            lines.append("[SAFETY AUDIT] Additional warnings:")
        else:
            lines.append(f"[SAFETY AUDIT] Warnings for {rs_path} (not blocking):")
        lines.extend(report["warnings"])

    return "\n".join(lines)

def check_banned(source_code):
    """Check source for banned patterns.

    Returns list of (pattern_description, message) tuples for each violation found.
    Checks both simple string matches and per-line regex matches.
    """
    report = analyze_safety(source_code)
    return [(v["pattern"], v["message"]) for v in report["violations"]]

def safety_audit(source_code):
    """Post-compile safety audit. Returns list of warning strings."""
    report = analyze_safety(source_code)
    return report["warnings"]
