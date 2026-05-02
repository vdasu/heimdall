"""Enhanced counter-example formatting for LLM equivalence fixing.

E3: classify_divergence() — categorizes mismatch patterns.
E4: heuristic_annotate_helpers() — annotates Rust source with counter-example values.
"""

import re
import struct

def classify_divergence(c_val, r_val, field_bits=64):
    """Classify the type of mismatch between C and Rust output values.

    Returns a short diagnosis string describing the likely bug pattern.
    """
    if not isinstance(c_val, int) or not isinstance(r_val, int):
        return "GENERAL_MISMATCH: non-integer values"

    if c_val == r_val:
        return "NO_DIVERGENCE"

    mask = (1 << field_bits) - 1
    c_val = c_val & mask
    r_val = r_val & mask

    if r_val == 0 and c_val != 0:
        return "MISSING_WRITE: Rust produced 0, C produced a value. Likely a missed branch or map update."
    if c_val == 0 and r_val != 0:
        return "EXTRA_WRITE: Rust produced a value where C produced 0. Likely entering a branch C skips."

    diff = c_val ^ r_val

    abs_diff = abs(c_val - r_val)
    if abs_diff <= 16:
        return f"OFF_BY_{abs_diff}: Values are close. Likely an off-by-one or wrong constant."

    if field_bits >= 64:
        if (diff & 0xFFFFFFFF) == 0 and (diff & 0xFFFFFFFF00000000) != 0:
            low32 = c_val & 0xFFFFFFFF
            c_high = (c_val >> 32) & 0xFFFFFFFF
            r_high = (r_val >> 32) & 0xFFFFFFFF
            if c_high == 0 and r_high == 0xFFFFFFFF and (low32 & 0x80000000):
                return "SIGN_EXTENSION: Rust sign-extended a negative 32-bit value to 64 bits. Use zero-extension (as u32 as u64) instead."
            if c_high == 0xFFFFFFFF and r_high == 0 and (low32 & 0x80000000):
                return "MISSING_SIGN_EXTENSION: C sign-extended but Rust zero-extended. Use (as i32 as i64) cast."
            return "UPPER_32_BITS: Only high 32 bits differ. Likely a sign-extension or 32-vs-64-bit cast issue."

    if field_bits >= 64:
        c_lo = c_val & 0xFFFFFFFF
        r_lo = r_val & 0xFFFFFFFF
        if c_val != 0 and r_val != 0 and c_lo != r_lo:
            if c_lo == ((r_val >> 32) & 0xFFFFFFFF) and c_val <= 0xFFFFFFFF:
                return "SHIFT_32: C value matches upper 32 bits of Rust. Check pid/tgid or uid/gid extraction (>> 32 vs & 0xFFFFFFFF)."
            if ((c_val >> 32) & 0xFFFFFFFF) == r_lo and r_val <= 0xFFFFFFFF:
                return "SHIFT_32: Rust value matches upper 32 bits of C. Check pid/tgid or uid/gid extraction (>> 32 vs & 0xFFFFFFFF)."

    if field_bits >= 64:
        if c_val > 0xFFFFFFFF and r_val <= 0xFFFFFFFF and (c_val & 0xFFFFFFFF) == r_val:
            return "TRUNCATION: Rust has 32-bit truncation of C value. Check cast widths (u64 vs u32)."
        if r_val > 0xFFFFFFFF and c_val <= 0xFFFFFFFF and (r_val & 0xFFFFFFFF) == c_val:
            return "TRUNCATION: C has 32-bit truncation of Rust value. Check cast widths (u64 vs u32)."

    if field_bits >= 64:
        try:
            c_bytes = c_val.to_bytes(8, 'big')
            r_bytes = r_val.to_bytes(8, 'big')
            if c_bytes == r_bytes[::-1] and c_bytes != r_bytes:
                return "ENDIANNESS: Values are byte-swapped (64-bit). Check .to_be()/.to_le() or htonll/ntohll."
        except (OverflowError, ValueError):
            pass
    if field_bits >= 32:
        try:
            c_lo_bytes = (c_val & 0xFFFFFFFF).to_bytes(4, 'big')
            r_lo_bytes = (r_val & 0xFFFFFFFF).to_bytes(4, 'big')
            if c_lo_bytes == r_lo_bytes[::-1] and c_lo_bytes != r_lo_bytes:
                return "ENDIANNESS: Values are byte-swapped (32-bit). Check .to_be()/.to_le() or htonl/ntohl."
        except (OverflowError, ValueError):
            pass

    if field_bits >= 64:
        if (diff & 0xFFFFFFFF00000000) == 0 and (diff & 0xFFFFFFFF) != 0:
            if c_val > 0xFFFFFFFF or r_val > 0xFFFFFFFF:
                return "LOWER_32_BITS: Only low 32 bits differ. Likely an arithmetic or truncation issue."

    if c_val == (~r_val & mask):
        return "BITWISE_INVERSION: Values are bitwise complements. Check negation or NOT logic."

    return "GENERAL_MISMATCH: Values differ significantly. Compare the logic paths carefully."

_HELPER_VAR_MAP = {
    "bpf_ktime_get_ns":            "input_ktime_v",
    "bpf_get_current_pid_tgid":    "input_pid_tgid_v",
    "bpf_get_current_uid_gid":     "input_uid_gid_v",
    "bpf_get_current_comm":        "input_current_comm_v",
    "bpf_get_smp_processor_id":    "input_smp_processor_id_v",
    "bpf_get_prandom_u32":         "input_prandom_v",
}

_HELPER_SOURCE_PATTERNS = {
    "bpf_ktime_get_ns":         re.compile(r'bpf_ktime_get_ns\s*\('),
    "bpf_get_current_pid_tgid": re.compile(r'bpf_get_current_pid_tgid\s*\('),
    "bpf_get_current_uid_gid":  re.compile(r'bpf_get_current_uid_gid\s*\('),
    "bpf_get_current_comm":     re.compile(r'bpf_get_current_comm\s*\('),
    "bpf_get_smp_processor_id": re.compile(r'bpf_get_smp_processor_id\s*\('),
    "bpf_get_prandom_u32":      re.compile(r'bpf_get_prandom_u32\s*\('),
}

def _collect_helper_values(shared_var_values):
    """Collect helper return values grouped by helper name.

    Returns dict: helper_name → list of (version_idx, value).
    """
    result = {}
    for var_name, value in sorted(shared_var_values.items()):
        for helper_name, prefix in _HELPER_VAR_MAP.items():

            clean = var_name
            if clean.startswith("shared_"):
                clean = clean[len("shared_"):]
            if clean.startswith(prefix):
                suffix = clean[len(prefix):]
                try:
                    version = int(suffix)
                except ValueError:
                    continue
                result.setdefault(helper_name, []).append((version, value))
                break
    return result

def _format_helper_value(helper_name, value):
    """Format a single helper return value with decomposition where appropriate."""
    if not isinstance(value, int):
        return str(value)

    if helper_name == "bpf_get_current_pid_tgid":
        pid = value & 0xFFFFFFFF
        tgid = (value >> 32) & 0xFFFFFFFF
        return f"{hex(value)} (pid={pid}, tgid={tgid})"
    elif helper_name == "bpf_get_current_uid_gid":
        uid = value & 0xFFFFFFFF
        gid = (value >> 32) & 0xFFFFFFFF
        return f"{hex(value)} (uid={uid}, gid={gid})"
    elif helper_name == "bpf_get_current_comm":

        try:
            raw = value.to_bytes(16, 'big')
            text = raw.split(b'\x00', 1)[0].decode('ascii', errors='replace')
            return f"{hex(value)} (\"{text}\")"
        except (OverflowError, ValueError):
            return hex(value)
    else:
        return hex(value)

def heuristic_annotate_helpers(rust_code, shared_var_values):
    """Annotate Rust source with counter-example helper return values.

    Single-call helpers (1 occurrence in source) get inline annotations.
    Multi-call helpers get a summary block at the top.

    Args:
        rust_code: Rust source code string
        shared_var_values: dict of shared variable name → concrete value

    Returns:
        Annotated Rust source code string
    """
    if not shared_var_values:
        return rust_code

    helper_values = _collect_helper_values(shared_var_values)
    if not helper_values:
        return rust_code

    lines = rust_code.splitlines()

    helper_counts = {}
    helper_line_indices = {}
    for helper_name, pattern in _HELPER_SOURCE_PATTERNS.items():
        if helper_name not in helper_values:
            continue
        indices = []
        for i, line in enumerate(lines):
            if pattern.search(line):
                indices.append(i)
        helper_counts[helper_name] = len(indices)
        helper_line_indices[helper_name] = indices

    inline_annotations = {}
    multi_call_summaries = []

    for helper_name, versions in sorted(helper_values.items()):
        count = helper_counts.get(helper_name, 0)

        if count == 1 and len(versions) == 1:

            line_idx = helper_line_indices[helper_name][0]
            _, value = versions[0]
            formatted = _format_helper_value(helper_name, value)
            inline_annotations[line_idx] = f"    // ^^ counter-example: returns {formatted}"
        else:

            parts = []
            for ver_idx, value in sorted(versions):
                formatted = _format_helper_value(helper_name, value)
                parts.append(f"v{ver_idx}={formatted}")
            call_word = "time" if len(versions) == 1 else "times"
            multi_call_summaries.append(
                f"// {helper_name}() called {len(versions)} {call_word}: {', '.join(parts)}"
            )

    for line_idx in sorted(inline_annotations.keys(), reverse=True):
        lines.insert(line_idx + 1, inline_annotations[line_idx])

    if multi_call_summaries:
        header = ["// == Counter-example helper return values (execution order) =="]
        header.extend(multi_call_summaries)
        header.append("")
        lines = header + lines

    return "\n".join(lines)

_AYA_ATOMIC_PATTERNS = {
    "add": ".fetch_add(val, Ordering::Relaxed)",
    "or": ".fetch_or(val, Ordering::Relaxed)",
    "and": ".fetch_and(val, Ordering::Relaxed)",
    "xor": ".fetch_xor(val, Ordering::Relaxed)",
    "xchg": ".swap(val, Ordering::Relaxed)",
    "cmpxchg": ".compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed)",
}

def format_atomic_mismatch(c_atomic_ops, r_atomic_ops):
    """Format an atomic operation mismatch for LLM feedback.

    Args:
        c_atomic_ops: list of AtomicOpRecord from C program
        r_atomic_ops: list of AtomicOpRecord from Rust program

    Returns:
        Formatted mismatch string for LLM equivalence fix prompt
    """
    lines = []

    if len(r_atomic_ops) == 0:
        lines.append("ATOMIC OPERATION MISMATCH (total drop)")
        lines.append("")
        lines.append(f"The C program uses {len(c_atomic_ops)} atomic operation(s), "
                     "but the Rust translation uses NONE.")
    else:
        lines.append("PARTIAL ATOMIC OPERATION MISMATCH")
        lines.append("")
        lines.append(f"The C program uses {len(c_atomic_ops)} atomic operation(s), "
                     f"but the Rust translation only has {len(r_atomic_ops)}.")

    lines.append("")
    lines.append("C atomic operations:")
    for op in c_atomic_ops:
        lines.append(f"  offset=0x{op.offset:x}: {op.width}-bit atomic {op.op_name} "
                     f"(fetch={op.is_fetch})")

    if r_atomic_ops:
        lines.append("")
        lines.append("Rust atomic operations (present):")
        for op in r_atomic_ops:
            lines.append(f"  offset=0x{op.offset:x}: {op.width}-bit atomic {op.op_name} "
                         f"(fetch={op.is_fetch})")

    lines.append("")
    lines.append("FIX INSTRUCTIONS:")
    lines.append("You MUST use core::sync::atomic operations instead of plain pointer dereferences.")
    lines.append("")
    lines.append("Required import:")
    lines.append("  use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};")
    lines.append("")
    lines.append("Translation patterns:")

    seen_ops = set()
    for op in c_atomic_ops:
        seen_ops.add((op.op_name, op.width))

    for op_name, width in sorted(seen_ops):
        atom_type = f"AtomicU{width}"
        aya_pattern = _AYA_ATOMIC_PATTERNS.get(op_name, f".{op_name}(...)")

        c_builtin = f"__sync_fetch_and_{op_name}" if op_name not in ("xchg", "cmpxchg") else (
            "__sync_lock_test_and_set" if op_name == "xchg" else "__sync_val_compare_and_swap"
        )

        lines.append(f"  {c_builtin}(ptr, val) →")
        lines.append(f"    unsafe {{ {atom_type}::from_ptr(ptr) }}{aya_pattern}")

    lines.append("")
    lines.append("Example (fetch_add):")
    lines.append("  // C:    __sync_fetch_and_add(val, 1);")
    lines.append("  // Rust: unsafe { AtomicU64::from_ptr(val) }.fetch_add(1, Ordering::Relaxed);")

    return "\n".join(lines)

def format_counter_example(
    shared_var_values,
    c_output_val,
    r_output_val,
    map_divergences,
    program_type="default",
    ctx_fields_meta=None,
):
    """Format a complete counter-example for LLM feedback.

    Args:
        shared_var_values: dict of shared variable name → concrete value
        c_output_val: C program return value (int or str)
        r_output_val: Rust program return value (int or str)
        map_divergences: list of dicts with keys:
            map_name, query_key, c_val, r_val, c_present, r_present
        program_type: eBPF program type string
        ctx_fields_meta: optional dict of field_name → (offset, bits, value)
            for per-field context display

    Returns:
        Formatted counter-example string
    """
    ce_lines = []

    ce_lines.append("Counter-Example Inputs:")

    if ctx_fields_meta:
        ce_lines.append(f"  Context ({program_type}):")
        for name, (offset, bits, value) in sorted(ctx_fields_meta.items(), key=lambda x: x[1][0]):
            display = hex(value) if isinstance(value, int) else str(value)
            ce_lines.append(f"    {name:<24} = {display}")
    else:

        for name, value in sorted(shared_var_values.items()):
            if "input_bpf_ctx" in name or "input_ctx_" in name:
                display = hex(value) if isinstance(value, int) else str(value)
                ce_lines.append(f"  {name}: {display}")

    map_init_entries = {}
    for name, value in sorted(shared_var_values.items()):
        if "shared_init_map_" in name:
            display = hex(value) if isinstance(value, int) else str(value)
            map_init_entries[name] = display
    if map_init_entries:
        ce_lines.append("  Map initial values:")
        for name, display in sorted(map_init_entries.items()):
            clean = name.replace("shared_init_", "").replace("shared_", "")
            ce_lines.append(f"    {clean}: {display}")

    helper_values = _collect_helper_values(shared_var_values)
    if helper_values:
        ce_lines.append("  BPF helper return values:")
        for helper_name, versions in sorted(helper_values.items()):
            for ver_idx, value in sorted(versions):
                formatted = _format_helper_value(helper_name, value)
                suffix = f"_v{ver_idx}" if len(versions) > 1 else ""
                ce_lines.append(f"    {helper_name}(){suffix} = {formatted}")

    shown = set()
    for name in sorted(shared_var_values.keys()):
        if any(x in name for x in ("init_map_", "input_ctx_", "input_bpf_ctx")):
            continue

        clean = name[len("shared_"):] if name.startswith("shared_") else name
        is_helper = any(clean.startswith(prefix) for prefix in _HELPER_VAR_MAP.values())
        if is_helper:
            continue
        if name not in shown:
            shown.add(name)
            value = shared_var_values[name]
            display = hex(value) if isinstance(value, int) else str(value)
            display_name = name if len(name) < 50 else name[:45] + "..."
            ce_lines.append(f"  {display_name}: {display}")

    ce_lines.append("\nDiverging Outputs:")

    if c_output_val != r_output_val:
        c_disp = hex(c_output_val) if isinstance(c_output_val, int) else str(c_output_val)
        r_disp = hex(r_output_val) if isinstance(r_output_val, int) else str(r_output_val)
        diag = classify_divergence(
            c_output_val if isinstance(c_output_val, int) else 0,
            r_output_val if isinstance(r_output_val, int) else 0,
        )
        ce_lines.append(f"  Return Value:")
        ce_lines.append(f"    C:         {c_disp}")
        ce_lines.append(f"    Rust:      {r_disp}")
        if diag != "NO_DIVERGENCE":
            ce_lines.append(f"    Diagnosis: {diag}")

    for div in map_divergences:
        map_name = div['map_name']
        qk = div['query_key']
        qk_disp = hex(qk) if isinstance(qk, int) else str(qk)

        c_val = div.get('c_val')
        r_val = div.get('r_val')
        c_present = div.get('c_present')
        r_present = div.get('r_present')

        ce_lines.append(f"  Map '{map_name}' at key={qk_disp}:")

        if c_val is not None and r_val is not None and c_val != r_val:
            c_disp = hex(c_val) if isinstance(c_val, int) else str(c_val)
            r_disp = hex(r_val) if isinstance(r_val, int) else str(r_val)
            ce_lines.append(f"    C value:    {c_disp}")
            ce_lines.append(f"    Rust value: {r_disp}")
            val_bits = div.get('val_bits', 64)
            diag = classify_divergence(c_val, r_val, field_bits=val_bits)
            if diag != "NO_DIVERGENCE":
                ce_lines.append(f"    Diagnosis:  {diag}")

        if c_present is not None and r_present is not None and c_present != r_present:
            c_p = "present" if c_present else "absent"
            r_p = "present" if r_present else "absent"
            ce_lines.append(f"    C key {c_p}, Rust key {r_p}")
            if c_present and not r_present:
                ce_lines.append(f"    Diagnosis:  MISSING_KEY: Rust did not create this map entry.")
            elif not c_present and r_present:
                ce_lines.append(f"    Diagnosis:  EXTRA_KEY: Rust created an entry that C did not.")

    return "\n".join(ce_lines)
