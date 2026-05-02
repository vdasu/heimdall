import argparse
import sys
import re
import z3
import claripy
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from claripy.backends import BackendZ3
backend = BackendZ3()

from generate_formula import (
    generate_formula_for_program,
    get_ctx_size_for_program,
    get_program_type_from_elf,
    build_ctx_shared_vars,
    ProgramFormula,
    _DATA_SYMBOLIZE_LIMIT,
)

try:
    from counter_example_formatter import (
        classify_divergence,
        format_counter_example,
        format_atomic_mismatch,
    )
except ImportError:
    from c2rust_translation.counter_example_formatter import (
        classify_divergence,
        format_counter_example,
        format_atomic_mismatch,
    )

try:
    from btf_parser import parse_map_metadata_from_btf, is_void_return_via_btf
except ImportError:
    from c2rust_translation.btf_parser import parse_map_metadata_from_btf, is_void_return_via_btf

try:
    from verify_ebpf_kernel import find_maps as _find_maps_for_type_check
except ImportError:
    from c2rust_translation.verify_ebpf_kernel import find_maps as _find_maps_for_type_check

VALID_HELPER_FAIL_MODES = ("off", "all", "selected")
DEFAULT_FAILABLE_HELPERS = (
    "bpf_probe_read",
    "bpf_probe_read_user",
    "bpf_probe_read_user_str",
    "get_current_comm",
    "perf_event_output",
    "get_stack",
    "get_stackid",
    "current_task_under_cgroup",
    "ringbuf_reserve",
)
HELPER_FAIL_ALIASES = {
    "probe_read": "bpf_probe_read",
    "probe_read_user": "bpf_probe_read_user",
    "probe_read_user_str": "bpf_probe_read_user_str",
    "get_comm": "get_current_comm",
    "current_comm": "get_current_comm",
    "stack": "get_stack",
    "stackid": "get_stackid",
    "under_cgroup": "current_task_under_cgroup",
    "task_under_cgroup": "current_task_under_cgroup",
    "ringbuf": "ringbuf_reserve",
}

def normalize_helper_fail_helpers(raw_helpers):
    normalized = set()
    if not raw_helpers:
        return normalized

    for name in raw_helpers:
        h = (name or "").strip().lower().replace("-", "_")
        if not h:
            continue
        h = HELPER_FAIL_ALIASES.get(h, h)
        normalized.add(h)
    return normalized

@dataclass
class VerificationResult:
    equivalent: bool
    result_type: str
    counter_example: str = ""
    raw_model: Any = None
    shared_var_values: dict = field(default_factory=dict)

class Z3VariableUnifier:

    def __init__(self):

        self.input_re = re.compile(r'^(input_.+?)(?:_\d+_\d+)?$')

        self.map_init_re = re.compile(r'(map_.+?_(?:entry_|v)\d+)_\d+_\d+$')

        self.key_exists_re = re.compile(r'(key_exists_.+?)_\d+_\d+$')

        self.map_final_re = re.compile(
            r'((?:final_|key_for_)map_.+?_(?:entry_|v)\d+)_\d+_\d+$'
        )

        self.output_re = re.compile(r'(output_r0(?:_\w+?)?)_\d+_\d+$')

        self.shared_vars = {}

    def get_canonical_z3(self, z3_var, lang_tag):
        name = str(z3_var)
        sort = z3_var.sort()

        m = self.input_re.match(name)
        if m:
            logical_name = "shared_" + m.group(1)
            cache_key = (logical_name, sort)
            if cache_key not in self.shared_vars:
                self.shared_vars[cache_key] = z3.Const(logical_name, sort)
            return self.shared_vars[cache_key]

        m = self.key_exists_re.match(name)
        if m:
            logical_name = "shared_" + m.group(1)
            cache_key = (logical_name, sort)
            if cache_key not in self.shared_vars:
                self.shared_vars[cache_key] = z3.Const(logical_name, sort)
            return self.shared_vars[cache_key]

        m = re.match(r'(glob_.+?_init)_\d+_\d+$', name)
        if m:
            logical_name = "shared_" + m.group(1)
            cache_key = (logical_name, sort)
            if cache_key not in self.shared_vars:
                self.shared_vars[cache_key] = z3.Const(logical_name, sort)
            return self.shared_vars[cache_key]

        m = self.map_init_re.match(name)
        if m and not name.startswith("final_") and not name.startswith("key_for_"):
            logical_name = "shared_init_" + m.group(1)
            cache_key = (logical_name, sort)
            if cache_key not in self.shared_vars:
                self.shared_vars[cache_key] = z3.Const(logical_name, sort)
            return self.shared_vars[cache_key]

        m = self.output_re.match(name)
        if m:
            logical_name = f"outcome_return_{lang_tag}"
            return z3.Const(logical_name, sort)

        m = self.map_final_re.match(name)
        if m:
            base_name = m.group(1)
            logical_name = f"{base_name}_{lang_tag}"
            return z3.Const(logical_name, sort)

        return z3.Const(f"internal_{name}_{lang_tag}", sort)

    def convert_and_unify(self, claripy_ast, lang_tag):
        z3_ast = backend.convert(claripy_ast)
        return self._unify_z3_ast(z3_ast, lang_tag)

    def _unify_z3_ast(self, z3_ast, lang_tag):
        vars_found = set()
        visited = set()

        def collect(node):

            z3_id = node.get_id()
            if z3_id in visited:
                return
            visited.add(z3_id)
            if z3.is_const(node) and node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                vars_found.add(node)
            for c in node.children():
                collect(c)

        collect(z3_ast)

        substitutions = []
        for v in vars_found:
            new_v = self.get_canonical_z3(v, lang_tag)
            substitutions.append((v, new_v))

        return z3.substitute(z3_ast, substitutions)

    def normalize_ast(self, claripy_ast, lang_tag):
        print(f"[*] Converting {lang_tag.upper()} AST to Z3...")
        result = self.convert_and_unify(claripy_ast, lang_tag)
        print(f"    Unified variables for {lang_tag}")
        return result

def _collect_z3_vars(z3_ast):
    vs = set()
    visited = set()
    def walk(n):
        z3_id = n.get_id()
        if z3_id in visited:
            return
        visited.add(z3_id)
        if z3.is_const(n) and n.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            vs.add(n)
        for child in n.children():
            walk(child)
    walk(z3_ast)
    return {str(v): v for v in vs}

def build_map_ite_for_path(entries_z3, query_key, default_val):

    sorted_entries = sorted(entries_z3, key=lambda e: e[4])
    result = default_val
    for entry in sorted_entries:
        key_z3, val_z3, exists_z3 = entry[0], entry[1], entry[2]
        cond = query_key == key_z3

        if exists_z3 is not None:
            cond = z3.And(cond, exists_z3 == z3.BitVecVal(1, 1))
        result = z3.If(cond, val_z3, result)
    return result

def build_map_ite_presence_for_path(entries_z3, query_key, default_presence):
    sorted_entries = sorted(entries_z3, key=lambda e: e[4])
    result = default_presence
    PRESENT = z3.BitVecVal(1, 1)
    ABSENT = z3.BitVecVal(0, 1)
    for entry in sorted_entries:
        key_z3, _val_z3, exists_z3 = entry[0], entry[1], entry[2]
        key_match = query_key == key_z3
        if exists_z3 is not None:

            result = z3.If(key_match, z3.If(exists_z3 == PRESENT, PRESENT, ABSENT), result)
        else:

            result = z3.If(key_match, PRESENT, result)
    return result

def build_map_ite(paths_z3, map_name, query_key, default_val):
    result = default_val
    for path_pred_z3, path_map_entries in reversed(paths_z3):
        entries = path_map_entries.get(map_name, [])
        if not entries:

            continue
        path_map = build_map_ite_for_path(entries, query_key, default_val)
        result = z3.If(path_pred_z3, path_map, result)
    return result

def build_map_ite_presence(paths_z3, map_name, query_key, default_presence):
    result = default_presence
    for path_pred_z3, path_map_entries in reversed(paths_z3):
        entries = path_map_entries.get(map_name, [])
        if not entries:
            continue
        path_presence = build_map_ite_presence_for_path(entries, query_key, default_presence)
        result = z3.If(path_pred_z3, path_presence, result)
    return result

def verify_equivalence_ite(c_program_data, rust_program_data, unifier,
                           ctx_constraints=None, skip_r0=False):
    print("\n[=] Starting ITE-based Z3 Verification [=]")

    solver = z3.Solver()

    if ctx_constraints:
        print(f"    [+] Adding {len(ctx_constraints)} input constraints to solver")
        for claripy_c in ctx_constraints:
            z3_c = unifier.convert_and_unify(claripy_c, "c")
            solver.add(z3_c)

    def convert_program_paths(program_data, lang_tag):
        output_var_z3 = unifier.convert_and_unify(program_data.output_var, lang_tag)

        path_disjuncts = []
        paths_z3_list = []
        paths_z3_glob = []

        for i, path in enumerate(program_data.paths):

            path_pred_z3 = unifier.convert_and_unify(path.path_predicate, lang_tag)

            r0_z3 = unifier.convert_and_unify(path.output_r0_expr, lang_tag)
            output_eq = (output_var_z3 == r0_z3)

            path_disjuncts.append(z3.And(path_pred_z3, output_eq))

            path_maps_z3 = {}
            for map_name, entry_snapshots in path.map_snapshots.items():
                entries_z3 = []
                for snap in entry_snapshots:
                    key_z3 = unifier.convert_and_unify(snap.key_expr, lang_tag)
                    val_z3 = unifier.convert_and_unify(snap.final_value_expr, lang_tag)
                    exists_z3 = unifier.convert_and_unify(snap.exists_cond, lang_tag)
                    written = getattr(snap, 'written', True)
                    write_seq = getattr(snap, 'write_seq', -1)
                    entries_z3.append((key_z3, val_z3, exists_z3, written, write_seq))
                path_maps_z3[map_name] = entries_z3

            paths_z3_list.append((path_pred_z3, path_maps_z3))

            path_glob_z3 = {}
            for sym_name, final_bv in path.global_writes.items():
                path_glob_z3[sym_name] = unifier.convert_and_unify(final_bv, lang_tag)
            paths_z3_glob.append((path_pred_z3, path_glob_z3))

        if path_disjuncts:
            z3_formula = z3.Or(path_disjuncts)
        else:
            z3_formula = z3.BoolVal(False)

        return z3_formula, paths_z3_list, output_var_z3, paths_z3_glob

    print("[*] Converting C program paths to Z3...")
    c_formula_z3, c_paths_z3, c_output_z3, c_paths_z3_glob = convert_program_paths(c_program_data, "c")
    print(f"    {len(c_program_data.paths)} paths converted")

    print("[*] Converting Rust program paths to Z3...")
    r_formula_z3, r_paths_z3, r_output_z3, r_paths_z3_glob = convert_program_paths(rust_program_data, "rust")
    print(f"    {len(rust_program_data.paths)} paths converted")

    solver.add(c_formula_z3)
    solver.add(r_formula_z3)

    divergence_checks = []

    if skip_r0:
        print("    [~] Skipping R0 comparison (void return type per BTF)")
    else:
        print("    [+] Comparing return values (R0)")
        divergence_checks.append(c_output_z3 != r_output_z3)

    all_map_names = set()
    all_map_names.update(c_program_data.map_metadata.keys())
    all_map_names.update(rust_program_data.map_metadata.keys())

    def _collect_snapshot_bitwidths(program_data, map_name):
        key_bits_set = set()
        val_bits_set = set()

        for path in program_data.paths:
            for snap in path.map_snapshots.get(map_name, []):
                try:
                    key_bits_set.add(int(snap.key_expr.size()))
                    val_bits_set.add(int(snap.final_value_expr.size()))
                except Exception:
                    continue

        return key_bits_set, val_bits_set

    def _resolve_map_bitwidths(map_name, c_meta, r_meta):
        key_candidates = []
        val_candidates = []

        def _add_meta(meta, tag):
            if not meta:
                return
            try:
                kb = int(meta.get('key_size', 0)) * 8
                vb = int(meta.get('value_size', 0)) * 8
            except Exception:
                return
            if kb > 0:
                key_candidates.append((kb, tag))
            if vb > 0:
                val_candidates.append((vb, tag))

        _add_meta(c_meta, "C metadata")
        _add_meta(r_meta, "Rust metadata")

        c_k_bits, c_v_bits = _collect_snapshot_bitwidths(c_program_data, map_name)
        r_k_bits, r_v_bits = _collect_snapshot_bitwidths(rust_program_data, map_name)

        for kb in sorted(c_k_bits):
            if kb > 0:
                key_candidates.append((kb, "C snapshots"))
        for kb in sorted(r_k_bits):
            if kb > 0:
                key_candidates.append((kb, "Rust snapshots"))
        for vb in sorted(c_v_bits):
            if vb > 0:
                val_candidates.append((vb, "C snapshots"))
        for vb in sorted(r_v_bits):
            if vb > 0:
                val_candidates.append((vb, "Rust snapshots"))

        key_unique = sorted({kb for kb, _ in key_candidates})
        val_unique = sorted({vb for vb, _ in val_candidates})

        if not key_unique or not val_unique:
            raise ValueError(
                f"Map '{map_name}' has invalid/unknown bit-widths "
                f"(keys={key_candidates}, values={val_candidates})."
            )

        if len(key_unique) > 1 or len(val_unique) > 1:
            raise ValueError(
                f"Map '{map_name}' width mismatch across sources: "
                f"keys={key_candidates}, values={val_candidates}."
            )

        return key_unique[0], val_unique[0]

    map_checks = 0

    map_ite_fns = {}

    for map_name in sorted(all_map_names):

        c_meta = c_program_data.map_metadata.get(map_name)
        r_meta = rust_program_data.map_metadata.get(map_name)
        if c_meta is None and r_meta is None:
            continue

        try:
            key_bits, val_bits = _resolve_map_bitwidths(map_name, c_meta, r_meta)
        except ValueError as e:
            print(f"[!] {e}")
            return VerificationResult(
                equivalent=False,
                result_type="error",
                counter_example=str(e),
            )

        query_key = z3.BitVec(f'qk_{map_name}', key_bits)

        initial_array = z3.Array(
            f'initial_{map_name}',
            z3.BitVecSort(key_bits),
            z3.BitVecSort(val_bits),
        )
        default_val = z3.Select(initial_array, query_key)

        initial_presence = z3.Array(
            f'initial_presence_{map_name}',
            z3.BitVecSort(key_bits),
            z3.BitVecSort(1),
        )
        default_presence = z3.Select(initial_presence, query_key)

        c_fn = build_map_ite(c_paths_z3, map_name, query_key, default_val)
        r_fn = build_map_ite(r_paths_z3, map_name, query_key, default_val)
        divergence_checks.append(c_fn != r_fn)

        c_pres = build_map_ite_presence(c_paths_z3, map_name, query_key, default_presence)
        r_pres = build_map_ite_presence(r_paths_z3, map_name, query_key, default_presence)
        divergence_checks.append(c_pres != r_pres)

        map_ite_fns[map_name] = (c_fn, r_fn, c_pres, r_pres, query_key, key_bits, val_bits)
        map_checks += 1

    print(f"    [+] Comparing {map_checks} maps via ITE semantics")

    _GLOB_BITS_LIMIT = _DATA_SYMBOLIZE_LIMIT * 8

    def _is_global_written(sym_name, paths_z3_glob, bits, lang_tag):
        init_bvs = claripy.BVS(f'glob_{sym_name}_init', bits)
        canonical_str = str(unifier.convert_and_unify(init_bvs, lang_tag))
        for _pred, gw in paths_z3_glob:
            if sym_name not in gw:
                continue
            final_z3 = gw[sym_name]
            if not (z3.is_const(final_z3) and str(final_z3) == canonical_str):
                return True
        return False

    def _build_glob_ite(sym_name, paths_z3_glob, default_z3):
        ite = default_z3
        for pred_z3, gw in reversed(paths_z3_glob):
            if sym_name in gw:
                ite = z3.If(pred_z3, gw[sym_name], ite)
        return ite

    c_syms = c_program_data.data_symbols
    r_syms = rust_program_data.data_symbols
    all_data_syms = set(c_syms.keys()) | set(r_syms.keys())

    structural_mismatches = []
    glob_checks = 0

    c_matched = set()
    r_matched = set()
    for sym_name in sorted(all_data_syms):
        c_bits = c_syms.get(sym_name)
        r_bits = r_syms.get(sym_name)
        if not (c_bits and r_bits):
            continue
        c_matched.add(sym_name)
        r_matched.add(sym_name)
        if c_bits != r_bits:
            print(f"[!] .data symbol '{sym_name}': C={c_bits}b vs Rust={r_bits}b size mismatch, skipping")
            continue
        if c_bits > _GLOB_BITS_LIMIT:
            print(f"[!] .data symbol '{sym_name}': too large ({c_bits // 8}B > {_DATA_SYMBOLIZE_LIMIT}B), skipping value comparison")
            continue
        c_init = claripy.BVS(f'glob_{sym_name}_init', c_bits)
        r_init = claripy.BVS(f'glob_{sym_name}_init', r_bits)
        c_default = unifier.convert_and_unify(c_init, 'c')
        r_default = unifier.convert_and_unify(r_init, 'rust')
        c_ite = _build_glob_ite(sym_name, c_paths_z3_glob, c_default)
        r_ite = _build_glob_ite(sym_name, r_paths_z3_glob, r_default)
        divergence_checks.append(c_ite != r_ite)
        glob_checks += 1

    c_unmatched = {n: b for n, b in c_syms.items() if n not in c_matched}
    r_unmatched = {n: b for n, b in r_syms.items() if n not in r_matched}

    c_output = {}
    r_output = {}

    for sym_name, bits in sorted(c_unmatched.items()):
        if bits > _GLOB_BITS_LIMIT:
            c_output[sym_name] = bits
        elif _is_global_written(sym_name, c_paths_z3_glob, bits, 'c'):
            c_output[sym_name] = bits
        else:
            print(f"    [~] C .data '{sym_name}' never written — read-only config, skipping")

    for sym_name, bits in sorted(r_unmatched.items()):
        if bits > _GLOB_BITS_LIMIT:
            r_output[sym_name] = bits
        elif _is_global_written(sym_name, r_paths_z3_glob, bits, 'rust'):
            r_output[sym_name] = bits
        else:
            print(f"    [~] Rust .data '{sym_name}' never written — read-only config, skipping")

    from collections import defaultdict
    c_by_size = defaultdict(list)
    r_by_size = defaultdict(list)
    for n, b in c_output.items():
        c_by_size[b].append(n)
    for n, b in r_output.items():
        r_by_size[b].append(n)

    c_size_paired = set()
    r_size_paired = set()
    for size_bits in sorted(set(c_by_size) & set(r_by_size)):
        c_names = c_by_size[size_bits]
        r_names = r_by_size[size_bits]
        if len(c_names) != 1 or len(r_names) != 1:
            continue
        c_name, r_name = c_names[0], r_names[0]
        c_size_paired.add(c_name)
        r_size_paired.add(r_name)
        if size_bits > _GLOB_BITS_LIMIT:
            print(f"    [~] .data alias (too large to compare): '{c_name}' (C) ↔ '{r_name}' (Rust) [{size_bits // 8}B]")
        else:

            c_init_bvs = claripy.BVS(f'glob_{c_name}_init', size_bits)
            r_init_bvs = claripy.BVS(f'glob_{r_name}_init', size_bits)
            c_init_z3 = unifier.convert_and_unify(c_init_bvs, 'c')
            r_init_z3 = unifier.convert_and_unify(r_init_bvs, 'rust')
            solver.add(c_init_z3 == r_init_z3)
            c_ite = _build_glob_ite(c_name, c_paths_z3_glob, c_init_z3)
            r_ite = _build_glob_ite(r_name, r_paths_z3_glob, r_init_z3)
            divergence_checks.append(c_ite != r_ite)
            glob_checks += 1
            print(f"    [+] .data alias: '{c_name}' (C) ↔ '{r_name}' (Rust) [{size_bits // 8}B]")

    for sym_name, bits in sorted(c_output.items()):
        if sym_name not in c_size_paired:
            structural_mismatches.append(
                f"C has .data global '{sym_name}' ({bits // 8}B) but Rust does not"
            )
    for sym_name, bits in sorted(r_output.items()):
        if sym_name not in r_size_paired:
            structural_mismatches.append(
                f"Rust has .data global '{sym_name}' ({bits // 8}B) but C does not"
            )

    if glob_checks > 0:
        print(f"    [+] Comparing {glob_checks} .data global(s)")

    if structural_mismatches:
        print("\n[!] STRUCTURAL MISMATCH: C and Rust use different state storage mechanisms.")
        for msg in structural_mismatches:
            print(f"    - {msg}")
        sm_str = "Structural mismatch — C and Rust use different state storage:\n"
        sm_str += "\n".join(f"  - {m}" for m in structural_mismatches)
        sm_str += (
            "\n\nThe C program stores state in .data section globals (direct memory), "
            "while the Rust program uses BPF maps (or vice versa). "
            "Translate C globals to Rust #[no_mangle] static atomics, not BPF maps."
        )
        return VerificationResult(
            equivalent=False,
            result_type="mismatch",
            counter_example=sm_str,
        )

    if not divergence_checks:
        print("[!] No outputs or maps found to compare. Verification is meaningless.")
        return VerificationResult(
            equivalent=False, result_type="error",
            counter_example="No outputs or maps found to compare."
        )

    mismatch_condition = z3.Or(divergence_checks)
    solver.add(mismatch_condition)

    print(f"    [?] Solver checking {len(divergence_checks)} divergence conditions...")
    result = solver.check()

    if result == z3.sat:
        print("\n[!] MISMATCH DETECTED! Programs are NOT equivalent.")
        model = solver.model()

        def get_val(node):
            val = model.eval(node, model_completion=True)
            try:
                import sys
                if hasattr(sys, 'set_int_max_str_digits'):
                    sys.set_int_max_str_digits(0)
                return val.as_long()
            except AttributeError:
                return str(val)

        shared_var_values = {}
        for key, node in unifier.shared_vars.items():

            logical_name = key[0] if isinstance(key, tuple) else key
            shared_var_values[logical_name] = get_val(node)

        print("    Counter-Example Inputs:")
        for name, val in sorted(shared_var_values.items()):
            display = hex(val) if isinstance(val, int) else val
            display_name = name if len(name) < 50 else name[:45] + "..."
            print(f"      {display_name}: {display}")

        val_c = get_val(c_output_z3)
        val_r = get_val(r_output_z3)
        print("    Diverging Outputs:")
        if val_c != val_r:
            c_disp = hex(val_c) if isinstance(val_c, int) else val_c
            r_disp = hex(val_r) if isinstance(val_r, int) else val_r
            diag = classify_divergence(
                val_c if isinstance(val_c, int) else 0,
                val_r if isinstance(val_r, int) else 0,
            )
            print(f"      Return Value: C={c_disp} vs Rust={r_disp}")
            print(f"        Diagnosis: {diag}")

        map_divergences = []
        for map_name in sorted(all_map_names):
            if map_name not in map_ite_fns:
                continue
            c_fn, r_fn, c_pres, r_pres, qk, key_bits, val_bits = map_ite_fns[map_name]
            qk_val = get_val(qk)
            c_val = get_val(c_fn)
            r_val = get_val(r_fn)
            c_present = get_val(c_pres)
            r_present = get_val(r_pres)

            has_val_div = (c_val != r_val)
            has_pres_div = (c_present != r_present)

            if has_val_div or has_pres_div:
                qk_disp = hex(qk_val) if isinstance(qk_val, int) else str(qk_val)
                c_disp = hex(c_val) if isinstance(c_val, int) else str(c_val)
                r_disp = hex(r_val) if isinstance(r_val, int) else str(r_val)
                print(f"      Map '{map_name}' at key={qk_disp}: C={c_disp} vs Rust={r_disp}")
                if has_val_div:
                    diag = classify_divergence(
                        c_val if isinstance(c_val, int) else 0,
                        r_val if isinstance(r_val, int) else 0,
                        field_bits=val_bits,
                    )
                    print(f"        Diagnosis: {diag}")
                if has_pres_div:
                    c_p_str = "present" if c_present else "absent"
                    r_p_str = "present" if r_present else "absent"
                    print(f"        Presence: C={c_p_str}, Rust={r_p_str}")

                c_pres_bool = bool(c_present) if isinstance(c_present, int) else None
                r_pres_bool = bool(r_present) if isinstance(r_present, int) else None

                map_divergences.append({
                    'map_name': map_name,
                    'query_key': qk_val,
                    'c_val': c_val,
                    'r_val': r_val,
                    'c_present': c_pres_bool,
                    'r_present': r_pres_bool,
                    'val_bits': val_bits,
                })

        counter_example_str = format_counter_example(
            shared_var_values=shared_var_values,
            c_output_val=val_c,
            r_output_val=val_r,
            map_divergences=map_divergences,
        )

        return VerificationResult(
            equivalent=False, result_type="mismatch",
            counter_example=counter_example_str, raw_model=model,
            shared_var_values=shared_var_values,
        )

    elif result == z3.unsat:

        c_atomics = getattr(c_program_data, 'atomic_ops', []) or []
        r_atomics = getattr(rust_program_data, 'atomic_ops', []) or []

        if len(c_atomics) > 0 and len(r_atomics) == 0:

            print("\n[!] ATOMIC MISMATCH: C uses atomic operations but Rust does not.")
            print(f"    C atomic ops: {len(c_atomics)}")
            for op in c_atomics:
                print(f"      offset=0x{op.offset:x} {op.width}-bit {op.op_name} fetch={op.is_fetch}")
            feedback = format_atomic_mismatch(c_atomics, r_atomics)
            return VerificationResult(
                equivalent=False,
                result_type="atomic_mismatch",
                counter_example=feedback,
            )

        if len(c_atomics) > len(r_atomics) > 0:

            print(f"\n[!] PARTIAL ATOMIC MISMATCH: C has {len(c_atomics)} "
                  f"atomics, Rust has only {len(r_atomics)}")
            feedback = format_atomic_mismatch(c_atomics, r_atomics)
            return VerificationResult(
                equivalent=False,
                result_type="atomic_mismatch",
                counter_example=feedback,
            )

        print("\n[SUCCESS] Programs are EQUIVALENT.")
        print("    No input exists that produces divergent outputs or map states.")
        return VerificationResult(equivalent=True, result_type="equivalent")

    else:
        print(f"\n[?] Solver returned: {result}")
        return VerificationResult(
            equivalent=False, result_type="unknown",
            counter_example=f"Solver returned: {result}"
        )

def parse_map_specs(map_specs):
    map_symbol_names = []
    map_type_names = []

    for spec in map_specs:
        if ':' in spec:
            name, mtype = spec.split(':', 1)
            mtype = mtype.strip().lower()
            if mtype not in ("hash", "array"):
                print(
                    f"[!] Unknown map type '{mtype}' for spec '{spec}', "
                    f"defaulting to 'hash'"
                )
                mtype = "hash"
        else:
            name = spec
            mtype = "hash"

        map_symbol_names.append(name)
        map_type_names.append(mtype)

    return map_symbol_names, map_type_names

@dataclass
class VerificationContext:
    shared_vars: dict
    map_symbol_names: list
    map_type_names: list
    btf_metadata: dict
    c_btf_metadata: dict
    c_formula: Any
    c_program_data: Any
    helper_fail_mode: str = "off"
    helper_fail_helpers: set = field(default_factory=set)
    program_type: str = "default"
    c_filepath: str = ""

def prepare_verification(c_filepath, map_specs, helper_fail_mode="off", helper_fail_helpers=None, pkt_size=None):
    map_symbol_names, map_type_names = parse_map_specs(map_specs)
    helper_fail_mode = (helper_fail_mode or "off").strip().lower()
    if helper_fail_mode not in VALID_HELPER_FAIL_MODES:
        print(
            f"[!] Unknown helper fail mode '{helper_fail_mode}', defaulting to 'off'. "
            f"Valid values: {VALID_HELPER_FAIL_MODES}"
        )
        helper_fail_mode = "off"

    helper_fail_helpers = normalize_helper_fail_helpers(helper_fail_helpers)
    if helper_fail_mode == "selected" and not helper_fail_helpers:
        print(
            "[!] helper fail mode is 'selected' but no helpers were provided; "
            "defaulting to success-only ('off')."
        )
        helper_fail_mode = "off"

    if helper_fail_mode == "all":
        helper_fail_helpers = set(DEFAULT_FAILABLE_HELPERS)

    ctx_size = get_ctx_size_for_program(c_filepath)
    program_type = get_program_type_from_elf(c_filepath)

    c_btf_metadata = parse_map_metadata_from_btf(c_filepath)

    if c_btf_metadata:
        print(f"[*] Parsed BTF metadata from C binary: {len(c_btf_metadata)} maps")
        for name, meta in c_btf_metadata.items():
            print(f"    - {name}: type={meta.map_type_name}, "
                  f"key_size={meta.key_size}, value_size={meta.value_size}, "
                  f"max_entries={meta.max_entries}")
    else:
        print("[*] No BTF metadata from C binary")

    btf_metadata = dict(c_btf_metadata) if c_btf_metadata else {}

    if not btf_metadata:
        print("[*] No BTF metadata available, using command-line map specs")

    if not map_symbol_names and btf_metadata:
        print("[*] No map specs on command line, using all maps from BTF")
        for name, meta in btf_metadata.items():
            map_symbol_names.append(name)
            map_type_names.append(meta.map_type_name)

    shared_vars, ctx_constraints = build_ctx_shared_vars(program_type, ctx_size, pkt_size=pkt_size)
    shared_vars['ctx_constraints'] = ctx_constraints

    return VerificationContext(
        shared_vars=shared_vars,
        map_symbol_names=map_symbol_names,
        map_type_names=map_type_names,
        btf_metadata=btf_metadata,
        c_btf_metadata=c_btf_metadata,
        c_formula=None,
        c_program_data=None,
        helper_fail_mode=helper_fail_mode,
        helper_fail_helpers=helper_fail_helpers,
        program_type=program_type,
        c_filepath=c_filepath,
    )

def generate_c_formula(vctx, c_filepath, entry_sym, max_steps=50000, ringbuf_track_max=512):
    print("\n" + "=" * 60)
    print("  Generating formula for C program")
    print("=" * 60)
    try:
        c_formula, _, c_program_data = generate_formula_for_program(
            c_filepath,
            vctx.shared_vars,
            entry_sym,
            vctx.map_symbol_names,
            vctx.map_type_names,
            lang_tag='c',
            btf_metadata=vctx.c_btf_metadata or vctx.btf_metadata,
            helper_fail_mode=vctx.helper_fail_mode,
            helper_fail_helpers=vctx.helper_fail_helpers,
            max_steps=max_steps,
            ringbuf_track_max=ringbuf_track_max,
        )
    except Exception as exc:
        return VerificationResult(
            equivalent=False,
            result_type="error",
            counter_example=(
                "Formula generation failed for C program.\n"
                f"{exc}"
            ),
        )
    if c_formula is None:
        return VerificationResult(
            equivalent=False, result_type="error",
            counter_example="Formula generation failed for C program."
        )
    vctx.c_formula = c_formula
    vctx.c_program_data = c_program_data
    return None

def _check_map_type_consistency(c_filepath, rust_filepath):
    try:
        c_maps = _find_maps_for_type_check(c_filepath) or []
        r_maps = _find_maps_for_type_check(rust_filepath) or []
    except Exception as exc:

        print(f"[!] map-type consistency check skipped: {exc}")
        return None

    def _classify(maps):
        return Counter(m.map_type_name for m in maps if m.map_type_name != "unknown")

    c_types = _classify(c_maps)
    r_types = _classify(r_maps)
    if c_types == r_types:
        return None

    diff_lines = []
    for t in sorted(set(c_types) | set(r_types)):
        cn, rn = c_types.get(t, 0), r_types.get(t, 0)
        if cn != rn:
            diff_lines.append(f"  {t}: C={cn}, Rust={rn}")

    msg = (
        "Map-type mismatch between C and Rust binaries:\n"
        + "\n".join(diff_lines)
        + "\n\nThe Rust translation must declare the same eBPF map types as "
          "the C source. Different map types have different kernel semantics "
          "(emission mechanism, per-CPU vs shared storage, ordering "
          "guarantees) that are observable to userspace consumers and not "
          "captured by symbolic equivalence on the per-program formula."
    )
    print(f"\n[!] MAP-TYPE MISMATCH:\n{msg}")
    return VerificationResult(
        equivalent=False,
        result_type="map_type_mismatch",
        counter_example=msg,
    )

def run_verification_rust_only(vctx, rust_filepath, entry_sym, max_steps=50000, ringbuf_track_max=512):

    mt_result = _check_map_type_consistency(vctx.c_filepath, rust_filepath)
    if mt_result is not None:
        return mt_result

    r_btf_metadata = parse_map_metadata_from_btf(rust_filepath)

    if r_btf_metadata:
        print(f"[*] Parsed BTF metadata from Rust binary: {len(r_btf_metadata)} maps")
        for name, meta in r_btf_metadata.items():
            print(f"    - {name}: type={meta.map_type_name}, "
                  f"key_size={meta.key_size}, value_size={meta.value_size}, "
                  f"max_entries={meta.max_entries}")

        for name in sorted(set(vctx.c_btf_metadata or {}) & set(r_btf_metadata)):
            c_meta = vctx.c_btf_metadata[name]
            r_meta = r_btf_metadata[name]
            if c_meta.key_size != r_meta.key_size:
                print(f"[!] BTF MISMATCH: map '{name}' key_size differs: "
                      f"C={c_meta.key_size} vs Rust={r_meta.key_size}")
                return VerificationResult(
                    equivalent=False, result_type="error",
                    counter_example=f"BTF mismatch: map '{name}' key_size C={c_meta.key_size} vs Rust={r_meta.key_size}"
                )
            if c_meta.value_size != r_meta.value_size:
                print(f"[!] BTF MISMATCH: map '{name}' value_size differs: "
                      f"C={c_meta.value_size} vs Rust={r_meta.value_size}")
                return VerificationResult(
                    equivalent=False, result_type="error",
                    counter_example=f"BTF mismatch: map '{name}' value_size C={c_meta.value_size} vs Rust={r_meta.value_size}"
                )
    else:
        print("[*] No BTF metadata from Rust binary")

    print("\n" + "=" * 60)
    print("  Generating formula for Rust program")
    print("=" * 60)
    try:
        r_formula, _, r_program_data = generate_formula_for_program(
            rust_filepath,
            vctx.shared_vars,
            entry_sym,
            vctx.map_symbol_names,
            vctx.map_type_names,
            lang_tag='rust',
            btf_metadata=r_btf_metadata or vctx.btf_metadata,
            helper_fail_mode=vctx.helper_fail_mode,
            helper_fail_helpers=vctx.helper_fail_helpers,
            max_steps=max_steps,
            ringbuf_track_max=ringbuf_track_max,
        )
    except Exception as exc:
        return VerificationResult(
            equivalent=False,
            result_type="error",
            counter_example=(
                "Formula generation failed for Rust program.\n"
                f"{exc}"
            ),
        )

    if r_formula is None:
        return VerificationResult(
            equivalent=False, result_type="error",
            counter_example="Formula generation failed for Rust program."
        )

    skip_r0 = False
    if vctx.c_filepath:
        skip_r0 = is_void_return_via_btf(vctx.c_filepath, entry_sym)
        if skip_r0:
            print(f"[*] BTF: '{entry_sym}' returns void — R0 comparison skipped")

    unifier = Z3VariableUnifier()
    ctx_constraints = vctx.shared_vars.get('ctx_constraints', [])
    return verify_equivalence_ite(vctx.c_program_data, r_program_data, unifier,
                                  ctx_constraints=ctx_constraints, skip_r0=skip_r0)

def run_verification(
    c_filepath,
    rust_filepath,
    entry_sym,
    map_specs,
    helper_fail_mode="off",
    helper_fail_helpers=None,
    pkt_size=None,
):
    vctx = prepare_verification(
        c_filepath,
        map_specs,
        helper_fail_mode=helper_fail_mode,
        helper_fail_helpers=helper_fail_helpers,
        pkt_size=pkt_size,
    )

    err = generate_c_formula(vctx, c_filepath, entry_sym)
    if err is not None:
        return err

    return run_verification_rust_only(vctx, rust_filepath, entry_sym)

def main(argv):
    parser = argparse.ArgumentParser(
        description="Run symbolic equivalence verification between two eBPF object files."
    )
    parser.add_argument("c_ebpf", help="Path to C eBPF object")
    parser.add_argument("rust_ebpf", help="Path to Rust eBPF object")
    parser.add_argument("entry_symbol", help="Entry symbol name (used for both objects)")
    parser.add_argument(
        "map_specs",
        nargs="+",
        help="Map specs in name or name:type format (type: hash|array)",
    )
    parser.add_argument(
        "--helper-fail-mode",
        choices=VALID_HELPER_FAIL_MODES,
        default="off",
        help=(
            "Helper failure modeling mode: "
            "'off' (success-only), 'all' (all failable helpers), "
            "'selected' (only helpers from --helper-fail-helpers)."
        ),
    )
    parser.add_argument(
        "--helper-fail-helpers",
        default="",
        help=(
            "Comma-separated helper names for selected mode, e.g. "
            "bpf_probe_read,get_current_comm,ringbuf_reserve"
        ),
    )
    parser.add_argument(
        "--pkt-size",
        type=int,
        default=None,
        help=(
            "Packet buffer size in bytes for XDP/socket programs "
            "(default: 1500). Only applies to program types with "
            "direct packet access."
        ),
    )

    args = parser.parse_args(argv[1:])
    selected_helpers = [
        h.strip() for h in args.helper_fail_helpers.split(",") if h.strip()
    ]

    result = run_verification(
        args.c_ebpf,
        args.rust_ebpf,
        args.entry_symbol,
        args.map_specs,
        helper_fail_mode=args.helper_fail_mode,
        helper_fail_helpers=selected_helpers,
        pkt_size=args.pkt_size,
    )

    if not result.equivalent:
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
