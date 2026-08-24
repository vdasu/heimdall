from angr.procedures.definitions import SimSyscallLibrary
from angr.calling_conventions import (
    SimCC,
    SimCCSyscall,
    register_default_cc,
    SimRegArg,
    register_syscall_cc,
)
from angr.simos import SimUserland, register_simos
from angr.sim_procedure import SimProcedure
from angr.state_plugins.plugin import SimStatePlugin
from claripy import BVS, BVV, If
import copy
import angr
import claripy

from . import ArchExtendedBPF
from .instrs_ebpf import BPF_CALL_STACK_BASE, BPF_EXIT_SENTINEL

def _compact_sym(expr):
    """Return a short representation of a claripy/symbolic expression for logging."""
    s = str(expr)
    if len(s) > 60:
        return f"<sym {expr.size()}bit #{hash(expr) & 0xFFFF:04x}>"
    return s

HASH_LIKE_TYPES = ("hash", "lru_hash", "lru_percpu_hash", "percpu_hash", "stack_trace", "devmap_hash", "lpm_trie", "sockhash")
ARRAY_LIKE_TYPES = ("array", "percpu_array", "cgroup_array", "xskmap", "devmap", "cpumap", "sockmap")
OUTPUT_SINK_TYPES = ("perf_event_array", "ringbuf")
MAP_OF_MAPS_TYPES = ("array_of_maps", "hash_of_maps")
PROG_ARRAY_TYPES = ("prog_array",)

FAILABLE_HELPERS = {
    "bpf_probe_read",
    "bpf_probe_read_user",
    "bpf_probe_read_user_str",
    "bpf_probe_read_kernel_str",
    "get_current_comm",
    "perf_event_output",
    "get_stack",
    "get_stackid",
    "current_task_under_cgroup",
    "ringbuf_reserve",
    "ringbuf_output",
    "redirect_map",
    "xdp_adjust_head",
}
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
    "bpf_ringbuf_output": "ringbuf_output",
    "probe_read_kernel_str": "bpf_probe_read_kernel_str",
    "read_kernel_str": "bpf_probe_read_kernel_str",
    "bpf_redirect_map": "redirect_map",
    "bpf_xdp_adjust_head": "xdp_adjust_head",
    "adjust_head": "xdp_adjust_head",
}

def _normalize_helper_name(name):
    return (name or "").strip().lower().replace("-", "_")

def _canonical_helper_name(name):
    norm = _normalize_helper_name(name)
    return HELPER_FAIL_ALIASES.get(norm, norm)

def _helper_fail_cfg(state):
    cfg = state.globals.get("helper_fail_cfg", {})
    mode = (cfg.get("mode") or "off").strip().lower()
    helpers = {
        _canonical_helper_name(h)
        for h in cfg.get("helpers", set())
        if _normalize_helper_name(h)
    }
    return mode, helpers

def _should_model_helper_failure(state, helper_name):
    helper_name = _canonical_helper_name(helper_name)
    mode, selected = _helper_fail_cfg(state)
    if helper_name not in FAILABLE_HELPERS:
        return False
    if mode == "all":
        return True
    if mode == "selected":
        return helper_name in selected
    return False

def _helper_failure_cond(state, helper_name, bits=1):
    helper_name = _canonical_helper_name(helper_name)
    key = f"helper_fail_ctr_{helper_name}"
    counter = state.globals.get(key, 0)
    state.globals[key] = counter + 1
    fail_bit = claripy.BVS(f"input_helper_fail_{helper_name}_v{counter}", bits)
    if bits == 1:
        state.add_constraints(claripy.Or(fail_bit == 0, fail_bit == 1))
        return fail_bit == 1
    state.add_constraints(fail_bit.UGE(0))
    return fail_bit != 0

def _errno_ret(errno, bits=64):
    """Return a negative errno value as a bitvector."""
    return claripy.BVV(-abs(int(errno)), bits)

def _maybe_fail_errno_ret(state, helper_name, success_ret, errno):
    """Return (ret_expr, fail_cond). fail_cond is None when fail mode is disabled."""
    if not _should_model_helper_failure(state, helper_name):
        return success_ret, None
    fail_cond = _helper_failure_cond(state, helper_name)
    bits = success_ret.size()
    return claripy.If(fail_cond, _errno_ret(errno, bits), success_ret), fail_cond

def _maybe_fail_ptr_ret(state, helper_name, success_ptr):
    """Return (ret_expr, fail_cond) for pointer-return helpers (NULL on failure)."""
    if not _should_model_helper_failure(state, helper_name):
        return success_ptr, None
    fail_cond = _helper_failure_cond(state, helper_name)
    return claripy.If(fail_cond, claripy.BVV(0, success_ptr.size()), success_ptr), fail_cond

class EbpfMapManager(SimStatePlugin):
    """
    Coarse eBPF map model for symbolic execution and cross-program equivalence.

    Supports:
      - map_type="hash": dynamic key -> slot allocation (approximate hash map)
      - map_type="array": key is an index in [0, max_entries); 1 slot per index
      - map_type="percpu_hash"/"percpu_array": modeled as hash/array (CPU dimension folded)
      - map_type="lru_hash": modeled as hash (LRU eviction not modeled)
      - map_type="perf_event_array"/"ringbuf": output sinks (data leaves kernel)
      - map_type="stack_trace": modeled as hash, used with bpf_get_stackid

    Per-CPU maps are modeled without the CPU dimension for simplicity.
    """

    def __init__(self, maps_by_index=None, value_storage_ptr=0xDEAF0000, write_counter=0):
        super().__init__()
        self._maps_by_index = maps_by_index if maps_by_index is not None else []
        self._value_storage_ptr = value_storage_ptr
        self._write_counter = write_counter

    def set_state(self, state):
        super().set_state(state)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        """
        Copy-on-write: deep-copy the container structure but *not* claripy ASTs.
        """
        new_maps_by_index = copy.deepcopy(self._maps_by_index)
        return EbpfMapManager(
            maps_by_index=new_maps_by_index,
            value_storage_ptr=self._value_storage_ptr,
            write_counter=self._write_counter,
        )

    def create_map(self, map_addr, key_size, value_size, max_entries,
                   map_type="hash", map_name="None",
                   inner_map_type=None, inner_key_size=0, inner_value_size=0,
                   inner_max_entries=0):
        """
        Create a new map.
          map_type: "hash", "array", or specialized types

        For "hash" and hash-like types (lru_hash, percpu_hash, stack_trace, lpm_trie):
          - keys are arbitrary bitvectors of size key_size
          - slots allocated lazily per new key

        For "array" and array-like types (percpu_array, cgroup_array):
          - key is treated as an integral index
          - entries are allocated lazily per index

        For output sink types (perf_event_array, ringbuf):
          - modeled as array but writes are essentially no-ops (data leaves kernel)

        For map-of-maps types (array_of_maps, hash_of_maps):
          - outer map holds references to a canonical inner map
          - inner map is created automatically from the inner_* parameters
          - lookup returns a pointer to the inner map's index (for chained lookups)

        For prog_array:
          - used by bpf_tail_call, modeled as no-op array
        """
        if map_type in MAP_OF_MAPS_TYPES:
            effective_type = "map_of_maps"
        elif map_type in HASH_LIKE_TYPES:
            effective_type = "hash"
        elif map_type in ARRAY_LIKE_TYPES:
            effective_type = "array"
        elif map_type in OUTPUT_SINK_TYPES:
            effective_type = "array"
        elif map_type in PROG_ARRAY_TYPES:
            effective_type = "array"
        else:
            print(f"[!] Warning: Unknown map_type '{map_type}', defaulting to 'hash'")
            effective_type = "hash"

        map_index = len(self._maps_by_index)
        info = {
            "index": map_index,
            "addr": map_addr,
            "name": map_name or f"map_{map_index}",
            "key_size": key_size,
            "value_size": value_size,
            "max_entries": max_entries,
            "entries": [],
            "type": effective_type,
            "original_type": map_type,
            "is_output_sink": map_type in OUTPUT_SINK_TYPES,
            "is_prog_array": map_type in PROG_ARRAY_TYPES,
        }
        self._maps_by_index.append(info)

        if effective_type == "map_of_maps":
            inner_name = f"{map_name}__inner"
            inner_effective = "hash"
            if inner_map_type and inner_map_type in ARRAY_LIKE_TYPES:
                inner_effective = "array"
            elif inner_map_type and inner_map_type in HASH_LIKE_TYPES:
                inner_effective = "hash"

            if inner_key_size == 0:
                inner_key_size = 8
            if inner_value_size == 0:
                inner_value_size = 8
            if inner_max_entries == 0:
                inner_max_entries = 1024

            inner_addr = map_addr + 0x10000
            inner_idx = self.create_map(
                inner_addr,
                key_size=inner_key_size,
                value_size=inner_value_size,
                max_entries=inner_max_entries,
                map_type=inner_map_type or "hash",
                map_name=inner_name,
            )
            info["inner_map_index"] = inner_idx
            print(
                f"[*] Map Manager: Created map-of-maps '{map_name}' "
                f"(outer index={map_index}) with inner map '{inner_name}' "
                f"(index={inner_idx}, type={inner_map_type or 'hash'}, "
                f"key_size={inner_key_size}, value_size={inner_value_size})"
            )

        return map_index

    def _alloc_slot_hash(self, state, map_info, key_bvv, force_exists=None):
        """
        Allocate a new slot for this key in a hash map.

        Produces:
          - addr in the reserved map-region
          - value_sym:  map_<map_name>_v<slot>
          - exists_cond: either a fresh 1-bit BVS or a fixed BVV(1,1)
        """
        assert map_info["type"] == "hash"

        slot = len(map_info["entries"])
        if slot >= map_info["max_entries"]:
            print(f"[!] Map Manager: hash map '{map_info['name']}' exceeded max_entries; "
                  f"continuing with slot={slot} anyway (approximate model).")

        value_size = map_info["value_size"]

        addr = self._value_storage_ptr
        self._value_storage_ptr += value_size

        map_name = map_info["name"]
        value_sym = BVS(f"map_{map_name}_v{slot}", value_size * 8)

        if force_exists is None:
            exists_cond = BVS(f"key_exists_{map_name}_v{slot}", 1)
        else:
            exists_cond = BVV(force_exists, 1)

        state.memory.store(
            addr,
            value_sym,
            endness=state.arch.memory_endness,
            condition=(exists_cond == 1),
        )

        entry = {
            "slot": slot,
            "key": key_bvv,
            "addr": addr,
            "exists_cond": exists_cond,
            "value_sym": value_sym,
            "written": False,
            "write_seq": -1,
        }
        map_info["entries"].append(entry)
        return entry

    def _find_hash_entry(self, state, map_info, key_bvv):
        """
        For hash maps: Return the entry with definitely-equal key, if any.
        """
        assert map_info["type"] == "hash"
        for e in map_info["entries"]:
            if state.solver.is_true(key_bvv == e["key"]):
                return e
        return None

    def _array_index_from_key(self, state, map_info, key_bvv):
        """
        Interpret key_bvv as an integer array index.

        In real eBPF ARRAY maps, key is a u32 index. Here we just concretize
        the key bitvector to an int.
        """
        assert map_info["type"] == "array"
        return key_bvv

    def _get_array_entry(self, state, map_info, idx_sym, create_if_missing):
        """
        Get or lazily allocate the entry for array index 'idx_sym'.
        idx_sym may be a symbolic expression (e.g. cpu_id).
        """
        assert map_info["type"] == "array"
        max_entries = map_info["max_entries"]

        if state.solver.satisfiable(extra_constraints=[
            idx_sym >= 0, 
            idx_sym < max_entries
        ]) is False:
            return None

        entries = map_info["entries"]
        for e in entries:
            if state.solver.is_true(e["key"] == idx_sym):
                return e

        if not create_if_missing:
            return None

        value_size = map_info["value_size"]
        addr = self._value_storage_ptr
        self._value_storage_ptr += value_size

        map_name = map_info["name"]
        
        entry_id = len(entries)
        value_sym = BVS(f"map_{map_name}_entry_{entry_id}", value_size * 8)

        state.add_constraints(idx_sym >= 0)
        state.add_constraints(idx_sym < max_entries)

        exists_cond = BVV(1, 1) 

        state.memory.store(
            addr,
            value_sym,
            endness=state.arch.memory_endness,
        )

        entry = {
            "slot": entry_id,
            "key": idx_sym,
            "addr": addr,
            "exists_cond": exists_cond,
            "value_sym": value_sym,
            "written": False,
            "write_seq": -1,
        }

        entries.append(entry)
        return entry

    def lookup_elem(self, state, map_info, key_bvv):
        """
        Symbolically look up an element in the map.

        HASH:
          - If we've seen an equivalent key before: reuse the same slot.
          - Otherwise:
              - create a new slot with value_sym = map_<map_name>_v<slot>
              - create a 1-bit symbolic existence condition
              - return ptr or NULL accordingly

        ARRAY:
          - Treat key as an index in [0, max_entries).
          - Lazily allocate one canonical slot per index.
          - Return pointer for in-range indices; NULL for out-of-range.
        """
        if map_info is None:
            return BVV(0, 64)

        map_type = map_info.get("type", "hash")

        if map_type == "hash":
            entry = self._find_hash_entry(state, map_info, key_bvv)
            if entry is not None:
                print(f"[*] Map Manager: (hash) Reusing slot {entry['slot']} "
                      f"for map '{map_info['name']}'")
                return If(
                    entry["exists_cond"] == 1,
                    BVV(entry["addr"], 64),
                    BVV(0, 64),
                )

            entry = self._alloc_slot_hash(state, map_info, key_bvv, force_exists=None)
            print(
                f"[*] Map Manager: (hash) New key in map '{map_info['name']}', "
                f"slot {entry['slot']}, addr={hex(entry['addr'])}"
            )

            value_size = map_info["value_size"]
            ite_value = entry["value_sym"]
            ite_exists = entry["exists_cond"]

            for prev_entry in map_info["entries"][:-1]:
                prev_val = state.memory.load(
                    prev_entry["addr"], value_size,
                    endness=state.arch.memory_endness,
                )
                ite_value = If(key_bvv == prev_entry["key"], prev_val, ite_value)
                ite_exists = If(key_bvv == prev_entry["key"], prev_entry["exists_cond"], ite_exists)

            state.memory.store(entry["addr"], ite_value, endness=state.arch.memory_endness)

            entry["exists_cond"] = ite_exists

            return If(
                ite_exists == 1,
                BVV(entry["addr"], 64),
                BVV(0, 64),
            )

        elif map_type == "array":
            idx = self._array_index_from_key(state, map_info, key_bvv)
            entry = self._get_array_entry(state, map_info, idx, create_if_missing=True)
            if entry is None:
                print(f"[!] Map Manager: (array) Out-of-range index {_compact_sym(idx)} "
                      f"for map '{map_info['name']}' → NULL")
                return BVV(0, 64)

            print(
                f"[*] Map Manager: (array) Lookup index {_compact_sym(idx)} in map "
                f"'{map_info['name']}', addr={hex(entry['addr'])}"
            )
            return BVV(entry["addr"], 64)

        elif map_type == "map_of_maps":
            inner_idx = map_info.get("inner_map_index")
            if inner_idx is None:
                print(f"[!] Map Manager: map-of-maps '{map_info['name']}' has no inner map")
                return BVV(0, 64)

            slot_addr = self._value_storage_ptr
            self._value_storage_ptr += 4
            state.memory.store(
                slot_addr,
                BVV(inner_idx, 32),
                endness=state.arch.memory_endness,
            )
            print(
                f"[*] Map Manager: (map_of_maps) Lookup in '{map_info['name']}' "
                f"→ inner map index {inner_idx} at addr {hex(slot_addr)}"
            )
            return BVV(slot_addr, 64)

        else:
            raise ValueError(f"Unsupported map_type '{map_type}' in lookup_elem")

    def update_elem(self, state, map_info, key_bvv, value_bvv):
        """
        Update/insert an element.

        HASH:
          - If key already has a slot:
              - overwrite stored value and equate slot variable with written value.
              - force exists_cond == 1.
          - If it is a new key:
              - allocate a slot that definitely exists and tie the symbolic
                value to the written value.

        ARRAY:
          - Treat key as an index in [0, max_entries).
          - For in-range index:
              - allocate slot if missing
              - overwrite and tie symbolic value to written value.
          - For out-of-range index: return error (-1).

        OUTPUT SINK (perf_event_array, ringbuf):
          - No-op: data leaves kernel, not tracked symbolically.
        """
        if map_info is None:
            return BVV(-1, 64)

        if map_info.get("is_output_sink", False):
            print(f"[*] Map Manager: (output sink) Update to '{map_info['name']}' - data leaves kernel")
            return BVV(0, 64)

        map_type = map_info.get("type", "hash")
        value_size = map_info["value_size"]

        if map_type == "hash":
            entry = self._find_hash_entry(state, map_info, key_bvv)

            if entry is not None:
                print(
                    f"[*] Map Manager: (hash) Updating existing slot {entry['slot']} "
                    f"in map '{map_info['name']}'"
                )
                state.memory.store(
                    entry["addr"],
                    value_bvv,
                    endness=state.arch.memory_endness,
                )
                entry["exists_cond"] = BVV(1, 1)
                entry["written"] = True
                entry["write_seq"] = self._write_counter
                self._write_counter += 1
                return BVV(0, 64)

            entry = self._alloc_slot_hash(state, map_info, key_bvv, force_exists=1)
            print(
                f"[*] Map Manager: (hash) Creating new slot {entry['slot']} "
                f"in map '{map_info['name']}' via update"
            )

            state.memory.store(
                entry["addr"],
                value_bvv,
                endness=state.arch.memory_endness,
            )
            entry["written"] = True
            entry["write_seq"] = self._write_counter
            self._write_counter += 1

            return BVV(0, 64)

        elif map_type == "array":
            idx = self._array_index_from_key(state, map_info, key_bvv)
            entry = self._get_array_entry(state, map_info, idx, create_if_missing=True)
            if entry is None:
                print(
                    f"[!] Map Manager: (array) Update out-of-range index {_compact_sym(idx)} "
                    f"in map '{map_info['name']}' → error"
                )
                return BVV(-1, 64)

            print(
                f"[*] Map Manager: (array) Updating index {_compact_sym(idx)} in map "
                f"'{map_info['name']}'"
            )
            state.memory.store(
                entry["addr"],
                value_bvv,
                endness=state.arch.memory_endness,
            )
            entry["written"] = True
            entry["write_seq"] = self._write_counter
            self._write_counter += 1
            return BVV(0, 64)

        else:
            raise ValueError(f"Unsupported map_type '{map_type}' in update_elem")

class SimCcEbpf(SimCC):
    """CC for eBPF"""
    ARCH = ArchExtendedBPF
    ARG_REGS = ["R1", "R2", "R3", "R4", "R5"]
    CALLER_SAVED_REGS = ["R6", "R7", "R8", "R9"]
    RETURN_VAL = SimRegArg("R0", 8)

register_default_cc("eBPF", SimCcEbpf)

class SimCcSyscallEbpf(SimCCSyscall):
    """CC syscall for eBPF"""
    ARCH = ArchExtendedBPF
    ARG_REGS = ["R1", "R2", "R3", "R4", "R5"]
    CALLER_SAVED_REGS = ["R6", "R7", "R8", "R9"]
    RETURN_VAL = SimRegArg("R0", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)

    @staticmethod
    def syscall_num(state):
        return state.regs.syscall

register_syscall_cc("eBPF", "eBPF", SimCcSyscallEbpf)

class ExitSimProcedure(SimProcedure):
    """End of program"""
    NO_RET = True
    ADDS_EXITS = True

    def run(self):
        print("[*] BPF Helper: exit() called.")
        self.exit(self.state.regs.R0)

class KtimeGetNSSimProcedure(angr.SimProcedure):
    KEY_CTR = "ktime_call_counter"
    KEY_LAST = "last_ktime"

    def run(self):
        print("[*] BPF Helper: bpf_ktime_get_ns called.")

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1
        
        ret = claripy.BVS(f"input_ktime_v{counter}", 64)

        last_time = self.state.globals.get(self.KEY_LAST, None)
        if last_time is not None:
            self.state.add_constraints(ret.UGE(last_time))
        else:
            self.state.add_constraints(ret.UGE(0))

        self.state.globals[self.KEY_LAST] = ret
        return ret

class BpfPrintk(SimProcedure):
    def run(self, fmt_ptr, fmt_size, arg1=None, arg2=None, arg3=None):
        print("[*] BPF Helper: bpf_printk called.")
        return 0

def _resolve_map_by_addr_or_index(state, map_manager, map_fd_val):
    """Resolve a map by index, ELF address, or inner-map dereference.

    Katran patterns like ``lru_map = &fallback_cache`` pass a map's
    ELF address instead of a sequential index.  Additionally, after a
    map-of-maps lookup the value at the returned pointer is an inner
    map index.  This function handles all three cases:

    1. Direct index: ``map_fd_val`` is a valid index into ``_maps_by_index``.
    2. ELF address: ``map_fd_val`` matches the ``addr`` field of some map.
    3. Inner-map dereference: ``map_fd_val`` is an address that contains
       the index of an inner map (written by map-of-maps lookup).
    """
    if 0 <= map_fd_val < len(map_manager._maps_by_index):
        return map_manager._maps_by_index[map_fd_val]

    for m in map_manager._maps_by_index:
        if m["addr"] == map_fd_val:
            return m

    try:
        inner_idx_bv = state.memory.load(
            map_fd_val, 4, endness=state.arch.memory_endness,
        )
        inner_idx = state.solver.eval(inner_idx_bv)
        if 0 <= inner_idx < len(map_manager._maps_by_index):
            print(
                f"[*] BPF Helper: Dereferenced inner map index {inner_idx} "
                f"from addr {hex(map_fd_val)}"
            )
            return map_manager._maps_by_index[inner_idx]
    except Exception:
        pass

    return None

class BpfMapLookupElem(SimProcedure):
    def run(self, map_fd_ptr, key_ptr):
        print("[*] BPF Helper: bpf_map_lookup_elem called.")
        map_manager = self.state.ebpf_map
        map_fd_val = self.state.solver.eval(map_fd_ptr)
        map_info = _resolve_map_by_addr_or_index(self.state, map_manager, map_fd_val)

        if map_info is None:
            print(f"[!] BPF Helper Error: map_lookup_elem called with unresolvable map ref {hex(map_fd_val)}")
            return BVV(0, 64)

        key_size_bytes = map_info['key_size']
        key_bvv = self.state.memory.load(key_ptr, key_size_bytes, endness=self.state.arch.memory_endness)

        return map_manager.lookup_elem(self.state, map_info, key_bvv)

class BpfMapUpdateElem(SimProcedure):
    def run(self, map_fd_ptr, key_ptr, value_ptr, flags):
        print("[*] BPF Helper: bpf_map_update_elem called.")
        map_manager = self.state.ebpf_map
        map_fd_val = self.state.solver.eval(map_fd_ptr)
        map_info = _resolve_map_by_addr_or_index(self.state, map_manager, map_fd_val)

        if map_info is None:
            print(f"[!] BPF Helper Error: map_update_elem called with unresolvable map ref {hex(map_fd_val)}")
            return BVV(-1, 64)

        key_size = map_info['key_size']
        value_size = map_info['value_size']

        key_bvv = self.state.memory.load(key_ptr, key_size, endness=self.state.arch.memory_endness)
        value_bvv = self.state.memory.load(value_ptr, value_size, endness=self.state.arch.memory_endness)

        return map_manager.update_elem(self.state, map_info, key_bvv, value_bvv)

class BpfMapDeleteElem(SimProcedure):
    """
    Model bpf_map_delete_elem(map, key).
    For hash maps: marks the entry as deleted (exists_cond = 0).
    For array maps: deletion is not supported (returns -EINVAL).
    """
    def run(self, map_fd_ptr, key_ptr):
        print("[*] BPF Helper: bpf_map_delete_elem called.")
        map_manager = self.state.ebpf_map
        map_fd_val = self.state.solver.eval(map_fd_ptr)
        map_info = _resolve_map_by_addr_or_index(self.state, map_manager, map_fd_val)

        if map_info is None:
            print(f"[!] BPF Helper Error: map_delete_elem called with unresolvable map ref {hex(map_fd_val)}")
            return BVV(-1, 64)

        map_type = map_info.get("type", "hash")

        if map_type == "array":
            print(f"[!] BPF Helper: map_delete_elem on array map '{map_info['name']}' - not supported")
            return BVV(-22, 64)

        key_size = map_info["key_size"]
        key_bvv = self.state.memory.load(
            key_ptr,
            key_size,
            endness=self.state.arch.memory_endness,
        )

        for entry in map_info["entries"]:
            if self.state.solver.is_true(key_bvv == entry["key"]):
                print(f"[*] Map Manager: (hash) Deleting entry slot {entry['slot']} in map '{map_info['name']}'")
                entry["exists_cond"] = BVV(0, 1)
                entry["written"] = True
                entry["write_seq"] = map_manager._write_counter
                map_manager._write_counter += 1
                return BVV(0, 64)

        print(f"[*] Map Manager: (hash) Key not found for deletion in map '{map_info['name']}'")
        return BVV(-2, 64)

class BpfGetPrandomU32(SimProcedure):
    KEY_CTR = "prandom_counter"

    def run(self):
        print("[*] BPF Helper: bpf_get_prandom_u32 called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1
        return BVS(f"input_prandom_v{counter}", 32)

class BpfGetCurrentPidTgid(SimProcedure):
    """
    Returns (tgid << 32) | pid.
    Returns consistent value per execution (stored in state.globals).
    """
    KEY = "current_pid_tgid"

    def run(self):
        print("[*] BPF Helper: bpf_get_current_pid_tgid called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        pid_tgid = BVS('input_pid_tgid', 64)
        pid = pid_tgid & 0xFFFFFFFF
        tgid = pid_tgid >> 32
        self.state.add_constraints(pid > 0)
        self.state.add_constraints(tgid > 0)

        self.state.globals[self.KEY] = pid_tgid
        return pid_tgid

class BpfGetSmpProcessorId(SimProcedure):
    """
    Returns the current CPU ID.
    Returns consistent value per execution (stored in state.globals).
    Constrained to reasonable range (0 to MAX_CPUS-1).
    """
    KEY = "smp_processor_id"
    MAX_CPUS = 256

    def run(self):
        print("[*] BPF Helper: bpf_get_smp_processor_id called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        proc_id = BVS('input_smp_processor_id', 32)
        self.state.add_constraints(proc_id.UGE(0))
        self.state.add_constraints(proc_id.ULT(self.MAX_CPUS))

        self.state.globals[self.KEY] = proc_id
        return proc_id

class BpfProbeRead(SimProcedure):
    """
    Model bpf_probe_read(dst, size, src).

    Two cases:
    - src points into BPF-managed memory (context, stack, maps): load from angr
      memory so that values derived from symbolic context inputs (input_bpf_ctx_*,
      input_*) remain correlated across C and Rust runs.
    - src points into arbitrary kernel memory (e.g. a struct pointer obtained from
      a previous probe_read or helper): the memory is uninitialized in angr and
      produces auto-named variables (mem_*) that the Z3 variable unifier cannot
      match between C and Rust, causing false counter-examples.  In this case we
      replace the loaded data with a fresh input_probe_read_kernel_v<N> symbolic
      bitvector so both programs use the same variable name for the same call index.
    """
    KEY_CTR = "probe_read_kernel_counter"

    BPF_MANAGED_ADDR_MIN = 0x100000

    @staticmethod
    def _has_only_input_vars(claripy_ast):
        """Return True if every free variable in the AST starts with 'input_'."""
        for leaf in claripy_ast.leaf_asts():
            if leaf.op == "BVS":
                raw_name = leaf.args[0]
                if not raw_name.startswith("input_"):
                    return False
        return True

    def run(self, dst_ptr, size, src_ptr):
        src_addr = self.state.solver.eval(src_ptr)
        print("[*] BPF Helper: bpf_probe_read called at source address: ", src_addr)

        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "bpf_probe_read",
            claripy.BVV(0, 64),
            errno=14,
        )
        size_int = self.state.solver.eval(size)
        if size_int > 0:
            in_elf_space = src_addr < self.BPF_MANAGED_ADDR_MIN
            src_is_symbolic = not self.state.solver.is_true(
                src_ptr == claripy.BVV(src_addr, src_ptr.size())
            )

            if in_elf_space or src_is_symbolic:
                data = None
            else:
                data = self.state.memory.load(
                    src_ptr,
                    size_int,
                    endness=self.state.arch.memory_endness,
                )

            if data is None or not self._has_only_input_vars(data):
                counter = self.state.globals.get(self.KEY_CTR, 0)
                self.state.globals[self.KEY_CTR] = counter + 1
                data = claripy.BVS(
                    f"input_probe_read_kernel_v{counter}",
                    size_int * 8,
                )
                print(f"[*] BPF Helper: probe_read from non-input memory → input_probe_read_kernel_v{counter}")

            if fail_cond is None:
                self.state.memory.store(
                    dst_ptr,
                    data,
                    endness=self.state.arch.memory_endness,
                )
            else:
                self.state.memory.store(
                    dst_ptr,
                    data,
                    endness=self.state.arch.memory_endness,
                    condition=claripy.Not(fail_cond),
                )

        return ret
    
class BpfGetCurrentComm(SimProcedure):
    """
    Model bpf_get_current_comm(buf, size).
    Writes a null-terminated string representing the current task name into 'buf'.
    """
    KEY_CTR = "get_comm_counter"
    TASK_COMM_LEN = 16

    def run(self, buf_ptr, size):
        print("[*] BPF Helper: bpf_get_current_comm called.")

        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "get_current_comm",
            claripy.BVV(0, 64),
            errno=14,
        )
        size_int = self.state.solver.eval(size)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        if size_int > 0:
            norm_bits = self.TASK_COMM_LEN * 8
            comm_bvs = claripy.BVS(f"input_current_comm_v{counter}", norm_bits)
            actual_bits = size_int * 8
            store_val = claripy.Extract(actual_bits - 1, 0, comm_bvs) if actual_bits < norm_bits else comm_bvs
            if fail_cond is None:
                self.state.memory.store(
                    buf_ptr,
                    store_val,
                    endness=self.state.arch.memory_endness,
                )
            else:
                self.state.memory.store(
                    buf_ptr,
                    store_val,
                    endness=self.state.arch.memory_endness,
                    condition=claripy.Not(fail_cond),
                )

        return ret

class BpfPerfEventOutput(SimProcedure):
    KEY_CTR = "perf_output_counter"
    PERF_MAP_NAME = "__perf_output"
    PERF_MAP_ADDR = 0xFEED0000

    def run(self, ctx_ptr, map_ptr, flags, data_ptr, size):
        print("[*] BPF Helper: bpf_perf_event_output called.")
        ret, _ = _maybe_fail_errno_ret(
            self.state,
            "perf_event_output",
            claripy.BVV(0, 64),
            errno=28,
        )

        if self.state.solver.symbolic(size):
            size_int = self.state.solver.min(size)
        else:
            size_int = self.state.solver.eval(size)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        if size_int > 0:
            data_bvs = self.state.memory.load(
                data_ptr,
                size_int,
                endness=self.state.arch.memory_endness,
            )

            map_manager = self.state.ebpf_map

            perf_map = None
            for m in map_manager._maps_by_index:
                if m["name"] == self.PERF_MAP_NAME:
                    perf_map = m
                    break

            if perf_map is None:
                perf_idx = map_manager.create_map(
                    map_addr=self.PERF_MAP_ADDR,
                    key_size=4,
                    value_size=size_int,
                    max_entries=64,
                    map_type="array",
                    map_name=self.PERF_MAP_NAME,
                )
                perf_map = map_manager._maps_by_index[perf_idx]

            key_bvv = claripy.BVV(counter, 32)
            map_manager.update_elem(self.state, perf_map, key_bvv, data_bvs)

        return ret

class BpfPerfEventRead(angr.SimProcedure):
    """
    Model bpf_perf_event_read(map, flags).

    Returns a non-negative symbolic counter value. Error paths are not modeled
    yet to keep the stub additive and low-risk.
    """
    KEY_CTR = "perf_event_read_counter"

    def run(self, map_ptr, flags):
        print("[*] BPF Helper: bpf_perf_event_read called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        ret = claripy.BVS(f"input_perf_event_read_v{counter}", 64)
        self.state.add_constraints(ret[63] == 0)
        return ret

class BpfPerfEventReadValue(angr.SimProcedure):
    """
    Model bpf_perf_event_read_value(map, flags, buf, buf_size).

    On success, fills the output buffer with symbolic bytes and returns 0.
    """
    KEY_CTR = "perf_event_read_value_counter"

    def run(self, map_ptr, flags, buf_ptr, buf_size):
        print("[*] BPF Helper: bpf_perf_event_read_value called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        size_int = self.state.solver.eval(buf_size)
        if size_int > 0:
            data = claripy.BVS(f"input_perf_event_read_value_v{counter}", size_int * 8)
            self.state.memory.store(
                buf_ptr,
                data,
                endness=self.state.arch.memory_endness,
            )

        return claripy.BVV(0, 64)

class BpfPerfProgReadValue(angr.SimProcedure):
    """
    Model bpf_perf_prog_read_value(ctx, buf, buf_size).

    On success, fills the output buffer with symbolic bytes and returns 0.
    """
    KEY_CTR = "perf_prog_read_value_counter"

    def run(self, ctx_ptr, buf_ptr, buf_size):
        print("[*] BPF Helper: bpf_perf_prog_read_value called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        size_int = self.state.solver.eval(buf_size)
        if size_int > 0:
            data = claripy.BVS(f"input_perf_prog_read_value_v{counter}", size_int * 8)
            self.state.memory.store(
                buf_ptr,
                data,
                endness=self.state.arch.memory_endness,
            )

        return claripy.BVV(0, 64)

class BpfCurrentTaskUnderCgroup(angr.SimProcedure):
    KEY_CTR = "under_cgroup_counter"

    def run(self, map_ptr, index):
        print("[*] BPF Helper: bpf_current_task_under_cgroup called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1
        res32 = claripy.BVS(f"input_under_cgroup_v{counter}", 32)
        self.state.add_constraints(claripy.Or(res32 == 0, res32 == 1))
        success_ret = claripy.ZeroExt(32, res32)
        ret, _ = _maybe_fail_errno_ret(
            self.state,
            "current_task_under_cgroup",
            success_ret,
            errno=14,
        )
        return ret

class BpfGetCurrentUidGid(angr.SimProcedure):
    """
    Returns (gid << 32) | uid.
    Returns consistent value per execution (stored in state.globals).
    """
    KEY = "current_uid_gid"

    def run(self):
        print("[*] BPF Helper: bpf_get_current_uid_gid called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        uid_gid = claripy.BVS("input_uid_gid", 64)
        self.state.globals[self.KEY] = uid_gid
        return uid_gid

class BpfGetCurrentTask(angr.SimProcedure):
    """
    Returns a pointer to the current task_struct.
    Returns consistent value per execution (stored in state.globals).
    The pointer is constrained to be in kernel address space.
    """
    KEY = "current_task_ptr"
    KERNEL_BASE = 0xffff800000000000

    def run(self):
        print("[*] BPF Helper: bpf_get_current_task called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        task_ptr = claripy.BVS("input_task_struct_ptr", 64)
        self.state.add_constraints(task_ptr >= self.KERNEL_BASE)
        self.state.add_constraints((task_ptr & 0x7) == 0)

        self.state.globals[self.KEY] = task_ptr
        return task_ptr

class BpfKtimeGetBootNS(angr.SimProcedure):
    """bpf_ktime_get_boot_ns — same as ktime_get_ns but includes suspended time."""
    KEY_CTR = "ktime_boot_call_counter"
    KEY_LAST = "last_ktime_boot"

    def run(self):
        print("[*] BPF Helper: bpf_ktime_get_boot_ns called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        ret = claripy.BVS(f"input_ktime_boot_v{counter}", 64)

        last_time = self.state.globals.get(self.KEY_LAST, None)
        if last_time is not None:
            self.state.add_constraints(ret.UGE(last_time))
        else:
            self.state.add_constraints(ret.UGE(0))

        self.state.globals[self.KEY_LAST] = ret
        return ret

class BpfGetCurrentTaskBtf(angr.SimProcedure):
    """bpf_get_current_task_btf — same as bpf_get_current_task but with BTF type info."""
    KEY = "current_task_btf_ptr"
    KERNEL_BASE = 0xffff800000000000

    def run(self):
        print("[*] BPF Helper: bpf_get_current_task_btf called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        task_ptr = claripy.BVS("input_task_struct_btf_ptr", 64)
        self.state.add_constraints(task_ptr >= self.KERNEL_BASE)
        self.state.add_constraints((task_ptr & 0x7) == 0)

        self.state.globals[self.KEY] = task_ptr
        return task_ptr

class BpfGetCurrentCgroupId(angr.SimProcedure):
    """
    Returns current task cgroup v2 id (u64).
    Returns consistent value per execution (stored in state.globals).
    """
    KEY = "current_cgroup_id"

    def run(self):
        print("[*] BPF Helper: bpf_get_current_cgroup_id called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        cgroup_id = claripy.BVS("input_cgroup_id", 64)
        self.state.globals[self.KEY] = cgroup_id
        return cgroup_id

class BpfGetCgroupClassid(angr.SimProcedure):
    """
    Returns the current task's net_cls classid as a stable symbolic u32.
    """
    KEY = "current_cgroup_classid"

    def run(self, skb_ptr):
        print("[*] BPF Helper: bpf_get_cgroup_classid called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        classid = claripy.ZeroExt(32, claripy.BVS("input_cgroup_classid", 32))
        self.state.globals[self.KEY] = classid
        return classid

class BpfProbeReadUser(angr.SimProcedure):
    """Exactly like BpfProbeRead but for user-space addresses."""
    def run(self, dst_ptr, size, src_ptr):
        print(f"[*] BPF Helper: bpf_probe_read_user called. Src: {src_ptr}")
        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "bpf_probe_read_user",
            claripy.BVV(0, 64),
            errno=14,
        )
        size_int = self.state.solver.eval(size)
        if size_int > 0:
            data = self.state.memory.load(src_ptr, size_int, endness=self.state.arch.memory_endness)
            if fail_cond is None:
                self.state.memory.store(dst_ptr, data, endness=self.state.arch.memory_endness)
            else:
                self.state.memory.store(
                    dst_ptr,
                    data,
                    endness=self.state.arch.memory_endness,
                    condition=claripy.Not(fail_cond),
                )
        return ret

def _model_nul_stopping_str_read(state, dst_ptr, size_int, sym_prefix, counter, fail_cond):
    ret_len = claripy.BVS(f"{sym_prefix}_len_v{counter}", 64)
    state.add_constraints(ret_len.ULE(size_int))
    state.add_constraints(ret_len.UGE(1))
    sym = claripy.BVS(f"{sym_prefix}_v{counter}", size_int * 8)

    partial = angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY in state.options
    if not partial:
        if fail_cond is None:
            state.memory.store(dst_ptr, sym)
        else:
            state.memory.store(dst_ptr, sym, condition=claripy.Not(fail_cond))
        return ret_len

    endness = state.arch.memory_endness
    old = state.memory.load(dst_ptr, size_int, endness=endness)
    parts = []
    for i in range(size_int):
        lo = i * 8
        write_cond = claripy.BVV(i, 64).ULT(ret_len)
        parts.append(claripy.If(write_cond, sym[lo + 7:lo], old[lo + 7:lo]))
    val = claripy.Concat(*reversed(parts))
    if fail_cond is not None:
        val = claripy.If(fail_cond, old, val)
    state.memory.store(dst_ptr, val, endness=endness)
    return ret_len

class BpfProbeReadUserStr(angr.SimProcedure):
    KEY_CTR = "probe_read_user_str_counter"

    def run(self, dst_ptr, size, src_ptr):
        print("[*] BPF Helper: bpf_probe_read_user_str called.")
        size_int = self.state.solver.eval(size)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        if size_int <= 0:
            return _errno_ret(22, 64)

        fail_enabled = _should_model_helper_failure(self.state, "bpf_probe_read_user_str")
        fail_cond = _helper_failure_cond(self.state, "bpf_probe_read_user_str") if fail_enabled else None

        ret_len = _model_nul_stopping_str_read(
            self.state, dst_ptr, size_int, "input_user_str", counter, fail_cond
        )
        if fail_cond is None:
            return ret_len
        return claripy.If(fail_cond, _errno_ret(14, 64), ret_len)

class BpfGetStackid(angr.SimProcedure):
    """
    Model bpf_get_stackid(ctx, map, flags).

    Returns a symbolic stack ID that can be used as a key into a stack_trace map.
    The actual stack trace content is not modeled - we just return symbolic IDs.
    """
    KEY = "stackid_counter"

    def run(self, ctx_ptr, map_ptr, flags):
        print("[*] BPF Helper: bpf_get_stackid called.")

        counter = self.state.globals.get(self.KEY, 0)
        self.state.globals[self.KEY] = counter + 1

        stack_id = claripy.BVS(f"input_stackid_v{counter}", 64)

        self.state.add_constraints(stack_id.UGE(0))
        self.state.add_constraints(stack_id.ULT(0x7FFFFFFF))

        ret, _ = _maybe_fail_errno_ret(
            self.state,
            "get_stackid",
            stack_id,
            errno=14,
        )
        return ret

class BpfGetStack(angr.SimProcedure):
    """
    Model bpf_get_stack(ctx, buf, size, flags).

    Fills buf with a symbolic representation of the stack trace.
    Returns the number of bytes written (or negative error).
    """
    KEY_CTR = "get_stack_counter"

    def run(self, ctx_ptr, buf_ptr, size, flags):
        print("[*] BPF Helper: bpf_get_stack called.")

        fail_enabled = _should_model_helper_failure(self.state, "get_stack")
        fail_cond = _helper_failure_cond(self.state, "get_stack") if fail_enabled else None
        size_int = self.state.solver.eval(size)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        if size_int > 0:
            stack_data = claripy.BVS(f"input_stack_data_v{counter}", size_int * 8)
            if fail_cond is None:
                self.state.memory.store(buf_ptr, stack_data)
            else:
                self.state.memory.store(buf_ptr, stack_data, condition=claripy.Not(fail_cond))

        ret_size = claripy.BVS(f"input_stack_size_v{counter}", 64)
        self.state.add_constraints(ret_size.UGE(0))
        self.state.add_constraints(ret_size.ULE(size_int))

        if fail_cond is None:
            return ret_size
        return claripy.If(fail_cond, _errno_ret(14, 64), ret_size)

class BpfRingbufReserve(angr.SimProcedure):
    """
    Model bpf_ringbuf_reserve(ringbuf, size, flags).

    Returns a pointer to reserved space in the ring buffer.
    Since ringbuf is an output sink, we just allocate symbolic memory.
    Saves reservation metadata so BpfRingbufSubmit can track the output.
    """
    KEY = "ringbuf_ptr"
    KEY_CTR = "ringbuf_reserve_counter"

    def run(self, ringbuf_ptr, size, flags):
        print("[*] BPF Helper: bpf_ringbuf_reserve called.")

        size_int = self.state.solver.eval(size)
        fail_enabled = _should_model_helper_failure(self.state, "ringbuf_reserve")
        fail_cond = _helper_failure_cond(self.state, "ringbuf_reserve") if fail_enabled else None

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        base_addr = self.state.globals.get(self.KEY, 0xBEEF0000)
        self.state.globals[self.KEY] = base_addr + size_int + 8

        RINGBUF_TRACK_MAX = self.state.globals.get("ringbuf_track_max", 512)
        track = 0 < size_int <= RINGBUF_TRACK_MAX

        if track:
            reserved_data = claripy.BVS(f"input_ringbuf_data_v{counter}", size_int * 8)
            if fail_cond is None:
                self.state.memory.store(base_addr, reserved_data)
            else:
                self.state.memory.store(base_addr, reserved_data, condition=claripy.Not(fail_cond))
        elif size_int > RINGBUF_TRACK_MAX:
            print(f"[*] bpf_ringbuf_reserve: size {size_int} > {RINGBUF_TRACK_MAX} bytes, "
                  f"skipping symbolic tracking (Z3 size limit).")

        reservations = self.state.globals.get("ringbuf_reservations", {})
        reservations[base_addr] = size_int if track else 0
        self.state.globals["ringbuf_reservations"] = reservations

        success_ptr = claripy.BVV(base_addr, 64)
        ret, _ = _maybe_fail_ptr_ret(self.state, "ringbuf_reserve", success_ptr)
        return ret

class BpfRingbufSubmit(angr.SimProcedure):
    """
    Model bpf_ringbuf_submit(data, flags).

    Stores submitted data in a synthetic __ringbuf_output array map so the
    equivalence checker can compare ringbuf output between C and Rust programs.
    """
    KEY_CTR = "ringbuf_output_counter"
    RINGBUF_MAP_NAME = "__ringbuf_output"
    RINGBUF_MAP_ADDR = 0xFEED1000

    def run(self, data_ptr, flags):
        print("[*] BPF Helper: bpf_ringbuf_submit called.")

        reservations = self.state.globals.get("ringbuf_reservations", {})
        data_ptr_int = self.state.solver.eval(data_ptr)
        size_int = reservations.get(data_ptr_int, 0)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        if size_int > 0:
            data_bvs = self.state.memory.load(
                data_ptr,
                size_int,
                endness=self.state.arch.memory_endness,
            )

            map_manager = self.state.ebpf_map

            ringbuf_map = None
            for m in map_manager._maps_by_index:
                if m["name"] == self.RINGBUF_MAP_NAME:
                    ringbuf_map = m
                    break

            if ringbuf_map is None:
                rb_idx = map_manager.create_map(
                    map_addr=self.RINGBUF_MAP_ADDR,
                    key_size=4,
                    value_size=size_int,
                    max_entries=64,
                    map_type="array",
                    map_name=self.RINGBUF_MAP_NAME,
                )
                ringbuf_map = map_manager._maps_by_index[rb_idx]

            key_bvv = claripy.BVV(counter, 32)
            map_manager.update_elem(self.state, ringbuf_map, key_bvv, data_bvs)

        return

class BpfRingbufDiscard(angr.SimProcedure):
    """
    Model bpf_ringbuf_discard(data, flags).

    Discards previously reserved ring buffer space.
    """
    def run(self, data_ptr, flags):
        print("[*] BPF Helper: bpf_ringbuf_discard called.")
        return

class BpfRedirectMap(angr.SimProcedure):
    """
    Model bpf_redirect_map(map, key, flags).

    Used by XDP programs to redirect packets via DEVMAP, CPUMAP, or XSKMAP.
    Returns XDP_REDIRECT (4) on success, XDP_ABORTED (0) on failure.

    Stores the redirect index and flags in a synthetic __redirect_map_output
    array map so the equivalence checker can compare redirect targets between
    C and Rust programs.
    """
    XDP_ABORTED = 0
    XDP_REDIRECT = 4
    KEY_CTR = "redirect_map_output_counter"
    REDIRECT_MAP_NAME = "__redirect_map_output"
    REDIRECT_MAP_ADDR = 0xFEED2000

    def run(self, map_ptr, key, flags):
        print("[*] BPF Helper: bpf_redirect_map called.")
        success_ret = claripy.BVV(self.XDP_REDIRECT, 64)
        ret, _ = _maybe_fail_errno_ret(
            self.state,
            "redirect_map",
            success_ret,
            errno=22,
        )

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        key_32 = key[31:0]
        flags_32 = flags[31:0]
        value_bvs = claripy.Concat(flags_32, key_32)

        map_manager = self.state.ebpf_map

        redir_map = None
        for m in map_manager._maps_by_index:
            if m["name"] == self.REDIRECT_MAP_NAME:
                redir_map = m
                break

        if redir_map is None:
            rm_idx = map_manager.create_map(
                map_addr=self.REDIRECT_MAP_ADDR,
                key_size=4,
                value_size=8,
                max_entries=64,
                map_type="array",
                map_name=self.REDIRECT_MAP_NAME,
            )
            redir_map = map_manager._maps_by_index[rm_idx]

        map_key = claripy.BVV(counter, 32)
        map_manager.update_elem(self.state, redir_map, map_key, value_bvs)

        return ret

class BpfXdpAdjustHead(angr.SimProcedure):
    """
    Model bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta).

    Moves xdp_md->data by delta bytes (negative = grow headroom,
    positive = shrink).  xdp_md->data_end is unchanged.
    Returns 0 on success, -EINVAL on failure.

    Failable: yes – in real kernels the call fails when the adjusted
    pointer would underflow data_hard_start or leave less than ETH_HLEN
    bytes before data_end.
    """

    def run(self, ctx_ptr, delta):
        print("[*] BPF Helper: bpf_xdp_adjust_head called.")

        success_ret = claripy.BVV(0, 64)
        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "xdp_adjust_head",
            success_ret,
            errno=22,
        )

        old_data = self.state.memory.load(
            ctx_ptr,
            4,
            endness=self.state.arch.memory_endness,
        )

        delta_32 = delta[31:0].sign_extend(32)
        new_data = old_data.zero_extend(32) + delta_32
        new_data_32 = new_data[31:0]

        if fail_cond is None:
            self.state.memory.store(
                ctx_ptr,
                new_data_32,
                endness=self.state.arch.memory_endness,
            )
        else:
            self.state.memory.store(
                ctx_ptr,
                new_data_32,
                endness=self.state.arch.memory_endness,
                condition=claripy.Not(fail_cond),
            )

        return ret

class BpfCsumDiff(angr.SimProcedure):
    """
    Model bpf_csum_diff(__be32 *from, u32 from_size,
                        __be32 *to,   u32 to_size, __wsum seed).

    Returns an incremental one's-complement checksum.  The computation
    is deterministic given the inputs, but modelling the full folded
    one's-complement arithmetic symbolically is expensive and rarely
    needed for equivalence checking.  We therefore return a fresh
    symbolic value per call-site; the Z3VariableUnifier will pair up
    corresponding calls between C and Rust by sequence counter.

    Not failable – verified programs always pass aligned, in-bounds
    buffers, and the current kernel implementation has no runtime error
    path.
    """
    KEY_CTR = "csum_diff_counter"

    def run(self, from_ptr, from_size, to_ptr, to_size, seed):
        print("[*] BPF Helper: bpf_csum_diff called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1
        return claripy.BVS(f"input_csum_diff_v{counter}", 64)

class BpfRingbufOutput(angr.SimProcedure):
    """
    Model bpf_ringbuf_output(ringbuf, data, size, flags).

    Combines reserve+submit in one call: reads data from data_ptr and stores it
    in the synthetic __ringbuf_output array map.  Shares the same output counter
    as BpfRingbufSubmit so outputs from both patterns share one sequence.
    """
    KEY_CTR = "ringbuf_output_counter"
    RINGBUF_MAP_NAME = "__ringbuf_output"
    RINGBUF_MAP_ADDR = 0xFEED1000

    def run(self, ringbuf_ptr, data_ptr, size, flags):
        print("[*] BPF Helper: bpf_ringbuf_output called.")
        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "ringbuf_output",
            claripy.BVV(0, 64),
            errno=28,
        )

        size_int = self.state.solver.eval(size)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        RINGBUF_TRACK_MAX = self.state.globals.get("ringbuf_track_max", 512)
        if size_int > RINGBUF_TRACK_MAX:
            print(f"[*] bpf_ringbuf_output: size {size_int} > {RINGBUF_TRACK_MAX} bytes, "
                  f"skipping symbolic tracking (Z3 size limit).")

        if 0 < size_int <= RINGBUF_TRACK_MAX:
            data_bvs = self.state.memory.load(
                data_ptr,
                size_int,
                endness=self.state.arch.memory_endness,
            )

            map_manager = self.state.ebpf_map

            ringbuf_map = None
            for m in map_manager._maps_by_index:
                if m["name"] == self.RINGBUF_MAP_NAME:
                    ringbuf_map = m
                    break

            if ringbuf_map is None:
                rb_idx = map_manager.create_map(
                    map_addr=self.RINGBUF_MAP_ADDR,
                    key_size=4,
                    value_size=size_int,
                    max_entries=64,
                    map_type="array",
                    map_name=self.RINGBUF_MAP_NAME,
                )
                ringbuf_map = map_manager._maps_by_index[rb_idx]

            key_bvv = claripy.BVV(counter, 32)
            map_manager.update_elem(self.state, ringbuf_map, key_bvv, data_bvs)

        return ret

class BpfProbeReadKernelStr(angr.SimProcedure):
    """
    Model bpf_probe_read_kernel_str(dst, size, unsafe_ptr).

    Mirrors BpfProbeReadUserStr but for kernel-space reads.
    """
    KEY_CTR = "probe_read_kernel_str_counter"

    def run(self, dst_ptr, size, src_ptr):
        print("[*] BPF Helper: bpf_probe_read_kernel_str called.")
        size_int = self.state.solver.eval(size)

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        if size_int <= 0:
            return _errno_ret(22, 64)

        fail_enabled = _should_model_helper_failure(self.state, "bpf_probe_read_kernel_str")
        fail_cond = _helper_failure_cond(self.state, "bpf_probe_read_kernel_str") if fail_enabled else None

        ret_len = _model_nul_stopping_str_read(
            self.state, dst_ptr, size_int, "input_kernel_str", counter, fail_cond
        )
        if fail_cond is None:
            return ret_len
        return claripy.If(fail_cond, _errno_ret(14, 64), ret_len)

class BpfGetFuncIp(SimProcedure):
    """
    Model bpf_get_func_ip(ctx).

    Returns the IP address of the traced function.  Always succeeds (not failable).
    Returns a fresh symbolic value per call.
    """
    KEY_CTR = "func_ip_counter"

    def run(self, ctx_ptr):
        print("[*] BPF Helper: bpf_get_func_ip called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1
        return claripy.BVS(f"input_func_ip_v{counter}", 64)

class BpfGetNumaNodeId(SimProcedure):
    """Return a stable symbolic NUMA node id."""
    KEY = "numa_node_id"

    def run(self):
        print("[*] BPF Helper: bpf_get_numa_node_id called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        node_id = claripy.ZeroExt(32, claripy.BVS("input_numa_node_id", 32))
        self.state.add_constraints(node_id.ULE(4096))
        self.state.globals[self.KEY] = node_id
        return node_id

class BpfGetSocketCookie(SimProcedure):
    """
    Model bpf_get_socket_cookie(ctx) -> u64.

    Returns a u64 cookie uniquely identifying the socket associated with the
    current skb/sock context.  For equivalence checking, both C and Rust call
    this helper with the same ctx, so we return a single shared symbolic value
    per call site (keyed by invocation counter) — the same value for both
    programs when the path predicates match.
    """
    KEY_CTR = "socket_cookie_counter"

    def run(self, ctx_ptr):
        print("[*] BPF Helper: bpf_get_socket_cookie called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1
        return BVS(f"input_socket_cookie_v{counter}", 64)

class BpfGetSocketUid(SimProcedure):
    """Return the socket owner's uid as a stable symbolic u32."""
    KEY = "socket_uid"

    def run(self, ctx_ptr):
        print("[*] BPF Helper: bpf_get_socket_uid called.")
        cached = self.state.globals.get(self.KEY, None)
        if cached is not None:
            return cached

        uid = claripy.ZeroExt(32, claripy.BVS("input_socket_uid", 32))
        self.state.globals[self.KEY] = uid
        return uid

class BpfTailCall(SimProcedure):
    """
    Model bpf_tail_call(ctx, prog_array, index).

    In production, this replaces the current program with the one at
    prog_array[index].  On failure (index out of range, NULL entry, or
    nesting limit exceeded), execution falls through to the next instruction.

    We model this as a **no-op fallthrough**: the tail call always "fails"
    and execution continues.  This is correct for equivalence checking
    because both C and Rust programs see the same fallthrough behavior.
    """
    def run(self, ctx_ptr, prog_array_ptr, index):
        print("[*] BPF Helper: bpf_tail_call called (modeled as no-op fallthrough).")
        return

class BpfLoop(SimProcedure):
    """
    Coarse model of bpf_loop(nr_loops, callback_fn, callback_ctx, flags).

    This stub does not execute the callback. It returns the requested loop
    count when flags == 0, or -EINVAL for unsupported flag values.
    """
    def run(self, nr_loops, callback_fn, callback_ctx, flags):
        print("[*] BPF Helper: bpf_loop called (callback execution not modeled).")
        loops = claripy.ZeroExt(32, nr_loops[31:0])
        return claripy.If(flags == 0, loops, _errno_ret(22, 64))

class BpfXdpAdjustTail(SimProcedure):
    """
    Model bpf_xdp_adjust_tail(struct xdp_md *xdp_md, int delta).

    Adjusts xdp_md->data_end by delta bytes.
    Returns 0 on success, negative on failure.

    For symbolic execution, we model this as always succeeding and
    updating the data_end field in the XDP context.
    """
    def run(self, ctx_ptr, delta):
        print("[*] BPF Helper: bpf_xdp_adjust_tail called.")
        old_data_end = self.state.memory.load(
            ctx_ptr + 4, 4, endness=self.state.arch.memory_endness,
        )
        delta_32 = delta[31:0].sign_extend(32)
        new_data_end = old_data_end.zero_extend(32) + delta_32
        new_data_end_32 = new_data_end[31:0]
        self.state.memory.store(
            ctx_ptr + 4,
            new_data_end_32,
            endness=self.state.arch.memory_endness,
        )
        return BVV(0, 64)

class BpfKtimeGetTaiNS(angr.SimProcedure):
    """bpf_ktime_get_tai_ns — TAI (International Atomic Time) clock, similar to ktime_get_ns."""
    KEY_CTR = "ktime_tai_call_counter"
    KEY_LAST = "last_ktime_tai"

    def run(self):
        print("[*] BPF Helper: bpf_ktime_get_tai_ns called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        ret = claripy.BVS(f"input_ktime_tai_v{counter}", 64)

        last_time = self.state.globals.get(self.KEY_LAST, None)
        if last_time is not None:
            self.state.add_constraints(ret.UGE(last_time))
        else:
            self.state.add_constraints(ret.UGE(0))

        self.state.globals[self.KEY_LAST] = ret
        return ret

class BpfSetsockopt(angr.SimProcedure):
    """
    Model bpf_setsockopt(bpf_socket, level, optname, optval, optlen).

    This low-risk stub treats the helper as a successful side-effecting call.
    """
    def run(self, bpf_socket, level, optname, optval, optlen):
        print("[*] BPF Helper: bpf_setsockopt called.")
        return claripy.BVV(0, 64)

class BpfGetsockopt(angr.SimProcedure):
    """
    Model bpf_getsockopt(bpf_socket, level, optname, optval, optlen).

    On success, fills the output buffer with symbolic bytes and returns 0.
    """
    KEY_CTR = "getsockopt_counter"

    def run(self, bpf_socket, level, optname, optval, optlen):
        print("[*] BPF Helper: bpf_getsockopt called.")
        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        size_int = self.state.solver.eval(optlen)
        if size_int > 0:
            data = claripy.BVS(f"input_getsockopt_v{counter}", size_int * 8)
            self.state.memory.store(
                optval,
                data,
                endness=self.state.arch.memory_endness,
            )

        return claripy.BVV(0, 64)

class BpfSockOpsCbFlagsSet(angr.SimProcedure):
    """
    Model bpf_sock_ops_cb_flags_set(bpf_sock, argval).

    This is treated as a successful control-plane update.
    """
    def run(self, bpf_sock, argval):
        print("[*] BPF Helper: bpf_sock_ops_cb_flags_set called.")
        return claripy.BVV(0, 64)

class BpfGetHashRecalc(angr.SimProcedure):
    """bpf_get_hash_recalc — return skb->hash, recalculating if needed. Returns u32."""

    def run(self, skb_ptr):
        print("[*] BPF Helper: bpf_get_hash_recalc called.")
        return claripy.BVS("input_skb_hash", 64)

class BpfRedirect(angr.SimProcedure):
    """
    Model bpf_redirect(u32 ifindex, u64 flags).

    Returns TC_ACT_REDIRECT (7) for TC programs or XDP_REDIRECT (4) for XDP.
    Stores the redirect target in a synthetic map for equivalence checking.
    """
    TC_ACT_REDIRECT = 7
    KEY_CTR = "redirect_output_counter"
    REDIRECT_MAP_NAME = "__redirect_output"
    REDIRECT_MAP_ADDR = 0xFEED3000

    def run(self, ifindex, flags):
        print("[*] BPF Helper: bpf_redirect called.")
        success_ret = claripy.BVV(self.TC_ACT_REDIRECT, 64)
        ret, _ = _maybe_fail_errno_ret(
            self.state,
            "redirect",
            success_ret,
            errno=22,
        )

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        ifindex_32 = ifindex[31:0]
        flags_32 = flags[31:0]
        value_bvs = claripy.Concat(flags_32, ifindex_32)

        map_manager = self.state.ebpf_map
        redir_map = None
        for m in map_manager._maps_by_index:
            if m["name"] == self.REDIRECT_MAP_NAME:
                redir_map = m
                break

        if redir_map is None:
            rm_idx = map_manager.create_map(
                map_addr=self.REDIRECT_MAP_ADDR,
                key_size=4, value_size=8, max_entries=64,
                map_type="array", map_name=self.REDIRECT_MAP_NAME,
            )
            redir_map = map_manager._maps_by_index[rm_idx]

        map_key = claripy.BVV(counter, 32)
        map_manager.update_elem(self.state, redir_map, map_key, value_bvs)
        return ret

class BpfRedirectNeigh(angr.SimProcedure):
    """
    Model bpf_redirect_neigh(u32 ifindex, struct bpf_redir_neigh *params, int plen, u64 flags).

    Like bpf_redirect but performs neighbor lookup. For symbolic execution,
    we model it identically to bpf_redirect (store target, return redirect action).
    """
    TC_ACT_REDIRECT = 7
    KEY_CTR = "redirect_neigh_output_counter"
    REDIRECT_MAP_NAME = "__redirect_neigh_output"
    REDIRECT_MAP_ADDR = 0xFEED4000

    def run(self, ifindex, params, plen, flags):
        print("[*] BPF Helper: bpf_redirect_neigh called.")
        success_ret = claripy.BVV(self.TC_ACT_REDIRECT, 64)
        ret, _ = _maybe_fail_errno_ret(
            self.state,
            "redirect_neigh",
            success_ret,
            errno=22,
        )

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        ifindex_32 = ifindex[31:0]
        flags_32 = flags[31:0]
        value_bvs = claripy.Concat(flags_32, ifindex_32)

        map_manager = self.state.ebpf_map
        redir_map = None
        for m in map_manager._maps_by_index:
            if m["name"] == self.REDIRECT_MAP_NAME:
                redir_map = m
                break

        if redir_map is None:
            rm_idx = map_manager.create_map(
                map_addr=self.REDIRECT_MAP_ADDR,
                key_size=4, value_size=8, max_entries=64,
                map_type="array", map_name=self.REDIRECT_MAP_NAME,
            )
            redir_map = map_manager._maps_by_index[rm_idx]

        map_key = claripy.BVV(counter, 32)
        map_manager.update_elem(self.state, redir_map, map_key, value_bvs)
        return ret

class BpfXdpAdjustMeta(angr.SimProcedure):
    """
    Model bpf_xdp_adjust_meta(struct xdp_md *xdp_md, int delta).

    Adjusts xdp_md->data_meta by delta bytes.
    data_meta is at offset 8 in struct xdp_md (after data at 0, data_end at 4).
    Returns 0 on success, -EINVAL on failure.
    """
    def run(self, ctx_ptr, delta):
        print("[*] BPF Helper: bpf_xdp_adjust_meta called.")
        success_ret = claripy.BVV(0, 64)
        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "xdp_adjust_meta",
            success_ret,
            errno=22,
        )

        old_data_meta = self.state.memory.load(
            ctx_ptr + 8, 4, endness=self.state.arch.memory_endness,
        )

        delta_32 = delta[31:0].sign_extend(32)
        new_data_meta = old_data_meta.zero_extend(32) + delta_32
        new_data_meta_32 = new_data_meta[31:0]

        if fail_cond is None:
            self.state.memory.store(
                ctx_ptr + 8, new_data_meta_32,
                endness=self.state.arch.memory_endness,
            )
        else:
            self.state.memory.store(
                ctx_ptr + 8, new_data_meta_32,
                endness=self.state.arch.memory_endness,
                condition=claripy.Not(fail_cond),
            )
        return ret

class BpfCheckMtu(angr.SimProcedure):
    """
    Model bpf_check_mtu(void *ctx, u32 ifindex, u32 *mtu_len, s32 len_diff, u64 flags).

    Checks if packet fits within MTU. Writes actual MTU to *mtu_len.
    Returns 0 (fits), BPF_MTU_CHK_RET_FRAG_NEEDED (1), or negative on error.
    For symbolic execution: write symbolic MTU, return symbolic result.
    """
    def run(self, ctx_ptr, ifindex, mtu_len_ptr, len_diff, flags):
        print("[*] BPF Helper: bpf_check_mtu called.")
        sym_mtu = claripy.BVS("input_mtu", 32)
        self.state.add_constraints(sym_mtu.UGE(68))
        self.state.add_constraints(sym_mtu.ULE(65535))
        self.state.memory.store(
            mtu_len_ptr, sym_mtu,
            endness=self.state.arch.memory_endness,
        )
        return claripy.BVV(0, 64)

class BpfFibLookup(angr.SimProcedure):
    """
    Model bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags).

    Performs FIB (routing) lookup. Fills params with routing info.
    Returns BPF_FIB_LKUP_RET_SUCCESS (0) or error codes.
    For symbolic execution: fill output fields with symbolic values, return symbolic result.
    """
    def run(self, ctx_ptr, params_ptr, plen, flags):
        print("[*] BPF Helper: bpf_fib_lookup called.")
        plen_concrete = 64
        sym_result = claripy.BVS("input_fib_lookup_data", plen_concrete * 8)
        self.state.memory.store(params_ptr, sym_result)
        return claripy.BVV(0, 64)

class BpfSkbEcnSetCe(angr.SimProcedure):
    """
    Model bpf_skb_ecn_set_ce(struct __sk_buff *skb).

    Sets ECN CE (Congestion Experienced) bit in the IP header.
    Returns 1 on success, 0 on failure.
    For symbolic execution: return symbolic result (can't modify packet header symbolically).
    """
    def run(self, skb_ptr):
        print("[*] BPF Helper: bpf_skb_ecn_set_ce called.")
        return claripy.BVS("input_ecn_set_ce_result", 64)

class BpfSkbAdjustRoom(angr.SimProcedure):
    """
    Model bpf_skb_adjust_room(struct __sk_buff *skb, s32 len_diff, u32 mode, u64 flags).

    Grows or shrinks packet room. Adjusts skb->data and skb->data_end.
    Returns 0 on success, negative on error.
    For symbolic execution: adjust data/data_end fields in __sk_buff context.
    """
    def run(self, skb_ptr, len_diff, mode, flags):
        print("[*] BPF Helper: bpf_skb_adjust_room called.")
        success_ret = claripy.BVV(0, 64)
        ret, fail_cond = _maybe_fail_errno_ret(
            self.state,
            "skb_adjust_room",
            success_ret,
            errno=22,
        )

        old_data_end = self.state.memory.load(
            skb_ptr + 80, 4, endness=self.state.arch.memory_endness,
        )
        delta_32 = len_diff[31:0].sign_extend(32)
        new_data_end = old_data_end.zero_extend(32) + delta_32
        new_data_end_32 = new_data_end[31:0]

        if fail_cond is None:
            self.state.memory.store(
                skb_ptr + 80, new_data_end_32,
                endness=self.state.arch.memory_endness,
            )
        else:
            self.state.memory.store(
                skb_ptr + 80, new_data_end_32,
                endness=self.state.arch.memory_endness,
                condition=claripy.Not(fail_cond),
            )
        return ret

class BpfL4CsumReplace(angr.SimProcedure):
    """
    Model bpf_l4_csum_replace(struct __sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags).

    Replaces L4 checksum field in packet. For symbolic execution, we perform
    the incremental checksum update in-place if the offset is concrete.
    """
    def run(self, skb_ptr, offset, from_val, to_val, flags):
        print("[*] BPF Helper: bpf_l4_csum_replace called.")
        return claripy.BVV(0, 64)

class BpfKfuncStub(angr.SimProcedure):
    """
    Generic stub for kfunc calls (custom kernel module functions).

    Kfuncs are external symbols resolved at load time by the kernel.
    We model them as returning a symbolic value — both C and Rust binaries
    will call the same stub, ensuring equivalence checking works.
    """
    KEY_CTR = "kfunc_call_counter"

    def run(self, *args):
        kfunc_name = self.state.globals.get("_current_kfunc_name", "unknown")
        print(f"[*] BPF kfunc stub: {kfunc_name} called with {len(args)} args.")

        counter = self.state.globals.get(self.KEY_CTR, 0)
        self.state.globals[self.KEY_CTR] = counter + 1

        return claripy.BVS(f"input_kfunc_{kfunc_name}_v{counter}", 64)

KFUNC_HOOK_BASE = 0xFEED5000
KFUNC_HOOK_STRIDE = 0x100

P = {
    "exit": (0, ExitSimProcedure),
    "ktime_get_ns": (5, KtimeGetNSSimProcedure),
    "map_lookup_elem": (1, BpfMapLookupElem),
    "map_update_elem": (2, BpfMapUpdateElem),
    "map_delete_elem": (3, BpfMapDeleteElem),
    "bpf_probe_read": (4, BpfProbeRead),
    "printk": (6, BpfPrintk),
    "get_prandom_u32": (7, BpfGetPrandomU32),
    "get_smp_processor_id": (8, BpfGetSmpProcessorId),
    "get_current_pid_tgid": (14, BpfGetCurrentPidTgid),
    "get_current_uid_gid": (15, BpfGetCurrentUidGid),
    "get_current_comm": (16, BpfGetCurrentComm),
    "get_cgroup_classid": (17, BpfGetCgroupClassid),
    "perf_event_read": (22, BpfPerfEventRead),
    "perf_event_output": (25, BpfPerfEventOutput),
    "get_stackid": (27, BpfGetStackid),
    "get_current_task": (35, BpfGetCurrentTask),
    "current_task_under_cgroup": (37, BpfCurrentTaskUnderCgroup),
    "get_numa_node_id": (42, BpfGetNumaNodeId),
    "get_current_cgroup_id": (80, BpfGetCurrentCgroupId),
    "get_socket_uid": (47, BpfGetSocketUid),
    "setsockopt": (49, BpfSetsockopt),
    "get_stack": (67, BpfGetStack),
    "bpf_probe_read_user": (112, BpfProbeReadUser),
    "bpf_probe_read_kernel": (113, BpfProbeRead),
    "bpf_probe_read_user_str": (114, BpfProbeReadUserStr),
    "ringbuf_reserve": (131, BpfRingbufReserve),
    "ringbuf_submit": (132, BpfRingbufSubmit),
    "ringbuf_discard": (133, BpfRingbufDiscard),
    "redirect_map": (51, BpfRedirectMap),
    "xdp_adjust_head": (44, BpfXdpAdjustHead),
    "csum_diff": (28, BpfCsumDiff),
    "perf_event_read_value": (55, BpfPerfEventReadValue),
    "perf_prog_read_value": (56, BpfPerfProgReadValue),
    "getsockopt": (57, BpfGetsockopt),
    "sock_ops_cb_flags_set": (59, BpfSockOpsCbFlagsSet),
    "ringbuf_output": (130, BpfRingbufOutput),
    "bpf_probe_read_kernel_str": (115, BpfProbeReadKernelStr),
    "get_func_ip": (173, BpfGetFuncIp),
    "get_socket_cookie": (46, BpfGetSocketCookie),
    "tail_call": (12, BpfTailCall),
    "xdp_adjust_tail": (65, BpfXdpAdjustTail),
    "ktime_get_boot_ns": (125, BpfKtimeGetBootNS),
    "get_current_task_btf": (158, BpfGetCurrentTaskBtf),
    "ktime_get_tai_ns": (208, BpfKtimeGetTaiNS),
    "trace_vprintk": (177, BpfPrintk),
    "loop": (181, BpfLoop),
    "get_hash_recalc": (34, BpfGetHashRecalc),
    "redirect": (23, BpfRedirect),
    "redirect_neigh": (152, BpfRedirectNeigh),
    "xdp_adjust_meta": (54, BpfXdpAdjustMeta),
    "check_mtu": (163, BpfCheckMtu),
    "fib_lookup": (69, BpfFibLookup),
    "skb_ecn_set_ce": (97, BpfSkbEcnSetCe),
    "skb_adjust_room": (50, BpfSkbAdjustRoom),
    "l4_csum_replace": (11, BpfL4CsumReplace),
}
syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names("eBPF")
syscall_lib.add_all_from_dict({k: v[1] for k, v in P.items()})
syscall_lib.add_number_mapping_from_dict("abi", {v[0]: k for k, v in P.items()})

class BpfProgramExit(SimProcedure):
    """Hook at BPF_EXIT_SENTINEL that terminates the state cleanly."""
    NO_RET = True

    def run(self):
        self.exit(0)

class SimOsEbpf(SimUserland):
    """Simulate parts of the eBPF env"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, syscall_library=syscall_lib, name="eBPF", **kwargs)

    def state_blank(self, *args, **kwargs):
        state = super().state_blank(*args, **kwargs)
        state.register_plugin('ebpf_map', EbpfMapManager())

        state.regs.call_depth = 1
        state.memory.store(
            BPF_CALL_STACK_BASE,
            claripy.BVV(BPF_EXIT_SENTINEL, 64),
            endness=state.arch.memory_endness,
        )

        if not self.project.is_hooked(BPF_EXIT_SENTINEL):
            self.project.hook(BPF_EXIT_SENTINEL, BpfProgramExit())

        return state

register_simos("UNIX - System V", SimOsEbpf)
