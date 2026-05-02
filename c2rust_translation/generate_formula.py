import sys
import os
import angr
import claripy
from claripy import BVS
import z3
import traceback
import re
import difflib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import struct as _struct

import angr_ebpf
from angr_ebpf.instrs_ebpf import BPF_CALL_STACK_BASE, BPF_EXIT_SENTINEL

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

try:
    from btf_parser import parse_map_metadata_from_btf, MapMetadata
except ImportError:

    from c2rust_translation.btf_parser import parse_map_metadata_from_btf, MapMetadata

try:
    from angr.engines.vex.claripy import irop as _irop
    _orig_irop_init = _irop.SimIROp.__init__

    def _patched_irop_init(self, *args, **kwargs):
        try:
            _orig_irop_init(self, *args, **kwargs)
        except AssertionError:

            if getattr(self, '_from_size', None) == getattr(self, '_to_size', None):
                self._calculate = lambda args: args[0]
            else:
                raise

    _irop.SimIROp.__init__ = _patched_irop_init
except Exception:
    pass

def extract_entry_symbols(filepath):
    """Return list of GLOBAL FUNC symbol names from an eBPF ELF object.

    Filters out internal symbols (_start, license markers) and .text
    subprograms (non-section entry points). Only returns symbols that
    correspond to SEC()-annotated program sections.
    """
    entries = []
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        if not symtab:
            return entries
        for sym in symtab.iter_symbols():
            if (sym['st_info']['type'] == 'STT_FUNC'
                and sym['st_info']['bind'] == 'STB_GLOBAL'
                and sym.name
                and sym.name not in ('_start',)):

                shndx = sym['st_shndx']
                if isinstance(shndx, int) and shndx > 0:
                    section = elf.get_section(shndx)
                    if section and section.name != '.text':
                        entries.append(sym.name)
    return entries

def get_entry_section_type(filepath: str, entry_symbol: str):
    """Return the BPF program type prefix for a given entry symbol, or None.

    Reads the ELF symbol table to find which section the symbol belongs to,
    then extracts the type prefix from the section name.

    Examples:
      section 'kprobe/tcp_connect'   -> 'kprobe'
      section 'uprobe/do_count'      -> 'uprobe'
      section 'usdt/javagc'          -> 'usdt'
      section 'xdp'                  -> 'xdp'
      section 'tracepoint/sched/...' -> 'tracepoint'

    Returns None if the symbol is not found or section name is unrecognizable.
    """
    try:
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            if not symtab:
                return None
            for sym in symtab.iter_symbols():
                if sym.name != entry_symbol:
                    continue
                if sym['st_info']['type'] != 'STT_FUNC':
                    continue
                shndx = sym['st_shndx']
                if not isinstance(shndx, int) or shndx <= 0:
                    continue
                section = elf.get_section(shndx)
                if not section:
                    return None
                sec_name = section.name
                if sec_name.startswith('.'):
                    sec_name = sec_name[1:]
                return sec_name.split('/')[0] if sec_name else None
    except Exception:
        return None
    return None

_COMPATIBLE_TYPE_GROUPS = [
    frozenset({'usdt', 'uprobe'}),
]

_SECTION_PREFIX_ALIASES = {
    'tp': 'tracepoint',
    'ksyscall': 'kprobe',
    'kretsyscall': 'kprobe',
    'tc': 'socket',
    'classifier': 'socket',
}

_TYPE_PREFIX_NORMALIZE = {
    'xdp': 'xdp',
    'filter': 'socket',
    'kprobe': 'kprobe',
    'tp_btf': 'tp_btf',
}

def _normalize_type(t):
    """Normalize a BPF program type to its canonical form."""
    if t is None:
        return None
    if t in _SECTION_PREFIX_ALIASES:
        return _SECTION_PREFIX_ALIASES[t]
    for prefix, base in _TYPE_PREFIX_NORMALIZE.items():
        if t == prefix or t.startswith(prefix + '_'):
            return base
    return t

def program_types_compatible(c_type, rust_type):
    """Return True if c_type and rust_type are compatible BPF program types.

    Returns True (don't block) when either type is unknown/None.
    """
    if c_type is None or rust_type is None:
        return True
    c_norm = _normalize_type(c_type)
    r_norm = _normalize_type(rust_type)
    if c_norm == r_norm:
        return True
    for group in _COMPATIBLE_TYPE_GROUPS:
        if c_norm in group and r_norm in group:
            return True
    return False

def extract_data_symbols(filepath):
    """Return {name: (size_bytes, is_bss)} for global mutable data symbols in .data/.bss sections.

    Excludes .maps, license, .rodata, BTF, and other non-data sections that are
    technically writable but don't contain mutable program globals.

    The is_bss flag indicates the symbol lives in a .bss section (zero-initialized
    by the BPF loader at program load time).
    """

    _SKIP_NAMES = frozenset({'_', '__', '___', 'LICENSE', 'license', '_license'})

    result = {}
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)

        data_sec_indices = set()
        bss_sec_indices = set()
        for i, sec in enumerate(elf.iter_sections()):
            name = sec.name
            if name == '.data' or name.startswith('.data.'):
                data_sec_indices.add(i)
            elif name == '.bss' or name.startswith('.bss.'):
                data_sec_indices.add(i)
                bss_sec_indices.add(i)
        if not data_sec_indices:
            return result
        symtab = elf.get_section_by_name('.symtab')
        if not symtab:
            return result
        for sym in symtab.iter_symbols():
            if sym['st_info']['type'] != 'STT_OBJECT':
                continue
            if sym['st_info']['bind'] not in ('STB_GLOBAL', 'STB_LOCAL'):
                continue
            size = sym['st_size']
            if size == 0:
                continue
            shndx = sym['st_shndx']
            if not isinstance(shndx, int) or shndx not in data_sec_indices:
                continue
            name = sym.name
            if not name:
                continue

            if name in _SKIP_NAMES or len(name) <= 1:
                continue
            result[name] = (size, shndx in bss_sec_indices)
    return result

_DATA_SYMBOLIZE_LIMIT = 64

CTX_ADDR = 0x200000

PKT_BUF_ADDR = 0x300000
DEFAULT_PKT_SIZE = 256

@dataclass
class MapEntrySnapshot:
    """Snapshot of a single map entry at end of a path."""
    key_expr: Any
    final_value_expr: Any
    exists_cond: Any
    written: bool = True
    write_seq: int = -1

@dataclass
class AtomicOpRecord:
    """Record of an atomic instruction found in eBPF bytecode."""
    offset: int
    width: int
    op_name: str
    is_fetch: bool

@dataclass
class PathOutcome:
    """Structured data for one execution path."""
    path_predicate: Any
    output_r0_expr: Any
    map_snapshots: Dict[str, List[MapEntrySnapshot]] = field(default_factory=dict)
    global_writes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ProgramFormula:
    """Structured formula output from symbolic execution."""
    output_var: Any
    paths: List[PathOutcome] = field(default_factory=list)
    map_metadata: Dict[str, dict] = field(default_factory=dict)
    atomic_ops: List[AtomicOpRecord] = field(default_factory=list)
    data_symbols: Dict[str, int] = field(default_factory=dict)

PROGRAM_TYPE_CTX_SIZES = {

    "kprobe": 168,
    "kretprobe": 168,

    "uprobe": 168,
    "uretprobe": 168,

    "usdt": 168,

    "tracepoint": 64,

    "raw_tp": 64,
    "raw_tracepoint": 64,

    "tp_btf": 64,

    "fentry": 64,
    "fexit": 72,

    "perf_event": 72,

    "xdp": 24,

    "socket": 128,

    "filter": 128,

    "cgroup": 64,

    "lwt": 128,

    "default": 128,
}

CTX_FIELD_LAYOUTS = {

    "kprobe": [
        ("r15",     0,   64),
        ("r14",     8,   64),
        ("r13",     16,  64),
        ("r12",     24,  64),
        ("bp",      32,  64),
        ("bx",      40,  64),
        ("r11",     48,  64),
        ("r10",     56,  64),
        ("r9_arg5", 64,  64),
        ("r8_arg4", 72,  64),
        ("ax",      80,  64),
        ("cx_arg3", 88,  64),
        ("dx_arg2", 96,  64),
        ("si_arg1", 104, 64),
        ("di_arg0", 112, 64),
        ("orig_ax", 120, 64),
        ("ip",      128, 64),
        ("cs",      136, 64),
        ("flags",   144, 64),
        ("sp",      152, 64),
        ("ss",      160, 64),
    ],

    "xdp": [
        ("data",            0,  32),
        ("data_end",        4,  32),
        ("data_meta",       8,  32),
        ("ingress_ifindex", 12, 32),
        ("rx_queue_index",  16, 32),
    ],

    "tracepoint": [
        ("common_type",          0, 16),
        ("common_flags",         2, 8),
        ("common_preempt_count", 3, 8),
        ("common_pid",           4, 32),

    ],

    "socket": [
        ("len",              0,  32),
        ("pkt_type",         4,  32),
        ("mark",             8,  32),
        ("queue_mapping",   12,  32),
        ("protocol",        16,  32),
        ("vlan_present",    20,  32),
        ("vlan_tci",        24,  32),
        ("vlan_proto",      28,  32),
        ("priority",        32,  32),
        ("ingress_ifindex", 36,  32),
        ("ifindex",         40,  32),
        ("tc_index",        44,  32),
        ("cb_0",            48,  32),
        ("cb_1",            52,  32),
        ("cb_2",            56,  32),
        ("cb_3",            60,  32),
        ("cb_4",            64,  32),
        ("hash",            68,  32),
        ("tc_classid",      72,  32),
        ("data",            76,  32),
        ("data_end",        80,  32),
        ("napi_id",         84,  32),
        ("family",          88,  32),
        ("remote_ip4",      92,  32),
        ("local_ip4",       96,  32),
        ("remote_ip6_0",   100,  32),
        ("remote_ip6_1",   104,  32),
        ("remote_ip6_2",   108,  32),
        ("remote_ip6_3",   112,  32),
        ("local_ip6_0",    116,  32),
        ("local_ip6_1",    120,  32),
        ("local_ip6_2",    124,  32),
    ],
}

for _alias in ("kretprobe", "uprobe", "uretprobe", "usdt"):
    CTX_FIELD_LAYOUTS[_alias] = CTX_FIELD_LAYOUTS["kprobe"]
for _alias in ("raw_tp", "raw_tracepoint", "tp_btf"):
    CTX_FIELD_LAYOUTS[_alias] = CTX_FIELD_LAYOUTS["tracepoint"]
CTX_FIELD_LAYOUTS["lwt"] = CTX_FIELD_LAYOUTS["socket"]
CTX_FIELD_LAYOUTS["filter"] = CTX_FIELD_LAYOUTS["socket"]

PACKET_ACCESS_PROGRAM_TYPES = {
    "xdp":    ("data", "data_end", "data_meta"),
    "socket": ("data", "data_end", None),
    "filter": ("data", "data_end", None),
    "lwt":    ("data", "data_end", None),
}

def build_ctx_shared_vars(program_type, ctx_size, pkt_size=None):
    """Build per-field symbolic variables for the BPF context.

    Returns (shared_vars_dict, constraints_list) where shared_vars_dict contains
    individual claripy BVS per named field plus metadata, and constraints_list
    contains any structural constraints (e.g., XDP data <= data_end).
    """
    fields_layout = CTX_FIELD_LAYOUTS.get(program_type)

    shared_vars = {'ctx_size': ctx_size, 'ctx_fields': {}}
    constraints = []

    if fields_layout is None:

        bvs = claripy.BVS('input_bpf_ctx', ctx_size * 8)
        shared_vars['bpf_ctx'] = bvs
        shared_vars['ctx_fields']['bpf_ctx'] = (0, ctx_size * 8, bvs)
        return shared_vars, constraints

    pkt_info = PACKET_ACCESS_PROGRAM_TYPES.get(program_type)
    actual_pkt_size = pkt_size if pkt_size is not None else DEFAULT_PKT_SIZE

    field_bvs_list = []
    covered_end = 0

    for field_name, byte_offset, bit_width in fields_layout:
        if pkt_info and field_name == pkt_info[0]:
            bvs = claripy.BVV(PKT_BUF_ADDR, bit_width)
        elif pkt_info and field_name == pkt_info[1]:
            bvs = claripy.BVV(PKT_BUF_ADDR + actual_pkt_size, bit_width)
        elif pkt_info and pkt_info[2] and field_name == pkt_info[2]:
            bvs = claripy.BVV(PKT_BUF_ADDR, bit_width)
        else:
            bvs = claripy.BVS(f'input_ctx_{field_name}', bit_width)
        field_bvs_list.append((byte_offset, bit_width, bvs))
        shared_vars['ctx_fields'][field_name] = (byte_offset, bit_width, bvs)
        field_end = byte_offset + bit_width // 8
        if field_end > covered_end:
            covered_end = field_end

    total_bits = ctx_size * 8
    remaining_bytes = ctx_size - covered_end
    if remaining_bytes > 0:
        remaining_bvs = claripy.BVS(
            f'input_ctx_remaining_{covered_end}',
            remaining_bytes * 8,
        )
        field_bvs_list.append((covered_end, remaining_bytes * 8, remaining_bvs))
        shared_vars['ctx_fields'][f'remaining_{covered_end}'] = (
            covered_end, remaining_bytes * 8, remaining_bvs,
        )

    if pkt_info:
        pkt_bytes = []
        for i in range(actual_pkt_size):
            pkt_bytes.append(claripy.BVS(f'input_pkt_byte_{i}', 8))
        shared_vars['pkt_bytes'] = pkt_bytes
        shared_vars['pkt_buf_addr'] = PKT_BUF_ADDR
        shared_vars['pkt_size'] = actual_pkt_size

    shared_vars['ctx_field_list'] = field_bvs_list

    sorted_fields = sorted(field_bvs_list, key=lambda f: f[0])

    concat = sorted_fields[0][2]
    for _, _, bvs in sorted_fields[1:]:
        concat = claripy.Concat(concat, bvs)
    shared_vars['bpf_ctx'] = concat

    if program_type == "xdp":
        data_bvs = shared_vars['ctx_fields'].get('data')
        data_end_bvs = shared_vars['ctx_fields'].get('data_end')
        data_meta_bvs = shared_vars['ctx_fields'].get('data_meta')
        if data_bvs and data_end_bvs and data_bvs[2].symbolic:
            constraints.append(claripy.ULE(data_bvs[2], data_end_bvs[2]))
        if data_meta_bvs and data_bvs and data_meta_bvs[2].symbolic:
            constraints.append(claripy.ULE(data_meta_bvs[2], data_bvs[2]))

    return shared_vars, constraints

def get_program_type_from_elf(filepath):
    """
    Parse the ELF file to determine the eBPF program type from section names.
    Returns a canonical program type string (key of PROGRAM_TYPE_CTX_SIZES,
    e.g., 'kprobe', 'tracepoint', 'xdp', 'socket'). Non-canonical SEC("...")
    prefixes ('tp', 'ksyscall', 'kretsyscall', 'tc', 'classifier') are resolved
    via _SECTION_PREFIX_ALIASES so downstream ctx-size / layout / packet-access
    tables all see the canonical key.
    """
    try:
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                name = section.name

                if not name or name.startswith('.'):
                    continue

                name_lower = name.lower()

                alias_key = name_lower.split('/', 1)[0]
                if alias_key in _SECTION_PREFIX_ALIASES:
                    canonical = _SECTION_PREFIX_ALIASES[alias_key]
                    print(f"[*] Detected program type '{canonical}' "
                          f"(aliased from '{alias_key}') from section '{name}'")
                    return canonical

                for prog_type in PROGRAM_TYPE_CTX_SIZES.keys():
                    if prog_type == "default":
                        continue
                    if name_lower.startswith(prog_type):
                        print(f"[*] Detected program type '{prog_type}' from section '{name}'")
                        return prog_type

                if '/' in name:
                    prefix = name.split('/')[0]
                    if prefix in PROGRAM_TYPE_CTX_SIZES:
                        print(f"[*] Detected program type '{prefix}' from section '{name}'")
                        return prefix

    except Exception as e:
        print(f"[!] Warning: Could not parse ELF for program type: {e}")

    print("[*] Using default program type")
    return "default"

def get_ctx_size_for_program(filepath, override_size=None):
    """
    Determine the context size for the eBPF program.

    Args:
        filepath: Path to the eBPF ELF file
        override_size: Optional override for context size (in bytes)

    Returns:
        Context size in bytes
    """
    if override_size is not None:
        print(f"[*] Using overridden context size: {override_size} bytes")
        return override_size

    prog_type = get_program_type_from_elf(filepath)
    ctx_size = PROGRAM_TYPE_CTX_SIZES.get(prog_type, PROGRAM_TYPE_CTX_SIZES["default"])
    print(f"[*] Using context size {ctx_size} bytes for program type '{prog_type}'")
    return ctx_size

def patch_map_indices(project, filepath, map_symbol_names):
    """
    Patches the BPF bytecode in angr's memory.
    It replaces the placeholder map IDs (usually 0) with the specific
    Map Index (0, 1, 2...) that EbpfMapManager expects.
    """
    print(f"[*] Patching map relocations for: {map_symbol_names}")

    map_indices = {name: i for i, name in enumerate(map_symbol_names)}

    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        if not symtab:
            print("[!] No symbol table found, cannot patch maps.")
            return

        for section in elf.iter_sections():

            if section['sh_type'] not in ['SHT_REL', 'SHT_RELA']:
                continue

            target_section_idx = section['sh_info']
            target_section = elf.get_section(target_section_idx)
            target_name = target_section.name

            angr_section = None
            for sec in project.loader.main_object.sections:
                if sec.name == target_name:
                    angr_section = sec
                    break

            if not angr_section:
                print(f"[!] Warning: Target section '{target_name}' not found in angr loader.")
                continue

            section_base_addr = angr_section.vaddr

            for reloc in section.iter_relocations():
                symbol_idx = reloc['r_info_sym']
                symbol = symtab.get_symbol(symbol_idx)
                sym_name = symbol.name

                if sym_name in map_indices:
                    map_idx = map_indices[sym_name]

                    patch_addr = section_base_addr + reloc['r_offset']

                    try:

                        opcode_bytes = project.loader.memory.load(patch_addr, 1)
                        opcode = opcode_bytes[0]

                        if opcode == 0x18:
                            print(
                                f"    - Patching '{sym_name}' (Index {map_idx}) at "
                                f"{hex(patch_addr)} (LD_IMM64)"
                            )

                            target_addr = patch_addr + 4

                            idx_bytes = map_idx.to_bytes(4, 'little')
                            project.loader.memory.store(target_addr, idx_bytes)

                        else:

                            print(
                                f"    - SKIPPING relocation at {hex(patch_addr)}: "
                                f"Opcode is {hex(opcode)}, not LD_IMM64."
                            )

                    except Exception as e:
                        print(
                            f"    - Warning: Could not verify/patch at {hex(patch_addr)}: {e}"
                        )

    print("[*] Map patching complete.")

SHT_REL = "SHT_REL"
SHT_RELA = "SHT_RELA"
SHF_EXECINSTR = 0x4

R_BPF_64_64 = 1
R_BPF_64_32 = 10

_kfunc_hooks = {}
_kfunc_next_id = None

def reset_kfunc_hooks():
    """Reset kfunc hook tracking. Call between independent program pairs."""
    global _kfunc_hooks, _kfunc_next_id
    _kfunc_hooks = {}
    _kfunc_next_id = None

_kfunc_next_id = None
KFUNC_HELPER_ID_BASE = 10000

def _handle_kfunc_reloc(project, sym_name, patch_addr):
    """
    Handle a kfunc relocation (R_BPF_64_32 targeting an undefined symbol).

    Registers the kfunc as a helper call (src_reg=0) with a unique high helper
    ID (starting from 10000). The kfunc SimProcedure is registered in the
    syscall library so angr dispatches it via the normal helper call path.
    """
    from angr_ebpf.simos_ebpf import BpfKfuncStub
    global _kfunc_next_id

    if _kfunc_next_id is None:
        _kfunc_next_id = KFUNC_HELPER_ID_BASE

    if sym_name in _kfunc_hooks:
        helper_id = _kfunc_hooks[sym_name]
    else:
        helper_id = _kfunc_next_id
        _kfunc_hooks[sym_name] = helper_id
        _kfunc_next_id += 1

    _sym = sym_name

    class _NamedKfuncStub(BpfKfuncStub):
        _kfunc_sym_name = _sym
        def run(self, *args):
            self.state.globals["_current_kfunc_name"] = self._kfunc_sym_name
            return super().run(*args)

    proj_lib = project.simos.syscall_library
    kfunc_key = f"kfunc_{sym_name}"
    proj_lib.add_all_from_dict({kfunc_key: _NamedKfuncStub})
    proj_lib.add_number_mapping("abi", helper_id, kfunc_key)

    P = patch_addr

    print(
        f"    - Hooking kfunc {sym_name} @ {hex(P)}: "
        f"helper_id={helper_id}"
    )

    project.loader.memory.store(
        P + 4, int(helper_id).to_bytes(4, "little", signed=True)
    )

    try:
        reg_byte = project.loader.memory.load(P + 1, 1)[0]
    except KeyError:
        return
    new_reg_byte = reg_byte & 0x0F
    project.loader.memory.store(P + 1, bytes([new_reg_byte]))

def patch_ebpf_relocations(project, filepath, map_symbol_names):
    """
    Patch eBPF relocations directly into angr memory.

    - R_BPF_64_64 (type 1): lddw / map reloc => patch imm32 at insn+4
    - R_BPF_64_32 (type 10): bpf2bpf call reloc => patch imm32 at insn+4 and set src_reg=1

    This implementation:
    - Uses file offsets -> addr mapping (robust under rebasing)
    - Handles empty symbol names and STT_SECTION-like symbols via (section_base + st_value)
    - Treats RELA addend as BYTE addend for calls (common on BPF): rel = (S + A - (P+8))/8
    """

    print("[*] Patching eBPF relocations (REL + RELA)...")
    map_indices = {name: i for i, name in enumerate(map_symbol_names)}

    with open(filepath, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            raise ValueError("No .symtab found (needed to resolve relocation symbols)")

        elfsec_idx_to_info = {}
        for i, sec in enumerate(elf.iter_sections()):
            sec_name = sec.name
            angr_sec = next((s for s in project.loader.main_object.sections if s.name == sec_name), None)
            if angr_sec is None:
                continue
            elfsec_idx_to_info[i] = {
                "name": sec_name,
                "elf_sh_offset": sec["sh_offset"],
                "elf_sh_flags": sec["sh_flags"],
                "angr_base": getattr(angr_sec, "rebased_addr", angr_sec.vaddr),
            }

        for relsec in elf.iter_sections():
            if relsec["sh_type"] not in (SHT_REL, SHT_RELA):
                continue

            target_sec_idx = relsec["sh_info"]
            if target_sec_idx not in elfsec_idx_to_info:
                continue

            tgt = elfsec_idx_to_info[target_sec_idx]

            if (tgt["elf_sh_flags"] & SHF_EXECINSTR) == 0:
                continue

            target_sec = elf.get_section(target_sec_idx)

            for reloc in relsec.iter_relocations():
                r_type = reloc["r_info_type"]
                r_off = reloc["r_offset"]

                file_off = target_sec["sh_offset"] + r_off
                try:
                    patch_addr = project.loader.main_object.offset_to_addr(file_off)
                except Exception:
                    continue
                if patch_addr is None:
                    continue

                sym = symtab.get_symbol(reloc["r_info_sym"])
                st_shndx = sym.entry["st_shndx"]
                st_value = sym.entry["st_value"]
                sym_name = sym.name

                addend = reloc.entry.get("r_addend", 0)

                def resolve_S():

                    if sym_name:
                        tgt_sym = project.loader.main_object.get_symbol(sym_name)
                        if tgt_sym is not None:

                            if tgt_sym.is_import:
                                return None
                            return tgt_sym.rebased_addr

                    if isinstance(st_shndx, int) and st_shndx in elfsec_idx_to_info:
                        sec_base = elfsec_idx_to_info[st_shndx]["angr_base"]
                        return sec_base + st_value

                    return None

                if r_type == R_BPF_64_64:

                    try:
                        opcode = project.loader.memory.load(patch_addr, 1)[0]
                    except KeyError:
                        continue

                    if opcode == 0x18:

                        if relsec["sh_type"] == SHT_REL and addend == 0:
                            try:
                                imm_raw = bytes(project.loader.memory.load(patch_addr + 4, 4))
                                implicit_addend = int.from_bytes(imm_raw, "little", signed=True)
                            except Exception:
                                implicit_addend = 0
                        else:
                            implicit_addend = 0

                        if sym_name in map_indices:

                            map_idx = map_indices[sym_name]
                            project.loader.memory.store(
                                patch_addr + 4,
                                int(map_idx).to_bytes(4, "little", signed=False),
                            )
                        elif sym_name or (isinstance(st_shndx, int) and st_shndx in elfsec_idx_to_info):

                            S = resolve_S()
                            if S is not None:
                                full_addr = (S + addend + implicit_addend) & 0xFFFFFFFFFFFFFFFF
                                project.loader.memory.store(
                                    patch_addr + 4,
                                    (full_addr & 0xFFFFFFFF).to_bytes(4, "little"),
                                )
                                project.loader.memory.store(
                                    patch_addr + 12,
                                    ((full_addr >> 32) & 0xFFFFFFFF).to_bytes(4, "little"),
                                )
                    continue

                if r_type == R_BPF_64_32:
                    S = resolve_S()
                    if S is None:

                        SHN_UNDEF = 0
                        if st_shndx == "SHN_UNDEF" or st_shndx == SHN_UNDEF:
                            _handle_kfunc_reloc(
                                project, sym_name, patch_addr
                            )
                        continue

                    P = patch_addr

                    if relsec["sh_type"] == SHT_REL:
                        try:
                            imm_raw = bytes(project.loader.memory.load(P + 4, 4))
                            implicit_imm = int.from_bytes(imm_raw, "little", signed=True)
                            effective_addend = (implicit_imm + 1) * 8
                        except Exception:
                            effective_addend = addend
                    else:
                        effective_addend = addend

                    rel_insn = (int(S) + int(effective_addend) - (int(P) + 8)) // 8

                    print(
                        f"    - Patching call {sym_name or '<anon>'} @ {hex(P)}:"
                        f" S={hex(int(S))} A={effective_addend} imm={rel_insn}"
                    )

                    project.loader.memory.store(
                        P + 4, int(rel_insn).to_bytes(4, "little", signed=True)
                    )

                    try:
                        reg_byte = project.loader.memory.load(P + 1, 1)[0]
                    except KeyError:
                        continue
                    new_reg_byte = (reg_byte & 0x0F) | 0x10
                    project.loader.memory.store(P + 1, bytes([new_reg_byte]))
                    continue

    print("[*] Patching complete.")

_ATOMIC_OP_NAMES = {
    0x00: "add",
    0x40: "or",
    0x50: "and",
    0xa0: "xor",
    0xe0: "xchg",
    0xf0: "cmpxchg",
}

def scan_atomic_instructions(elf_path, entry_symbol):
    """Scan an eBPF ELF for atomic instructions in the section containing entry_symbol.

    Returns a list of AtomicOpRecord for each BPF_ATOMIC instruction found.
    """
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            print("[!] No .symtab found, cannot scan for atomic instructions")
            return []

        target_section_idx = None
        sym_start = 0
        sym_size = 0
        for sym in symtab.iter_symbols():
            if sym.name == entry_symbol:
                target_section_idx = sym['st_shndx']
                sym_start = sym.entry['st_value']
                sym_size = sym.entry['st_size']
                break

        if target_section_idx is None or not isinstance(target_section_idx, int):
            print(f"[!] Entry symbol '{entry_symbol}' not found in .symtab, "
                  f"cannot scan for atomic instructions")
            return []

        section = elf.get_section(target_section_idx)
        section_name = section.name
        data = section.data()

        scan_start = sym_start
        scan_end = (sym_start + sym_size) if sym_size > 0 else len(data)
        print(f"[*] Scanning section '{section_name}' for atomic instructions "
              f"(offset {hex(scan_start)}-{hex(scan_end)})")

        records = []
        offset = scan_start
        while offset + 8 <= min(scan_end, len(data)):
            opcode = data[offset]

            if opcode == 0x18:
                offset += 16
                continue

            if opcode in (0xc3, 0xdb):
                width = 32 if opcode == 0xc3 else 64
                imm_raw = _struct.unpack_from('<i', data, offset + 4)[0]
                imm = imm_raw & 0xFF
                op_code = imm & 0xFE
                is_fetch = bool(imm & 0x01)
                op_name = _ATOMIC_OP_NAMES.get(op_code, f"unknown_0x{op_code:02x}")
                records.append(AtomicOpRecord(
                    offset=offset,
                    width=width,
                    op_name=op_name,
                    is_fetch=is_fetch,
                ))

            offset += 8

        if records:
            print(f"    Found {len(records)} atomic instruction(s)")
            for rec in records:
                print(f"      offset=0x{rec.offset:x} {rec.width}-bit "
                      f"{rec.op_name} fetch={rec.is_fetch}")
        else:
            print("    No atomic instructions found")

        return records

def generate_formula_for_program(
    filepath,
    shared_vars,
    entry_symbol_name,
    map_symbol_names,
    map_type_names,
    lang_tag,
    btf_metadata=None,
    helper_fail_mode="off",
    helper_fail_helpers=None,
    max_steps=50000,
    ringbuf_track_max=512,
):
    print(f"[*] Loading eBPF program: {filepath}")
    project = angr.Project(filepath, auto_load_libs=False)

    try:
        patch_ebpf_relocations(project, filepath, map_symbol_names)
    except Exception as e:
        print(f"[!] Patching failed: {e}")
        traceback.print_exc()
        sys.exit(1)

    atomic_ops = scan_atomic_instructions(filepath, entry_symbol_name)

    data_sym_info = extract_data_symbols(filepath)
    if data_sym_info:
        print(f"[*] Found {len(data_sym_info)} .data global(s): {', '.join(sorted(data_sym_info.keys()))}")

    start_addr = None
    for sym in project.loader.main_object.symbols:
        if sym.name == entry_symbol_name:
            start_addr = sym.rebased_addr
            print(f"[*] Found entry '{sym.name}' at {hex(start_addr)}")
            break
    if start_addr is None:
        func_names = []
        all_named = []
        seen = set()
        for sym in project.loader.main_object.symbols:
            name = (getattr(sym, "name", "") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            all_named.append(name)
            if getattr(sym, "is_function", False):
                func_names.append(name)

        candidates = func_names if func_names else all_named
        close = difflib.get_close_matches(entry_symbol_name, candidates, n=8, cutoff=0.3)
        sample = ", ".join(candidates[:20]) if candidates else "(none)"
        if candidates and len(candidates) > 20:
            sample += ", ..."

        msg = [f"Could not find the entry symbol: {entry_symbol_name!r}"]
        if close:
            msg.append("Closest symbols: " + ", ".join(close))
        msg.append(f"Available candidate symbols ({len(candidates)}): {sample}")
        raise ValueError("\n".join(msg))

    class BpfProgramExit(angr.SimProcedure):
        NO_RET = True
        def run(self):
            print(f"[*] BpfProgramExit: program terminating with R0={self.state.regs.R0}")
            self.exit(self.state.regs.R0)

    project.hook(BPF_EXIT_SENTINEL, BpfProgramExit())

    state = project.factory.blank_state(
        addr=start_addr,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )

    state.memory.store(
        BPF_CALL_STACK_BASE,
        claripy.BVV(BPF_EXIT_SENTINEL, 64),
        endness=state.arch.memory_endness,
    )
    state.regs.call_depth = 1
    print(f"[*] BPF call stack initialized: call_depth={state.solver.eval(state.regs.call_depth)}, "
          f"sentinel={hex(BPF_EXIT_SENTINEL)} at {hex(BPF_CALL_STACK_BASE)}")

    data_sym_initial = {}
    for sym_name, (sym_size, is_bss) in data_sym_info.items():
        sym_obj = project.loader.main_object.get_symbol(sym_name)
        if sym_obj is None:
            continue
        sym_addr = sym_obj.rebased_addr
        if sym_size <= _DATA_SYMBOLIZE_LIMIT:

            init_bvs = claripy.BVS(f'glob_{sym_name}_init', sym_size * 8)
            if is_bss:
                concrete_init = claripy.BVV(0, sym_size * 8)
            else:

                concrete_init = state.memory.load(
                    sym_addr, sym_size, endness=state.arch.memory_endness)

            state.memory.store(sym_addr, concrete_init, endness=state.arch.memory_endness)
            state.add_constraints(init_bvs == concrete_init)
            data_sym_initial[sym_name] = (sym_addr, init_bvs, sym_size)
        else:
            data_sym_initial[sym_name] = (sym_addr, None, sym_size)

    state.globals['shared_vars'] = shared_vars
    helper_fail_mode = (helper_fail_mode or "off").strip().lower()
    helper_fail_helpers = set(helper_fail_helpers or [])
    state.globals["helper_fail_cfg"] = {
        "mode": helper_fail_mode,
        "helpers": helper_fail_helpers,
    }
    print(
        f"[*] Helper failure modeling: mode={helper_fail_mode}, "
        f"helpers={sorted(helper_fail_helpers) if helper_fail_helpers else []}"
    )
    state.globals["ringbuf_track_max"] = ringbuf_track_max
    if ringbuf_track_max != 512:
        print(f"[*] Ringbuf tracking max: {ringbuf_track_max} bytes"
              f"{' (disabled)' if ringbuf_track_max == 0 else ''}")

    map_manager = state.ebpf_map

    all_symbols = {sym.name: sym for sym in project.loader.main_object.symbols}

    map_metadata_collected = {}
    for map_name, map_type_cli in zip(map_symbol_names, map_type_names):
        if map_name in all_symbols:
            sym = all_symbols[map_name]
            map_addr = sym.rebased_addr

            if btf_metadata and map_name in btf_metadata:
                meta = btf_metadata[map_name]
                key_size = meta.key_size
                value_size = meta.value_size
                max_entries = meta.max_entries

                map_type = meta.map_type_name if meta.map_type_name != "unknown" else map_type_cli
                print(
                    f"[*] Initializing map '{map_name}' from BTF: "
                    f"type={map_type}, key_size={key_size}, value_size={value_size}, "
                    f"max_entries={max_entries} at {hex(map_addr)}"
                )
            else:

                key_size = 8
                value_size = 8
                max_entries = 1024
                map_type = map_type_cli
                print(
                    f"[*] Initializing map '{map_name}' with defaults: "
                    f"type={map_type} at {hex(map_addr)}"
                )

            effective_map_type = map_type
            if map_type in ("percpu_hash", "lru_hash", "lru_percpu_hash"):
                effective_map_type = "hash"
            elif map_type in ("percpu_array", "cgroup_array", "xskmap"):
                effective_map_type = "array"
            elif map_type in ("perf_event_array", "ringbuf"):

                effective_map_type = "array"
            elif map_type == "stack_trace":

                effective_map_type = "hash"
            elif map_type in ("array_of_maps", "hash_of_maps"):
                effective_map_type = map_type
            elif map_type == "prog_array":
                effective_map_type = "array"
            elif map_type == "lpm_trie":
                effective_map_type = "hash"
            elif map_type not in ("hash", "array"):
                print(f"[!] Warning: Unsupported map type '{map_type}', defaulting to 'hash'")
                effective_map_type = "hash"

            inner_kwargs = {}
            if map_type in ("array_of_maps", "hash_of_maps") and btf_metadata and map_name in btf_metadata:
                meta = btf_metadata[map_name]
                if meta.inner_map_type:
                    inner_kwargs = dict(
                        inner_map_type=meta.inner_map_type,
                        inner_key_size=meta.inner_key_size,
                        inner_value_size=meta.inner_value_size,
                        inner_max_entries=meta.inner_max_entries,
                    )
                    print(
                        f"[*]   Inner map template: type={meta.inner_map_type}, "
                        f"key_size={meta.inner_key_size}, value_size={meta.inner_value_size}, "
                        f"max_entries={meta.inner_max_entries}"
                    )

            map_manager.create_map(
                map_addr,
                key_size=key_size,
                value_size=value_size,
                max_entries=max_entries,
                map_type=map_type,
                map_name=map_name,
                **inner_kwargs,
            )

            if map_type not in ("perf_event_array", "ringbuf", "array_of_maps", "hash_of_maps", "prog_array"):
                map_metadata_collected[map_name] = {
                    'key_size': key_size,
                    'value_size': value_size,
                    'type': effective_map_type,
                }

            if map_type in ("array_of_maps", "hash_of_maps") and inner_kwargs:
                inner_type = inner_kwargs.get("inner_map_type", "hash")
                if inner_type not in ("perf_event_array", "ringbuf"):
                    inner_name = f"{map_name}__inner"

                    if inner_type in ("lru_hash", "percpu_hash", "lru_percpu_hash"):
                        inner_eff_type = "hash"
                    elif inner_type in ("percpu_array",):
                        inner_eff_type = "array"
                    else:
                        inner_eff_type = inner_type if inner_type in ("hash", "array") else "hash"
                    map_metadata_collected[inner_name] = {
                        'key_size': inner_kwargs.get("inner_key_size", 8),
                        'value_size': inner_kwargs.get("inner_value_size", 8),
                        'type': inner_eff_type,
                    }
        else:
            print(f"[!] Warning: map symbol '{map_name}' not found in binary.")

    ctx_size = shared_vars.get('ctx_size', 128)
    print(f"[*] Storing symbolic context ({ctx_size} bytes) at {hex(CTX_ADDR)}")

    ctx_field_list = shared_vars.get('ctx_field_list')
    if ctx_field_list:
        for byte_offset, bit_width, bvs in ctx_field_list:
            state.memory.store(
                CTX_ADDR + byte_offset,
                bvs,
                endness=state.arch.memory_endness,
            )

        ctx_constraints = shared_vars.get('ctx_constraints', [])
        for c in ctx_constraints:
            state.add_constraints(c)
    else:
        state.memory.store(
            CTX_ADDR,
            shared_vars['bpf_ctx'],
            endness=state.arch.memory_endness,
        )

    state.regs.R1 = CTX_ADDR

    pkt_bytes = shared_vars.get('pkt_bytes')
    if pkt_bytes:
        pkt_buf_addr = shared_vars['pkt_buf_addr']
        pkt_size = shared_vars['pkt_size']
        print(f"[*] Storing symbolic packet buffer ({pkt_size} bytes) at {hex(pkt_buf_addr)}")
        pkt_bv = claripy.Concat(*pkt_bytes)
        state.memory.store(pkt_buf_addr, pkt_bv)

    state.regs.R2 = 0
    state.regs.R3 = 0
    state.regs.R4 = 0
    state.regs.R5 = 0

    simgr = project.factory.simulation_manager(state)
    print("[*] Starting symbolic execution...")

    print(f"[*] Max exploration steps: {max_steps}")
    simgr.explore(n=max_steps)
    print(
        f"[*] Exploration complete. deadended={len(simgr.deadended)} "
        f"errored={len(simgr.errored)}"
    )

    for stash_name, stash in simgr.stashes.items():
        if stash:
            print(f"    stash '{stash_name}': {len(stash)} states")
            for s in stash[:3]:
                print(f"      - addr={hex(s.addr)}, call_depth={s.solver.eval(s.regs.call_depth)}")

    if len(simgr.errored) > 0:
        print("[!] Errors encountered during symbolic execution:")
        for errored in simgr.errored:
            print(f" - {errored}")

    if not simgr.deadended:
        print("[!] No deadended states, cannot construct formula.")
        return None, None, None

    for final_state in simgr.deadended:
        for map_info in final_state.ebpf_map._maps_by_index:
            name = map_info["name"]
            if name not in map_metadata_collected and not map_info.get("is_output_sink", False):
                map_metadata_collected[name] = {
                    'key_size': map_info["key_size"],
                    'value_size': map_info["value_size"],
                    'type': map_info["type"],
                }
                print(f"[*] Auto-discovered synthetic map '{name}' "
                      f"(type={map_info['type']}, value_size={map_info['value_size']})")

    output_var_name = f"output_r0_{lang_tag}"
    output_bits = state.arch.bits
    output_bvs = claripy.BVS(output_var_name, output_bits)

    program_data = ProgramFormula(
        output_var=output_bvs,
        map_metadata=map_metadata_collected,
        atomic_ops=atomic_ops,
        data_symbols={name: size * 8 for name, (size, _is_bss) in data_sym_info.items()},
    )
    program_formula = None

    for i, final_state in enumerate(simgr.deadended):

        path_constraints = final_state.solver.constraints
        if len(path_constraints) == 0:
            path_pred = claripy.BoolV(True)
        else:
            path_pred = claripy.And(*path_constraints)

        output_relation = (output_bvs == final_state.regs.R0)

        map_state_eqs = []
        path_map_snapshots = {}

        final_map_manager = final_state.ebpf_map
        for map_info in final_map_manager._maps_by_index:
            map_name = map_info["name"]
            key_size = map_info["key_size"]
            value_size = map_info["value_size"]
            entries = map_info["entries"]

            entry_snapshots = []

            for entry in entries:

                if entry is None:
                    continue

                addr = entry["addr"]
                value_sym = entry["value_sym"]
                exists_cond = entry.get("exists_cond", claripy.BVV(1, 1))

                key_sym_expr = entry.get("key")

                if key_sym_expr is None:
                    continue

                mem_val = final_state.memory.load(
                    addr,
                    value_size,
                    endness=final_state.arch.memory_endness,
                )

                entry_snapshots.append(MapEntrySnapshot(
                    key_expr=key_sym_expr,
                    final_value_expr=mem_val,
                    exists_cond=exists_cond,
                    written=entry.get("written", True),
                    write_seq=entry.get("write_seq", -1),
                ))

                final_sym_name = f"final_{value_sym.args[0]}"
                final_sym = claripy.BVS(final_sym_name, value_size * 8)
                map_state_eqs.append(final_sym == mem_val)

                base_name = value_sym.args[0]
                final_key_name = f"key_for_{base_name}"
                key_bits = key_sym_expr.size() if hasattr(key_sym_expr, 'size') else key_size * 8
                final_key_sym = claripy.BVS(final_key_name, key_bits)
                map_state_eqs.append(final_key_sym == key_sym_expr)

            if entry_snapshots:
                path_map_snapshots[map_name] = entry_snapshots

        path_global_writes = {}
        for sym_name, (sym_addr, init_bvs, sym_size) in data_sym_initial.items():
            if init_bvs is not None:
                final_val = final_state.memory.load(
                    sym_addr, sym_size, endness=final_state.arch.memory_endness
                )
                path_global_writes[sym_name] = final_val

        path_outcome_struct = PathOutcome(
            path_predicate=path_pred,
            output_r0_expr=final_state.regs.R0,
            map_snapshots=path_map_snapshots,
            global_writes=path_global_writes,
        )
        program_data.paths.append(path_outcome_struct)

        if map_state_eqs:
            map_state_conj = claripy.And(*map_state_eqs)
            path_outcome = claripy.And(path_pred, output_relation, map_state_conj)
        else:
            path_outcome = claripy.And(path_pred, output_relation)

        total_entries = 0
        for m in final_map_manager._maps_by_index:
            total_entries += sum(1 for e in m["entries"] if e is not None)

        print(
            f"[*] Path {i+1}: constraints={len(path_constraints)}, "
            f"map_entries={total_entries}"
        )

        if program_formula is None:
            program_formula = path_outcome
        else:
            program_formula = claripy.Or(program_formula, path_outcome)

    return program_formula, output_var_name, program_data

def main(argv):

    pkt_size_cli = None
    max_steps_cli = 50000
    remaining_argv = []
    i = 1
    while i < len(argv):
        if argv[i] == "--pkt-size" and i + 1 < len(argv):
            pkt_size_cli = int(argv[i + 1])
            i += 2
        elif argv[i] == "--max-steps" and i + 1 < len(argv):
            max_steps_cli = int(argv[i + 1])
            i += 2
        else:
            remaining_argv.append(argv[i])
            i += 1

    filepath = remaining_argv[0]
    outpath = remaining_argv[1]
    entry_sym = remaining_argv[2]
    lang_tag = remaining_argv[3]
    map_specs = remaining_argv[4:]

    map_symbol_names = []
    map_type_names = []

    KNOWN_MAP_TYPES = {
        "hash", "array", "percpu_hash", "percpu_array", "lru_hash",
        "lru_percpu_hash", "stack_trace", "cgroup_array", "perf_event_array",
        "ringbuf", "lpm_trie", "array_of_maps", "hash_of_maps", "prog_array",
        "xskmap", "devmap", "devmap_hash", "sockmap", "sockhash", "cpumap",
    }

    for spec in map_specs:
        if ':' in spec:
            name, mtype = spec.split(':', 1)
            mtype = mtype.strip().lower()
            if mtype not in KNOWN_MAP_TYPES:
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

    ctx_size = get_ctx_size_for_program(filepath)

    btf_metadata = parse_map_metadata_from_btf(filepath)
    if btf_metadata:
        print(f"[*] Parsed BTF metadata for {len(btf_metadata)} maps")
        for name, meta in btf_metadata.items():
            print(f"    - {name}: type={meta.map_type_name}, "
                  f"key_size={meta.key_size}, value_size={meta.value_size}, "
                  f"max_entries={meta.max_entries}")
    else:
        print("[*] No BTF metadata available, using command-line map specs")

    if not map_symbol_names and btf_metadata:
        print("[*] No map specs on command line, using all maps from BTF")
        for name, meta in btf_metadata.items():
            map_symbol_names.append(name)
            map_type_names.append(meta.map_type_name)

    prog_type = get_program_type_from_elf(filepath)
    shared_vars, ctx_constraints = build_ctx_shared_vars(prog_type, ctx_size, pkt_size=pkt_size_cli)
    shared_vars['ctx_constraints'] = ctx_constraints

    formula, output_name, program_data = generate_formula_for_program(
        filepath,
        shared_vars,
        entry_sym,
        map_symbol_names,
        map_type_names,
        lang_tag,
        btf_metadata=btf_metadata,
        max_steps=max_steps_cli,
    )
    if formula is None:
        print("[!] No formula generated.")
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
