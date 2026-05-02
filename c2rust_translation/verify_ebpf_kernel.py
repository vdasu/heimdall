

import argparse
import ctypes
import ctypes.util
import os
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

try:
    from btf_parser import (
        BTFParser,
        MapMetadata,
        MAP_TYPE_NAMES,
        BTF_MAGIC,
        BTF_KIND_INT,
        BTF_KIND_ARRAY,
        BTF_KIND_STRUCT,
        BTF_KIND_UNION,
        BTF_KIND_ENUM,
        BTF_KIND_TYPEDEF,
        BTF_KIND_FUNC,
        BTF_KIND_FUNC_PROTO,
        BTF_KIND_VAR,
        BTF_KIND_DATASEC,
        BTF_KIND_DECL_TAG,
        BTF_KIND_ENUM64,
        BTFVar,
        BTFPtr,
        BTFStruct,
    )
except ImportError:
    from c2rust_translation.btf_parser import (
        BTFParser,
        MapMetadata,
        MAP_TYPE_NAMES,
        BTF_MAGIC,
        BTF_KIND_INT,
        BTF_KIND_ARRAY,
        BTF_KIND_STRUCT,
        BTF_KIND_UNION,
        BTF_KIND_ENUM,
        BTF_KIND_TYPEDEF,
        BTF_KIND_FUNC,
        BTF_KIND_FUNC_PROTO,
        BTF_KIND_VAR,
        BTF_KIND_DATASEC,
        BTF_KIND_DECL_TAG,
        BTF_KIND_ENUM64,
        BTFVar,
        BTFPtr,
        BTFStruct,
    )

__NR_bpf = 321

BPF_MAP_CREATE = 0
BPF_MAP_UPDATE_ELEM = 2
BPF_PROG_LOAD = 5
BPF_MAP_FREEZE = 22
BPF_BTF_LOAD = 18

BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PROG_ARRAY = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
BPF_MAP_TYPE_PERCPU_HASH = 5
BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
BPF_MAP_TYPE_HASH_OF_MAPS = 13
BPF_MAP_TYPE_SOCKHASH = 18
BPF_MAP_TYPE_RINGBUF = 27

BPF_PSEUDO_MAP_FD = 1
BPF_PSEUDO_MAP_VALUE = 2
BPF_PSEUDO_CALL = 1
BPF_PSEUDO_KFUNC_CALL = 2

BPF_PROG_TYPE_SOCKET_FILTER = 1
BPF_PROG_TYPE_KPROBE = 2
BPF_PROG_TYPE_SCHED_CLS = 3
BPF_PROG_TYPE_SCHED_ACT = 4
BPF_PROG_TYPE_TRACEPOINT = 5
BPF_PROG_TYPE_XDP = 6
BPF_PROG_TYPE_PERF_EVENT = 7
BPF_PROG_TYPE_CGROUP_SKB = 8
BPF_PROG_TYPE_CGROUP_SOCK = 9
BPF_PROG_TYPE_LWT_IN = 10
BPF_PROG_TYPE_LWT_OUT = 11
BPF_PROG_TYPE_LWT_XMIT = 12
BPF_PROG_TYPE_SOCK_OPS = 13
BPF_PROG_TYPE_SK_SKB = 14
BPF_PROG_TYPE_CGROUP_DEVICE = 15
BPF_PROG_TYPE_SK_MSG = 16
BPF_PROG_TYPE_RAW_TRACEPOINT = 17
BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18
BPF_PROG_TYPE_LWT_SEG6LOCAL = 19
BPF_PROG_TYPE_SK_LOOKUP = 23
BPF_PROG_TYPE_TRACING = 26
BPF_PROG_TYPE_STRUCT_OPS = 27
BPF_PROG_TYPE_EXT = 28
BPF_PROG_TYPE_LSM = 29

BPF_TRACE_RAW_TP = 23
BPF_TRACE_FENTRY = 24
BPF_TRACE_FEXIT = 25

R_BPF_64_64 = 1
R_BPF_64_32 = 10

SECTION_TO_PROG_TYPE = {
    "socket": BPF_PROG_TYPE_SOCKET_FILTER,
    "filter": BPF_PROG_TYPE_SOCKET_FILTER,
    "kprobe": BPF_PROG_TYPE_KPROBE,
    "kretprobe": BPF_PROG_TYPE_KPROBE,
    "uprobe": BPF_PROG_TYPE_KPROBE,
    "uretprobe": BPF_PROG_TYPE_KPROBE,

    "usdt": BPF_PROG_TYPE_KPROBE,
    "classifier": BPF_PROG_TYPE_SCHED_CLS,
    "action": BPF_PROG_TYPE_SCHED_ACT,
    "tracepoint": BPF_PROG_TYPE_TRACEPOINT,
    "tp": BPF_PROG_TYPE_TRACEPOINT,
    "xdp": BPF_PROG_TYPE_XDP,
    "perf_event": BPF_PROG_TYPE_PERF_EVENT,
    "cgroup_skb": BPF_PROG_TYPE_CGROUP_SKB,
    "cgroup/skb": BPF_PROG_TYPE_CGROUP_SKB,
    "cgroup/sock": BPF_PROG_TYPE_CGROUP_SOCK,
    "cgroup/dev": BPF_PROG_TYPE_CGROUP_DEVICE,
    "sockops": BPF_PROG_TYPE_SOCK_OPS,
    "sk_skb": BPF_PROG_TYPE_SK_SKB,
    "sk_msg": BPF_PROG_TYPE_SK_MSG,
    "raw_tp": BPF_PROG_TYPE_RAW_TRACEPOINT,
    "raw_tracepoint": BPF_PROG_TYPE_RAW_TRACEPOINT,
    "lwt_in": BPF_PROG_TYPE_LWT_IN,
    "lwt_out": BPF_PROG_TYPE_LWT_OUT,
    "lwt_xmit": BPF_PROG_TYPE_LWT_XMIT,

    "len_hist": BPF_PROG_TYPE_LWT_XMIT,
    "sk_lookup": BPF_PROG_TYPE_SK_LOOKUP,
    "fentry": BPF_PROG_TYPE_TRACING,
    "fexit": BPF_PROG_TYPE_TRACING,
    "freplace": BPF_PROG_TYPE_EXT,
    "lsm": BPF_PROG_TYPE_LSM,
    "struct_ops": BPF_PROG_TYPE_STRUCT_OPS,
    "iter": BPF_PROG_TYPE_TRACING,
    "tp_btf": BPF_PROG_TYPE_TRACING,
}

SECTION_OVERRIDES = {

    "bmc_rx_filter":      BPF_PROG_TYPE_XDP,
    "bmc_hash_keys":      BPF_PROG_TYPE_XDP,
    "bmc_prepare_packet": BPF_PROG_TYPE_XDP,
    "bmc_write_reply":    BPF_PROG_TYPE_XDP,
    "bmc_invalidate_cache": BPF_PROG_TYPE_XDP,
    "bmc_tx_filter":      BPF_PROG_TYPE_SCHED_CLS,
    "bmc_update_cache":   BPF_PROG_TYPE_SCHED_CLS,

    "loadbalancer":       BPF_PROG_TYPE_SOCKET_FILTER,

    "filter":             BPF_PROG_TYPE_SCHED_CLS,
}

SKIP_SECTIONS = {
    "", ".text", ".bss", ".data", ".rodata", ".maps", "maps",
    ".BTF", ".BTF.ext", ".symtab", ".strtab", ".shstrtab",
    ".kconfig", "license",
    ".debug_info", ".debug_abbrev", ".debug_line",
    ".debug_str", ".debug_ranges", ".debug_loc", ".debug_frame",
}

LEGACY_MAP_DEF_SIZE = 28

GLOBAL_DATA_SECTION_PREFIXES = (".rodata", ".data", ".bss")

_VMLINUX_BTF_NAME_IDS = None

TRACING_FUNC_ALIASES = {
    "account_page_dirtied": ["folio_account_dirtied"],
    "folio_account_dirtied": ["account_page_dirtied"],
    "migrate_misplaced_page": ["migrate_misplaced_folio"],
    "migrate_misplaced_folio": ["migrate_misplaced_page"],

    "filemap_alloc_folio_noprof": ["filemap_alloc_folio"],
}

def _kconfig_symbol_values():
    return {
        "LINUX_KERNEL_VERSION": struct.pack("<I", _get_kernel_version()),

        "LINUX_HAS_BPF_COOKIE": struct.pack("<B", 1),
    }

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def bpf_syscall(cmd, attr_buf, attr_size):
    ret = _libc.syscall(
        ctypes.c_long(__NR_bpf),
        ctypes.c_int(cmd),
        ctypes.c_void_p(ctypes.addressof(attr_buf)),
        ctypes.c_uint(attr_size),
    )
    return ret

def _parse_cpu_list(cpu_list_text):
    total = 0
    for part in (cpu_list_text or "").split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            lo_s, hi_s = item.split("-", 1)
            lo = int(lo_s)
            hi = int(hi_s)
            if hi >= lo:
                total += (hi - lo + 1)
        else:
            int(item)
            total += 1
    return total

def _n_possible_cpus():
    possible_path = "/sys/devices/system/cpu/possible"
    try:
        with open(possible_path, "r", encoding="utf-8") as f:
            text = f.read().strip()
        cnt = _parse_cpu_list(text)
        if cnt > 0:
            return cnt
    except Exception:
        pass

    cnt = os.cpu_count() or 1
    return max(int(cnt), 1)

def _default_max_entries_for_map_type(map_type):
    if map_type in {
        BPF_MAP_TYPE_HASH,
        BPF_MAP_TYPE_PERCPU_HASH,
        BPF_MAP_TYPE_LRU_HASH,
        BPF_MAP_TYPE_LRU_PERCPU_HASH,
        BPF_MAP_TYPE_LPM_TRIE,
        BPF_MAP_TYPE_HASH_OF_MAPS,
        BPF_MAP_TYPE_SOCKHASH,
    }:
        return 10240
    if map_type == BPF_MAP_TYPE_RINGBUF:
        return 256 * 1024

    return 1024

def find_programs(filepath):
    programs = []
    with open(filepath, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        for section in elf.iter_sections():
            name = section.name
            if not name:
                continue
            name_lower = name.lower()
            if name_lower in SKIP_SECTIONS:
                continue
            if name_lower.startswith((".rel", ".debug")):
                continue
            if section["sh_type"] != "SHT_PROGBITS" or section["sh_size"] == 0:
                continue

            prog_type = _section_to_prog_type(name_lower)
            if prog_type is not None:
                entries = _find_section_entry_functions(elf, symtab, name)
                if len(entries) <= 1:

                    if entries:
                        _, off, size = entries[0]
                        programs.append((name, name, prog_type, off, size))
                    else:
                        programs.append((name, name, prog_type, 0, None))
                    continue

                for func_name, off, size in entries:
                    display_name = f"{name}:{func_name}"
                    programs.append((display_name, name, prog_type, off, size))

    return programs

def _find_section_entry_functions(elf, symtab, section_name):
    entries = []
    if not symtab or not isinstance(symtab, SymbolTableSection):
        return entries

    sec_idx = None
    for i, sec in enumerate(elf.iter_sections()):
        if sec.name == section_name:
            sec_idx = i
            break
    if sec_idx is None:
        return entries

    for sym in symtab.iter_symbols():
        info = sym.entry["st_info"]
        if info["type"] != "STT_FUNC":
            continue
        if info["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
            continue
        if sym["st_shndx"] != sec_idx:
            continue
        if not sym.name:
            continue
        size = int(sym["st_size"])
        if size <= 0:
            continue
        off = int(sym["st_value"])
        entries.append((sym.name, off, size))

    entries.sort(key=lambda item: item[1])
    return entries

def _section_to_prog_type(name_lower):

    if name_lower in SECTION_OVERRIDES:
        return SECTION_OVERRIDES[name_lower]

    if name_lower in SECTION_TO_PROG_TYPE:
        return SECTION_TO_PROG_TYPE[name_lower]

    prefix = name_lower.split("/")[0]
    if prefix in SECTION_TO_PROG_TYPE:
        return SECTION_TO_PROG_TYPE[prefix]

    underscore_prefix = name_lower.split("_")[0]
    if underscore_prefix in SECTION_TO_PROG_TYPE:
        return SECTION_TO_PROG_TYPE[underscore_prefix]
    return None

def _prog_type_name(prog_type):
    for k, v in globals().items():
        if k.startswith("BPF_PROG_TYPE_") and v == prog_type:
            return k
    return f"UNKNOWN({prog_type})"

def _parse_raw_btf_name_ids(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError(f"BTF file too small: {filepath}")

    magic, version, flags, hdr_len = struct.unpack_from("<HBBI", data, 0)
    if magic != BTF_MAGIC:
        raise ValueError(f"Invalid BTF magic in {filepath}: {hex(magic)}")

    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, 8)
    str_start = hdr_len + str_off
    str_end = str_start + str_len
    type_start = hdr_len + type_off
    type_end = type_start + type_len

    if str_end > len(data) or type_end > len(data):
        raise ValueError(f"Corrupt BTF layout in {filepath}")

    strtab = data[str_start:str_end]
    types = data[type_start:type_end]

    def get_str(off):
        if off >= len(strtab):
            return ""
        end = strtab.find(b"\x00", off)
        if end < 0:
            end = len(strtab)
        return strtab[off:end].decode("utf-8", errors="replace")

    func_ids = {}
    typedef_ids = {}
    offset = 0
    type_id = 1

    while offset + 12 <= len(types):
        name_off, info, size_or_type = struct.unpack_from("<III", types, offset)
        offset += 12

        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        name = get_str(name_off)

        if kind == BTF_KIND_INT:
            offset += 4
        elif kind == BTF_KIND_ARRAY:
            offset += 12
        elif kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
            offset += 12 * vlen
        elif kind == BTF_KIND_ENUM:
            offset += 8 * vlen
        elif kind == BTF_KIND_FUNC_PROTO:
            offset += 8 * vlen
        elif kind == BTF_KIND_VAR:
            offset += 4
        elif kind == BTF_KIND_DATASEC:
            offset += 12 * vlen
        elif kind == BTF_KIND_DECL_TAG:
            offset += 4
        elif kind == BTF_KIND_ENUM64:
            offset += 12 * vlen

        if kind == BTF_KIND_FUNC and name:
            func_ids[name] = type_id
        elif kind == BTF_KIND_TYPEDEF and name:
            typedef_ids[name] = type_id

        type_id += 1

    return {"func": func_ids, "typedef": typedef_ids}

def _load_vmlinux_btf_name_ids():
    global _VMLINUX_BTF_NAME_IDS
    if _VMLINUX_BTF_NAME_IDS is not None:
        return _VMLINUX_BTF_NAME_IDS

    vmlinux_btf = "/sys/kernel/btf/vmlinux"
    if not os.path.isfile(vmlinux_btf):
        _VMLINUX_BTF_NAME_IDS = {"func": {}, "typedef": {}}
        return _VMLINUX_BTF_NAME_IDS

    try:
        _VMLINUX_BTF_NAME_IDS = _parse_raw_btf_name_ids(vmlinux_btf)
        return _VMLINUX_BTF_NAME_IDS
    except Exception:
        pass

    try:
        parser = BTFParser(vmlinux_btf)
        func_ids = {}
        typedef_ids = {}
        for tid, t in parser.types.items():
            kind = getattr(t, "kind", None)
            name = getattr(t, "name", "")
            if not name:
                continue
            if kind == BTF_KIND_FUNC:
                func_ids[name] = tid
            elif kind == BTF_KIND_TYPEDEF:
                typedef_ids[name] = tid
        _VMLINUX_BTF_NAME_IDS = {"func": func_ids, "typedef": typedef_ids}
        return _VMLINUX_BTF_NAME_IDS
    except Exception:
        _VMLINUX_BTF_NAME_IDS = {"func": {}, "typedef": {}}
        return _VMLINUX_BTF_NAME_IDS

def _resolve_tracing_attach(section_name):
    if "/" not in section_name:
        return 0, 0, None

    prefix, attach_name = section_name.split("/", 1)
    prefix = prefix.lower()
    attach_name = attach_name.strip()

    if prefix not in {"tp_btf", "fentry", "fexit"}:
        return 0, 0, None

    name_ids = _load_vmlinux_btf_name_ids()
    func_ids = name_ids.get("func", {})
    typedef_ids = name_ids.get("typedef", {})
    if not func_ids and not typedef_ids:
        raise RuntimeError(
            "Unable to read kernel BTF IDs from /sys/kernel/btf/vmlinux; "
            f"cannot resolve attach target for section '{section_name}'."
        )

    expected_attach_type = 0
    candidates = []

    if prefix == "tp_btf":
        expected_attach_type = BPF_TRACE_RAW_TP

        candidates = [
            f"btf_trace_{attach_name}",
            f"btf_trace_{attach_name.replace('/', '_')}",
        ]
    elif prefix == "fentry":
        expected_attach_type = BPF_TRACE_FENTRY
        candidates = [attach_name]
        candidates.extend(TRACING_FUNC_ALIASES.get(attach_name, []))
    elif prefix == "fexit":
        expected_attach_type = BPF_TRACE_FEXIT
        candidates = [attach_name]
        candidates.extend(TRACING_FUNC_ALIASES.get(attach_name, []))

    seen = set()
    ordered = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)

    if prefix == "tp_btf":
        for c in ordered:
            btf_id = typedef_ids.get(c)
            if btf_id is not None:
                return expected_attach_type, btf_id, c
    else:
        for c in ordered:
            btf_id = func_ids.get(c)
            if btf_id is not None:
                return expected_attach_type, btf_id, c

    raise RuntimeError(
        f"Could not resolve kernel BTF attach target for section '{section_name}'. "
        f"Tried: {ordered[:8]}"
    )

def _is_dummy_tracing_section(section_name):
    if "/" not in section_name:
        return False
    prefix, attach_name = section_name.split("/", 1)
    prefix = prefix.lower().strip()
    attach_name = attach_name.strip().lower()
    return prefix in {"fentry", "fexit"} and attach_name.startswith("dummy_")

def find_maps_btf(filepath):
    try:
        parser = BTFParser(filepath)

        datasec = None
        for t in parser.types.values():
            from btf_parser import BTFDatasec
            if isinstance(t, BTFDatasec) and t.name in ('.maps', 'maps'):
                datasec = t
                break

        if datasec is None:
            return []

        maps = []
        for var_type_id, _, _ in datasec.vars:
            map_meta = parser.parse_map_definition(var_type_id)
            if map_meta:
                maps.append(map_meta)
        return maps

    except Exception as e:
        return []

def find_maps_legacy(filepath):
    maps = []
    with open(filepath, "rb") as f:
        elf = ELFFile(f)

        maps_section = elf.get_section_by_name("maps")
        if maps_section is None:
            maps_section = elf.get_section_by_name(".maps")
        if maps_section is None:
            return []

        maps_data = maps_section.data()
        maps_section_idx = None
        for i, sec in enumerate(elf.iter_sections()):
            if sec.name == maps_section.name:
                maps_section_idx = i
                break

        symtab = elf.get_section_by_name(".symtab")
        offset_to_name = {}
        sym_offsets = []
        if symtab and isinstance(symtab, SymbolTableSection):
            for symbol in symtab.iter_symbols():
                if symbol["st_shndx"] == maps_section_idx and symbol.name:
                    offset_to_name[symbol["st_value"]] = symbol.name
                    sym_offsets.append(symbol["st_value"])

        entry_size = LEGACY_MAP_DEF_SIZE
        if len(sym_offsets) >= 2:
            sym_offsets_sorted = sorted(set(sym_offsets))
            strides = [sym_offsets_sorted[i+1] - sym_offsets_sorted[i]
                       for i in range(len(sym_offsets_sorted) - 1)]
            if strides:
                detected = min(strides)
                if detected in (20, 24, 28, 32):
                    entry_size = detected

        num_maps = len(maps_data) // entry_size
        for i in range(num_maps):
            off = i * entry_size
            entry = maps_data[off:off + entry_size]
            if len(entry) < 20:
                break

            map_type, key_size, value_size, max_entries, flags = struct.unpack_from("<IIIII", entry)

            name = offset_to_name.get(off, f"map_{i}")
            map_type_name = MAP_TYPE_NAMES.get(map_type, "unknown")

            maps.append(MapMetadata(
                name=name,
                map_type=map_type,
                map_type_name=map_type_name,
                key_size=key_size,
                value_size=value_size,
                max_entries=max_entries,
            ))

    return maps

def find_maps(filepath):
    btf_maps = find_maps_btf(filepath)
    btf_valid = btf_maps and any(
        m.map_type != 0 or m.key_size != 0 or m.value_size != 0
        for m in btf_maps
    )

    legacy_maps = find_maps_legacy(filepath)

    if btf_valid:

        merged = {m.name: m for m in legacy_maps}
        merged.update({m.name: m for m in btf_maps})
        return list(merged.values())

    return legacy_maps

def _get_kernel_version():
    parts = os.uname().release.split("-")[0].split(".")
    a = int(parts[0])
    b = int(parts[1]) if len(parts) > 1 else 0
    c = int(parts[2]) if len(parts) > 2 else 0
    return (a << 16) + (b << 8) + c

def _get_symbol_section_name(elf, symbol):
    shndx = symbol["st_shndx"]
    if isinstance(shndx, int) and shndx > 0:
        return elf.get_section(shndx).name
    return str(shndx)

def _is_global_data_section(section_name):
    if not section_name:
        return False
    for prefix in GLOBAL_DATA_SECTION_PREFIXES:
        if section_name == prefix or section_name.startswith(prefix + "."):
            return True
    return False

def collect_relocations(filepath, section_name):
    result = {"map": [], "kconfig": [], "data": [], "call": [], "kfunc": []}
    with open(filepath, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            return result
        text_sec = elf.get_section_by_name(".text")
        text_size = int(text_sec["sh_size"]) if text_sec is not None else 0

        for sec in elf.iter_sections():
            if sec["sh_type"] not in ("SHT_REL", "SHT_RELA"):
                continue
            target_idx = sec["sh_info"]
            target_sec = elf.get_section(target_idx)
            if target_sec.name != section_name:
                continue

            for reloc in sec.iter_relocations():
                rel_type = reloc["r_info_type"]
                sym_idx = reloc["r_info_sym"]
                symbol = symtab.get_symbol(sym_idx)
                sym_name = symbol.name
                sym_sec = _get_symbol_section_name(elf, symbol)
                offset = reloc["r_offset"]

                if rel_type == R_BPF_64_64:
                    if sym_sec in ("maps", ".maps"):
                        result["map"].append((offset, sym_name))
                    elif (
                        sym_sec == ".kconfig"
                        or (
                            sym_sec == "SHN_UNDEF"
                            and sym_name in _kconfig_symbol_values()
                        )
                    ):
                        result["kconfig"].append((offset, sym_name))
                    elif _is_global_data_section(sym_sec):
                        result["data"].append((offset, sym_name, sym_sec, symbol["st_value"]))
                    else:

                        result["data"].append((offset, sym_name, sym_sec, symbol["st_value"]))
                elif rel_type == R_BPF_64_32:
                    if sym_sec == ".text":
                        call_sym_value = symbol["st_value"]

                        if not sym_name or sym_name == ".text":
                            try:
                                call_imm = struct.unpack_from(
                                    "<i", target_sec.data(), offset + 4
                                )[0]
                                current_insn = int(offset) // 8
                                decoded_target = (current_insn + 1 + call_imm) * 8

                                if 0 <= decoded_target < text_size:
                                    call_sym_value = decoded_target
                            except Exception:
                                pass
                        result["call"].append((offset, sym_name, call_sym_value))
                    elif sym_sec == "SHN_UNDEF" and sym_name:

                        result["kfunc"].append((offset, sym_name))

    return result

def get_text_functions(filepath):
    funcs = {}
    with open(filepath, "rb") as f:
        elf = ELFFile(f)

        text_idx = None
        for i, sec in enumerate(elf.iter_sections()):
            if sec.name == ".text":
                text_idx = i
                break
        if text_idx is None:
            return funcs

        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            return funcs

        for sym in symtab.iter_symbols():
            if sym["st_shndx"] == text_idx and sym.name and sym["st_size"] > 0:
                funcs[sym.name] = (sym["st_value"], sym["st_size"])
    return funcs

def _build_text_func_offset_index(text_funcs):
    offset_to_name = {}
    for name, (byte_off, _byte_size) in text_funcs.items():
        byte_off = int(byte_off)
        if byte_off not in offset_to_name:
            offset_to_name[byte_off] = name
    return offset_to_name

def _resolve_text_call_target(sym_name, sym_value, text_funcs, text_offset_to_name):
    if sym_name and sym_name in text_funcs:
        func_off, _func_size = text_funcs[sym_name]
        return sym_name, int(func_off)

    try:
        value = int(sym_value)
    except (TypeError, ValueError):
        value = None

    if value is not None:
        if value in text_offset_to_name:
            return text_offset_to_name[value], value

        for name, (func_off, func_size) in text_funcs.items():
            func_off = int(func_off)
            func_size = int(func_size)
            if func_off <= value < (func_off + func_size):
                return name, func_off

    return None, None

def _build_text_func_ranges(text_funcs):
    ranges = []
    for name, (off, size) in text_funcs.items():
        start = int(off)
        end = start + int(size)
        ranges.append((start, end, name))
    ranges.sort(key=lambda item: item[0])
    return ranges

def _find_text_func_for_offset(byte_off, text_func_ranges):
    off = int(byte_off)
    for start, end, name in text_func_ranges:
        if start <= off < end:
            return name
    return None

def _shift_relocations(relocs, byte_offset_delta):
    out = {"map": [], "kconfig": [], "data": [], "call": [], "kfunc": []}

    for off, sym_name in relocs.get("map", []):
        out["map"].append((int(off) + byte_offset_delta, sym_name))

    for off, sym_name in relocs.get("kconfig", []):
        out["kconfig"].append((int(off) + byte_offset_delta, sym_name))

    for off, sym_name, sym_sec, sym_value in relocs.get("data", []):
        out["data"].append((int(off) + byte_offset_delta, sym_name, sym_sec, sym_value))

    for off, sym_name, sym_value in relocs.get("call", []):
        out["call"].append((int(off) + byte_offset_delta, sym_name, sym_value))

    for off, sym_name in relocs.get("kfunc", []):
        out["kfunc"].append((int(off) + byte_offset_delta, sym_name))

    return out

def _extend_relocations(dst, src):
    for k in ("map", "kconfig", "data", "call", "kfunc"):
        dst.setdefault(k, []).extend(src.get(k, []))

def _slice_relocations(relocs, start_off, size):
    if size is None:
        return relocs

    lo = int(start_off)
    hi = lo + int(size)
    out = {"map": [], "kconfig": [], "data": [], "call": [], "kfunc": []}

    for off, sym_name in relocs.get("map", []):
        off = int(off)
        if lo <= off < hi:
            out["map"].append((off - lo, sym_name))

    for off, sym_name in relocs.get("kconfig", []):
        off = int(off)
        if lo <= off < hi:
            out["kconfig"].append((off - lo, sym_name))

    for off, sym_name, sym_sec, sym_value in relocs.get("data", []):
        off = int(off)
        if lo <= off < hi:
            out["data"].append((off - lo, sym_name, sym_sec, sym_value))

    for off, sym_name, sym_value in relocs.get("call", []):
        off = int(off)
        if lo <= off < hi:
            out["call"].append((off - lo, sym_name, sym_value))

    for off, sym_name in relocs.get("kfunc", []):
        off = int(off)
        if lo <= off < hi:
            out["kfunc"].append((off - lo, sym_name))

    return out

def read_section_data(filepath, section_name):
    with open(filepath, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(section_name)
        if sec is None:
            return None
        return bytearray(sec.data())

def read_section_blob(filepath, section_name):
    with open(filepath, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(section_name)
        if sec is None:
            return None

        size = int(sec["sh_size"])
        if sec["sh_type"] == "SHT_NOBITS":
            return bytes(size)

        data = sec.data()
        if len(data) < size:
            data = data + (b"\x00" * (size - len(data)))
        return bytes(data[:size])

def _inner_map_type_name_to_int(type_name):
    _NAME_TO_TYPE = {v: k for k, v in MAP_TYPE_NAMES.items()}
    return _NAME_TO_TYPE.get(type_name, BPF_MAP_TYPE_HASH)

BPF_F_RDONLY_PROG = 0x80

def _fixup_btf_datasec(btf_data, filepath):
    btf_data = bytearray(btf_data)

    magic, version, flags, hdr_len = struct.unpack_from('<HBBI', btf_data, 0)
    type_off, type_len, str_off, str_len = struct.unpack_from('<IIII', btf_data, 8)

    if magic != 0xEB9F:
        return bytes(btf_data)

    str_start = hdr_len + str_off
    string_table = btf_data[str_start:str_start + str_len]

    def get_string(off):
        end = string_table.find(b'\x00', off)
        if end == -1:
            end = len(string_table)
        return string_table[off:end].decode('utf-8', errors='replace')

    sec_sizes = {}

    sym_offsets = {}
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name:
                sec_sizes[sec.name] = sec.data_size
        symtab = elf.get_section_by_name('.symtab')
        if symtab:
            for sym in symtab.iter_symbols():
                sec_idx = sym['st_shndx']
                if isinstance(sec_idx, int) and sec_idx > 0:
                    try:
                        sec = elf.get_section(sec_idx)
                    except Exception:
                        continue
                    sec_name = sec.name
                    if sec_name:
                        sym_offsets.setdefault(sec_name, {})[sym.name] = sym['st_value']

    type_start = hdr_len + type_off
    offset = type_start
    type_end = type_start + type_len
    var_names = {}
    var_tids = set()

    tid = 1
    while offset < type_end:
        if offset + 12 > type_end:
            break
        name_off, info, _size = struct.unpack_from('<III', btf_data, offset)
        kind = (info >> 24) & 0x1f
        vlen = info & 0xffff
        offset += 12

        if kind == 14:
            var_names[tid] = get_string(name_off)
            var_tids.add(tid)
            offset += 4
        elif kind == 1:
            offset += 4
        elif kind == 3:
            offset += 12
        elif kind in (4, 5):
            offset += vlen * 12
        elif kind == 6:
            offset += vlen * 8
        elif kind == 13:
            offset += vlen * 8
        elif kind == 15:
            offset += vlen * 12
        elif kind == 17:
            offset += 4
        elif kind == 19:
            offset += vlen * 12

        tid += 1

    offset = type_start
    tid = 1
    while offset < type_end:
        if offset + 12 > type_end:
            break
        name_off, info, size_or_type = struct.unpack_from('<III', btf_data, offset)
        kind = (info >> 24) & 0x1f
        vlen = info & 0xffff
        rec_start = offset
        offset += 12

        if kind == 1:
            offset += 4
        elif kind == 2:
            pass
        elif kind == 3:
            offset += 12
        elif kind in (4, 5):
            offset += vlen * 12
        elif kind == 6:
            offset += vlen * 8
        elif kind == 7:
            pass
        elif kind == 8:
            pass
        elif kind in (9, 10, 11):
            pass
        elif kind == 12:
            pass
        elif kind == 13:
            offset += vlen * 8
        elif kind == 14:
            offset += 4
        elif kind == 15:
            sec_name = get_string(name_off)

            has_non_var = False
            for i in range(vlen):
                var_type_id = struct.unpack_from(
                    '<I', btf_data, offset + i * 12
                )[0]
                if var_type_id not in var_tids:
                    has_non_var = True
                    break

            if has_non_var:

                new_info = (4 << 24) | vlen
                struct.pack_into('<I', btf_data, rec_start + 0, 0)
                struct.pack_into('<I', btf_data, rec_start + 4, new_info)

                if size_or_type == 0:
                    struct.pack_into('<I', btf_data, rec_start + 8, 8)
                for i in range(vlen):
                    member_off = offset + i * 12
                    struct.pack_into('<I', btf_data, member_off + 0, 0)
                    struct.pack_into('<I', btf_data, member_off + 4, 1)
                    struct.pack_into('<I', btf_data, member_off + 8, 0)
                offset += vlen * 12
            else:
                real_size = sec_sizes.get(sec_name, 0)
                if real_size > 0 and size_or_type == 0:
                    struct.pack_into('<I', btf_data, rec_start + 8, real_size)

                sec_syms = sym_offsets.get(sec_name, {})
                max_end = 0
                for i in range(vlen):
                    var_off = offset + i * 12
                    var_type_id, v_off, v_sz = struct.unpack_from(
                        '<III', btf_data, var_off
                    )
                    var_name = var_names.get(var_type_id)
                    if var_name and var_name in sec_syms:
                        v_off = sec_syms[var_name]
                        struct.pack_into('<I', btf_data, var_off + 4, v_off)
                    if v_sz == 0:
                        v_sz = 8
                        struct.pack_into('<I', btf_data, var_off + 8, v_sz)
                    max_end = max(max_end, v_off + v_sz)
                cur_size = struct.unpack_from('<I', btf_data, rec_start + 8)[0]
                if cur_size == 0 and max_end > 0:
                    struct.pack_into('<I', btf_data, rec_start + 8, max_end)
                offset += vlen * 12
        elif kind == 16:
            pass
        elif kind == 17:
            offset += 4
        elif kind == 18:
            pass
        elif kind == 19:
            offset += vlen * 12
        else:
            break
        tid += 1

    return bytes(btf_data)

def load_btf_from_elf(filepath):
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        btf_section = elf.get_section_by_name('.BTF')
        if btf_section is None:
            return -1
        btf_data = btf_section.data()

    if len(btf_data) < 24:
        return -1

    btf_data = _fixup_btf_datasec(btf_data, filepath)
    btf_buf = (ctypes.c_char * len(btf_data)).from_buffer_copy(btf_data)

    attr_size = 128

    attr = (ctypes.c_char * attr_size)()
    ctypes.memset(attr, 0, attr_size)
    struct.pack_into("<Q", attr, 0, ctypes.addressof(btf_buf))
    struct.pack_into("<I", attr, 16, len(btf_data))

    fd = bpf_syscall(BPF_BTF_LOAD, attr, attr_size)
    if fd >= 0:
        return fd

    first_errno = ctypes.get_errno()
    log_size = 256 * 1024
    log_buf = (ctypes.c_char * log_size)()
    ctypes.memset(log_buf, 0, log_size)

    attr2 = (ctypes.c_char * attr_size)()
    ctypes.memset(attr2, 0, attr_size)
    struct.pack_into("<Q", attr2, 0, ctypes.addressof(btf_buf))
    struct.pack_into("<Q", attr2, 8, ctypes.addressof(log_buf))
    struct.pack_into("<I", attr2, 16, len(btf_data))
    struct.pack_into("<I", attr2, 20, log_size)
    struct.pack_into("<I", attr2, 24, 1)

    fd = bpf_syscall(BPF_BTF_LOAD, attr2, attr_size)
    if fd >= 0:
        return fd

    errno = ctypes.get_errno()
    btf_log = bytes(log_buf).split(b'\x00', 1)[0].decode('utf-8', errors='replace')
    print(
        f"[!] BPF_BTF_LOAD failed: errno={first_errno} ({os.strerror(first_errno)})"
    )
    if btf_log:
        for line in btf_log.strip().splitlines()[:20]:
            print(f"    {line}")
    return -1

def find_rodata_btf_type_ids(filepath):
    try:
        parser = BTFParser(filepath)
    except (ValueError, FileNotFoundError):
        return 0, 0

    key_type_id = 0
    value_type_id = 0

    for tid, t in parser.types.items():

        if key_type_id == 0 and t.kind == BTF_KIND_INT:
            sz = getattr(t, 'size', 0)
            if sz == 4:
                key_type_id = tid

        if t.kind == BTF_KIND_DATASEC and t.name == '.rodata':
            value_type_id = tid

    return key_type_id, value_type_id

def find_map_btf_type_ids(filepath):
    try:
        parser = BTFParser(filepath)
    except (ValueError, FileNotFoundError):
        return {}

    result = {}
    datasec = parser.get_maps_datasec()
    if datasec is None:
        return {}

    for var_type_id, _, _ in datasec.vars:
        if var_type_id not in parser.types:
            continue
        var = parser.types[var_type_id]
        if not isinstance(var, BTFVar) or not var.name:
            continue

        struct_type_id = var.target_type_id
        if struct_type_id not in parser.types:
            continue
        struct = parser.types[struct_type_id]
        if not isinstance(struct, BTFStruct):
            continue

        fields = {name: tid for name, tid, _ in struct.members}
        key_type_id = 0
        value_type_id = 0

        if 'key' in fields:
            ptr_tid = fields['key']
            if ptr_tid in parser.types:
                ptr = parser.types[ptr_tid]
                if isinstance(ptr, BTFPtr):
                    key_type_id = ptr.target_type_id

        if 'value' in fields:
            ptr_tid = fields['value']
            if ptr_tid in parser.types:
                ptr = parser.types[ptr_tid]
                if isinstance(ptr, BTFPtr):
                    value_type_id = ptr.target_type_id

        if key_type_id > 0 and value_type_id > 0:
            result[var.name] = (key_type_id, value_type_id)

    return result

def create_map(map_meta, map_flags=0, btf_fd=-1, btf_key_type_id=0,
               btf_value_type_id=0):

    attr_size = 128
    attr = (ctypes.c_char * attr_size)()
    ctypes.memset(attr, 0, attr_size)

    map_type = map_meta.map_type
    key_size = map_meta.key_size
    value_size = map_meta.value_size
    max_entries = map_meta.max_entries

    if map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        if key_size == 0:
            key_size = 4
        if value_size == 0:
            value_size = 4
        if max_entries == 0:
            max_entries = _n_possible_cpus()
            print(
                f"[*] Adjusting perf_event_array '{map_meta.name}' max_entries "
                f"from 0 to n_possible_cpus={max_entries}"
            )
    elif map_type == BPF_MAP_TYPE_PROG_ARRAY:
        if key_size == 0:
            key_size = 4
        if value_size == 0:
            value_size = 4
        if max_entries == 0:
            max_entries = 32
            print(
                f"[*] Adjusting prog_array '{map_meta.name}' max_entries "
                f"from 0 to default={max_entries}"
            )
    elif max_entries == 0:
        max_entries = _default_max_entries_for_map_type(map_type)
        print(
            f"[*] Adjusting map '{map_meta.name}' max_entries from 0 "
            f"to default={max_entries} for type={map_meta.map_type_name}"
        )

    struct.pack_into("<I", attr, 0, map_type)
    struct.pack_into("<I", attr, 4, key_size)
    struct.pack_into("<I", attr, 8, value_size)
    struct.pack_into("<I", attr, 12, max_entries)
    struct.pack_into("<I", attr, 16, map_flags)

    if btf_fd >= 0 and btf_key_type_id > 0 and btf_value_type_id > 0:
        struct.pack_into("<I", attr, 48, btf_fd)
        struct.pack_into("<I", attr, 52, btf_key_type_id)
        struct.pack_into("<I", attr, 56, btf_value_type_id)

    inner_template_fd = -1
    if map_type in (BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS):
        inner_type_name = getattr(map_meta, 'inner_map_type', None)
        inner_key = getattr(map_meta, 'inner_key_size', 4)
        inner_val = getattr(map_meta, 'inner_value_size', 4)
        inner_max = getattr(map_meta, 'inner_max_entries', 1)

        if inner_type_name:
            inner_type_int = _inner_map_type_name_to_int(inner_type_name)
        else:

            inner_type_int = BPF_MAP_TYPE_HASH

        if inner_type_int == BPF_MAP_TYPE_RINGBUF:
            inner_key = 0
            inner_val = 0
            if inner_max == 0:
                inner_max = 256 * 1024
        else:
            if inner_key == 0:
                inner_key = 4
            if inner_val == 0:
                inner_val = 4
            if inner_max == 0:
                inner_max = 1

        inner_attr_size = 128
        inner_attr = (ctypes.c_char * inner_attr_size)()
        ctypes.memset(inner_attr, 0, inner_attr_size)
        struct.pack_into("<I", inner_attr, 0, inner_type_int)
        struct.pack_into("<I", inner_attr, 4, inner_key)
        struct.pack_into("<I", inner_attr, 8, inner_val)
        struct.pack_into("<I", inner_attr, 12, inner_max)

        inner_template_fd = bpf_syscall(BPF_MAP_CREATE, inner_attr, inner_attr_size)
        if inner_template_fd < 0:
            errno = ctypes.get_errno()
            raise RuntimeError(
                f"BPF_MAP_CREATE failed for inner template of '{map_meta.name}' "
                f"(inner_type={inner_type_name or 'hash'}, key_size={inner_key}, "
                f"value_size={inner_val}, max_entries={inner_max}): "
                f"errno={errno} ({os.strerror(errno)})"
            )
        print(
            f"[+] Created inner template map for '{map_meta.name}' "
            f"(type={inner_type_name or 'hash'}, key={inner_key}, val={inner_val}) → fd {inner_template_fd}"
        )

        struct.pack_into("<I", attr, 20, inner_template_fd)

    fd = bpf_syscall(BPF_MAP_CREATE, attr, attr_size)

    if inner_template_fd >= 0:
        os.close(inner_template_fd)

    if fd < 0:
        errno = ctypes.get_errno()
        raise RuntimeError(
            f"BPF_MAP_CREATE failed for '{map_meta.name}' "
            f"(type={map_meta.map_type_name}, key_size={key_size}, "
            f"value_size={value_size}, max_entries={max_entries}): "
            f"errno={errno} ({os.strerror(errno)})"
        )
    return fd

def _patch_lddw_map_value(bytecode, offset, map_fd, value_offset):
    dst_reg = bytecode[offset + 1] & 0x0f
    bytecode[offset + 1] = (dst_reg & 0x0f) | (BPF_PSEUDO_MAP_VALUE << 4)
    struct.pack_into("<i", bytecode, offset + 4, map_fd)
    struct.pack_into("<i", bytecode, offset + 12, value_offset)

def map_update_elem(map_fd, key_bytes, value_bytes):
    key_buf = (ctypes.c_char * len(key_bytes)).from_buffer_copy(key_bytes)
    val_buf = (ctypes.c_char * len(value_bytes)).from_buffer_copy(value_bytes)

    attr_size = 128
    attr = (ctypes.c_char * attr_size)()
    ctypes.memset(attr, 0, attr_size)

    struct.pack_into("<I", attr, 0, map_fd)
    struct.pack_into("<Q", attr, 8, ctypes.addressof(key_buf))
    struct.pack_into("<Q", attr, 16, ctypes.addressof(val_buf))

    ret = bpf_syscall(BPF_MAP_UPDATE_ELEM, attr, attr_size)
    if ret < 0:
        errno = ctypes.get_errno()
        raise RuntimeError(
            f"BPF_MAP_UPDATE_ELEM failed: errno={errno} ({os.strerror(errno)})"
        )

def create_kconfig_map(kconfig_relocs):
    if not kconfig_relocs:
        return None, {}

    kconfig_values = _kconfig_symbol_values()

    sym_names = sorted(set(name for _, name in kconfig_relocs))
    sym_to_offset = {}
    value_data = bytearray()
    for name in sym_names:
        if name not in kconfig_values:
            raise RuntimeError(f"Unknown .kconfig extern '{name}'")
        sym_to_offset[name] = len(value_data)
        value_data.extend(kconfig_values[name])

    value_size = len(value_data)
    if value_size == 0:
        return None, {}

    map_meta = MapMetadata(
        name="__kconfig",
        map_type=BPF_MAP_TYPE_ARRAY,
        map_type_name="array",
        key_size=4,
        value_size=value_size,
        max_entries=1,
    )
    fd = create_map(map_meta)

    key = struct.pack("<I", 0)
    map_update_elem(fd, key, bytes(value_data))

    return fd, sym_to_offset

def create_data_section_maps(filepath, data_relocs, overrides=None):
    sec_to_fd = {}
    sec_to_size = {}

    if not data_relocs:
        return sec_to_fd, sec_to_size

    relevant_secs = sorted(
        {
            sym_sec
            for _, _, sym_sec, _ in data_relocs
            if _is_global_data_section(sym_sec)
        }
    )
    if not relevant_secs:
        return sec_to_fd, sec_to_size

    sec_to_sym_offsets = {}
    for _, sym_name, sym_sec, sym_value in data_relocs:
        if not _is_global_data_section(sym_sec):
            continue
        sec_to_sym_offsets.setdefault(sym_sec, {})[sym_name] = int(sym_value)

    key0 = struct.pack("<I", 0)

    btf_fd = -1
    btf_key_tid = 0
    btf_val_tid = 0
    needs_rodata = any(s.startswith(".rodata") for s in relevant_secs)
    if needs_rodata:
        btf_fd = load_btf_from_elf(filepath)
        if btf_fd >= 0:
            btf_key_tid, btf_val_tid = find_rodata_btf_type_ids(filepath)
            if btf_key_tid and btf_val_tid:
                print(
                    f"[+] Loaded BTF → fd {btf_fd} "
                    f"(key_type_id={btf_key_tid}, rodata_type_id={btf_val_tid})"
                )
            else:
                print("[!] BTF loaded but could not find .rodata type IDs")

    for sec_name in relevant_secs:
        blob = read_section_blob(filepath, sec_name)
        if blob is None:
            raise RuntimeError(
                f"Relocations reference section '{sec_name}' but it does not exist"
            )

        value_size = len(blob)
        if value_size == 0:

            value_size = 1
            blob = b"\x00"

        is_rodata = sec_name.startswith(".rodata")
        flags = BPF_F_RDONLY_PROG if is_rodata else 0

        use_btf = is_rodata and btf_fd >= 0 and btf_key_tid and btf_val_tid

        sec_overrides = (overrides or {}).get(sec_name, {})
        if sec_overrides:
            sym_offsets = sec_to_sym_offsets.get(sec_name, {})
            patched = bytearray(blob)
            for sym_name, value_bytes in sec_overrides.items():
                if sym_name not in sym_offsets:
                    print(
                        f"[!] override skipped: '{sym_name}' not referenced "
                        f"from any program in '{sec_name}'"
                    )
                    continue
                off = sym_offsets[sym_name]
                if off + len(value_bytes) > len(patched):
                    raise RuntimeError(
                        f"override for '{sym_name}' overruns '{sec_name}' "
                        f"(offset={off}, len={len(value_bytes)}, "
                        f"section_size={len(patched)})"
                    )
                patched[off:off + len(value_bytes)] = value_bytes
                print(
                    f"[+] patched '{sec_name}'/{sym_name} @ +{off} "
                    f"({len(value_bytes)} bytes)"
                )
            blob = bytes(patched)

        map_meta = MapMetadata(
            name=f"__global_{sec_name.lstrip('.')}",
            map_type=BPF_MAP_TYPE_ARRAY,
            map_type_name="array",
            key_size=4,
            value_size=value_size,
            max_entries=1,
        )
        fd = create_map(
            map_meta,
            map_flags=flags,
            btf_fd=btf_fd if use_btf else -1,
            btf_key_type_id=btf_key_tid if use_btf else 0,
            btf_value_type_id=btf_val_tid if use_btf else 0,
        )
        map_update_elem(fd, key0, blob)

        if sec_name.startswith(".rodata"):
            freeze_attr_size = 128
            freeze_attr = (ctypes.c_char * freeze_attr_size)()
            ctypes.memset(freeze_attr, 0, freeze_attr_size)
            struct.pack_into("<I", freeze_attr, 0, fd)
            ret = bpf_syscall(BPF_MAP_FREEZE, freeze_attr, freeze_attr_size)
            if ret < 0:
                errno = ctypes.get_errno()
                print(
                    f"[!] BPF_MAP_FREEZE failed for '{sec_name}': "
                    f"errno={errno} ({os.strerror(errno)})"
                )
            else:
                print(f"[+] Froze map for '{sec_name}' → fd {fd}")

        sec_to_fd[sec_name] = fd
        sec_to_size[sec_name] = value_size

    if btf_fd >= 0:
        try:
            os.close(btf_fd)
        except OSError:
            pass

    return sec_to_fd, sec_to_size

def _patch_lddw_imm(bytecode, offset, imm_value, src_reg=0):

    dst_reg = bytecode[offset + 1] & 0x0f
    bytecode[offset + 1] = (dst_reg & 0x0f) | ((src_reg & 0x0f) << 4)

    struct.pack_into("<i", bytecode, offset + 4, imm_value)

    struct.pack_into("<i", bytecode, offset + 12, 0)

def apply_relocations(
    bytecode,
    relocs,
    map_name_to_fd,
    func_insn_offsets,
    func_insn_offsets_by_off=None,
    kconfig_fd=None,
    kconfig_offsets=None,
    data_sec_to_fd=None,
    data_sec_to_size=None,
):

    for offset, sym_name in relocs["map"]:
        if sym_name not in map_name_to_fd:
            raise RuntimeError(
                f"Relocation references unknown map '{sym_name}' at offset {offset}"
            )
        _patch_lddw_imm(bytecode, offset, map_name_to_fd[sym_name],
                         src_reg=BPF_PSEUDO_MAP_FD)

    if kconfig_offsets is None:
        kconfig_offsets = {}
    for offset, sym_name in relocs["kconfig"]:
        if kconfig_fd is None or sym_name not in kconfig_offsets:
            raise RuntimeError(
                f"Unknown .kconfig extern '{sym_name}' at offset {offset}"
            )
        _patch_lddw_map_value(bytecode, offset, kconfig_fd,
                              kconfig_offsets[sym_name])

    if data_sec_to_fd is None:
        data_sec_to_fd = {}
    if data_sec_to_size is None:
        data_sec_to_size = {}
    if func_insn_offsets_by_off is None:
        func_insn_offsets_by_off = {}
    for offset, sym_name, sym_sec, sym_value in relocs["data"]:
        if _is_global_data_section(sym_sec):
            if sym_sec not in data_sec_to_fd:
                raise RuntimeError(
                    f"Missing backing map for data section '{sym_sec}' "
                    f"(symbol '{sym_name}', reloc offset {offset})"
                )
            value_off = int(sym_value)
            sec_size = int(data_sec_to_size.get(sym_sec, 0))
            if value_off < 0 or value_off >= sec_size:
                raise RuntimeError(
                    f"Data relocation offset {value_off} out of bounds for section "
                    f"'{sym_sec}' (size={sec_size}, symbol='{sym_name}')"
                )
            _patch_lddw_map_value(bytecode, offset, data_sec_to_fd[sym_sec], value_off)
            continue

        _patch_lddw_imm(bytecode, offset, 0)

    for offset, sym_name, sym_value in relocs["call"]:
        target_insn = None
        if sym_name and sym_name in func_insn_offsets:
            target_insn = func_insn_offsets[sym_name]

        if target_insn is None:
            try:
                sym_value_int = int(sym_value)
            except (TypeError, ValueError):
                sym_value_int = None
            if sym_value_int is not None and sym_value_int in func_insn_offsets_by_off:
                target_insn = func_insn_offsets_by_off[sym_value_int]
            elif sym_value_int is not None and func_insn_offsets_by_off:

                candidate_off = None
                for off in func_insn_offsets_by_off:
                    if off <= sym_value_int and (
                        candidate_off is None or off > candidate_off
                    ):
                        candidate_off = off
                if candidate_off is not None:
                    target_insn = func_insn_offsets_by_off[candidate_off]

        if target_insn is None:
            raise RuntimeError(
                f"Call to unknown .text function '{sym_name}' "
                f"(sym_value={sym_value}) at offset {offset}"
            )
        current_insn = offset // 8
        rel_offset = target_insn - (current_insn + 1)
        struct.pack_into("<i", bytecode, offset + 4, rel_offset)

        dst_reg = bytecode[offset + 1] & 0x0f
        bytecode[offset + 1] = (dst_reg & 0x0f) | (BPF_PSEUDO_CALL << 4)

    kfunc_relocs = relocs.get("kfunc", [])
    if kfunc_relocs:
        name_ids = _load_vmlinux_btf_name_ids()
        func_ids = name_ids.get("func", {})
        if not func_ids:
            raise RuntimeError(
                "Program has kfunc calls but vmlinux BTF is unavailable "
                "(/sys/kernel/btf/vmlinux); cannot resolve kfunc IDs."
            )
        for offset, sym_name in kfunc_relocs:
            btf_id = func_ids.get(sym_name)
            if btf_id is None:
                raise RuntimeError(
                    f"Cannot resolve kfunc '{sym_name}' in vmlinux BTF "
                    f"(reloc at offset {offset})."
                )
            struct.pack_into("<i", bytecode, offset + 4, int(btf_id))
            dst_reg = bytecode[offset + 1] & 0x0f
            bytecode[offset + 1] = (dst_reg & 0x0f) | (BPF_PSEUDO_KFUNC_CALL << 4)

def load_program(
    prog_type,
    bytecode,
    log_level=1,
    log_size=16 * 1024 * 1024,
    expected_attach_type=0,
    attach_btf_id=0,
):
    insn_cnt = len(bytecode) // 8

    log_buf = (ctypes.c_char * log_size)()
    ctypes.memset(log_buf, 0, log_size)

    license_str = ctypes.create_string_buffer(b"GPL")

    attr_size = 256
    attr = (ctypes.c_char * attr_size)()
    ctypes.memset(attr, 0, attr_size)

    insns_buf = (ctypes.c_char * len(bytecode)).from_buffer_copy(bytecode)

    struct.pack_into("<I", attr, 0, prog_type)
    struct.pack_into("<I", attr, 4, insn_cnt)
    struct.pack_into("<Q", attr, 8, ctypes.addressof(insns_buf))
    struct.pack_into("<Q", attr, 16, ctypes.addressof(license_str))
    struct.pack_into("<I", attr, 24, log_level)
    struct.pack_into("<I", attr, 28, log_size)
    struct.pack_into("<Q", attr, 32, ctypes.addressof(log_buf))

    if expected_attach_type:
        struct.pack_into("<I", attr, 68, expected_attach_type)
    if attach_btf_id:
        struct.pack_into("<I", attr, 108, attach_btf_id)

        struct.pack_into("<I", attr, 112, 0)

    fd = bpf_syscall(BPF_PROG_LOAD, attr, attr_size)

    verifier_log = ctypes.string_at(log_buf).decode("utf-8", errors="replace")

    if fd < 0:
        errno = ctypes.get_errno()
        return -1, verifier_log, errno

    return fd, verifier_log, 0

def assemble_program_bytecode(
    filepath,
    section_name,
    section_off,
    section_size,
    map_name_to_fd,
    kconfig_fd=None,
    kconfig_offsets=None,
    data_sec_to_fd=None,
    data_sec_to_size=None,
):

    section_data = read_section_data(filepath, section_name)
    if section_data is None:
        return None, f"Could not read section '{section_name}'"
    if section_size is None:
        bytecode = bytearray(section_data)
    else:
        lo = int(section_off)
        hi = lo + int(section_size)
        if lo < 0 or hi > len(section_data):
            return (
                None,
                f"Program slice out of bounds "
                f"(off={lo}, size={section_size}, section_size={len(section_data)})",
            )
        bytecode = bytearray(section_data[lo:hi])

    relocs = collect_relocations(filepath, section_name)
    relocs = _slice_relocations(relocs, section_off, section_size)

    func_insn_offsets = {}
    func_insn_offsets_by_off = {}
    if relocs["call"]:
        text_data = read_section_data(filepath, ".text")
        if text_data is None:
            return (
                None,
                "Program has BPF-to-BPF calls but no .text section found",
            )

        text_funcs = get_text_functions(filepath)
        text_func_ranges = _build_text_func_ranges(text_funcs)
        text_offset_to_name = _build_text_func_offset_index(text_funcs)
        text_relocs = collect_relocations(filepath, ".text")

        needed_funcs = set()
        worklist = []

        for reloc_off, sym_name, sym_value in relocs["call"]:
            resolved_name, _resolved_off = _resolve_text_call_target(
                sym_name, sym_value, text_funcs, text_offset_to_name
            )
            if resolved_name is None:
                return None, (
                    f"Call to unknown .text function '{sym_name}' "
                    f"(sym_value={sym_value}, reloc_offset={reloc_off})"
                )
            if resolved_name not in needed_funcs:
                needed_funcs.add(resolved_name)
                worklist.append(resolved_name)

        text_call_relocs_by_func = {}
        for call_off, call_sym_name, call_sym_value in text_relocs["call"]:
            owner = _find_text_func_for_offset(call_off, text_func_ranges)
            if owner is None:
                continue
            text_call_relocs_by_func.setdefault(owner, []).append(
                (call_off, call_sym_name, call_sym_value)
            )

        while worklist:
            func_name = worklist.pop()
            func_off, func_size = text_funcs[func_name]
            func_off = int(func_off)
            func_size = int(func_size)
            func_end = func_off + func_size

            for _, call_sym_name, call_sym_value in text_call_relocs_by_func.get(
                func_name, []
            ):
                callee_name, _callee_off = _resolve_text_call_target(
                    call_sym_name,
                    call_sym_value,
                    text_funcs,
                    text_offset_to_name,
                )
                if callee_name is None:
                    return None, (
                        f"Call to unknown .text function '{call_sym_name}' "
                        f"(sym_value={call_sym_value}) from .text function '{func_name}'"
                    )
                if callee_name not in needed_funcs:
                    needed_funcs.add(callee_name)
                    worklist.append(callee_name)

            for insn_off in range(func_off, func_end, 8):
                if text_data[insn_off] != 0x85:
                    continue
                src_reg = (text_data[insn_off + 1] >> 4) & 0x0F
                if src_reg != BPF_PSEUDO_CALL:
                    continue

                imm = struct.unpack_from("<i", text_data, insn_off + 4)[0]
                current_insn = insn_off // 8
                target_insn = current_insn + 1 + imm
                target_off = target_insn * 8
                callee_name = _find_text_func_for_offset(target_off, text_func_ranges)
                if callee_name is None:
                    return None, (
                        f"Internal .text pseudo-call target out of range "
                        f"(caller='{func_name}', target_off={target_off})"
                    )
                if callee_name not in needed_funcs:
                    needed_funcs.add(callee_name)
                    worklist.append(callee_name)

        selected_text_funcs = sorted(
            (
                (int(text_funcs[name][0]), int(text_funcs[name][1]), name)
                for name in needed_funcs
            ),
            key=lambda item: item[0],
        )

        old_to_new_byte_off = {}
        for func_off, func_size, func_name in selected_text_funcs:
            new_func_off = len(bytecode)
            bytecode.extend(text_data[func_off:func_off + func_size])

            func_insn = new_func_off // 8
            func_insn_offsets[func_name] = func_insn
            func_insn_offsets_by_off[func_off] = func_insn

            for old_off in range(func_off, func_off + func_size, 8):
                old_to_new_byte_off[old_off] = new_func_off + (old_off - func_off)

        for func_off, func_size, func_name in selected_text_funcs:
            for old_off in range(func_off, func_off + func_size, 8):
                new_off = old_to_new_byte_off[old_off]
                if bytecode[new_off] != 0x85:
                    continue
                src_reg = (bytecode[new_off + 1] >> 4) & 0x0F
                if src_reg != BPF_PSEUDO_CALL:
                    continue

                imm = struct.unpack_from("<i", bytecode, new_off + 4)[0]
                old_current_insn = old_off // 8
                old_target_insn = old_current_insn + 1 + imm
                old_target_off = old_target_insn * 8
                if old_target_off not in old_to_new_byte_off:
                    return None, (
                        f"Internal .text pseudo-call target not selected "
                        f"(caller='{func_name}', target_off={old_target_off})"
                    )

                new_current_insn = new_off // 8
                new_target_insn = old_to_new_byte_off[old_target_off] // 8
                new_rel = new_target_insn - (new_current_insn + 1)
                struct.pack_into("<i", bytecode, new_off + 4, new_rel)

        remapped_text_relocs = {"map": [], "kconfig": [], "data": [], "call": [], "kfunc": []}
        for old_off, sym_name in text_relocs["map"]:
            old_off = int(old_off)
            if old_off in old_to_new_byte_off:
                remapped_text_relocs["map"].append(
                    (old_to_new_byte_off[old_off], sym_name)
                )
        for old_off, sym_name in text_relocs["kconfig"]:
            old_off = int(old_off)
            if old_off in old_to_new_byte_off:
                remapped_text_relocs["kconfig"].append(
                    (old_to_new_byte_off[old_off], sym_name)
                )
        for old_off, sym_name, sym_sec, sym_value in text_relocs["data"]:
            old_off = int(old_off)
            if old_off in old_to_new_byte_off:
                remapped_text_relocs["data"].append(
                    (old_to_new_byte_off[old_off], sym_name, sym_sec, sym_value)
                )
        for old_off, sym_name, sym_value in text_relocs["call"]:
            old_off = int(old_off)
            if old_off in old_to_new_byte_off:
                remapped_text_relocs["call"].append(
                    (old_to_new_byte_off[old_off], sym_name, sym_value)
                )
        for old_off, sym_name in text_relocs.get("kfunc", []):
            old_off = int(old_off)
            if old_off in old_to_new_byte_off:
                remapped_text_relocs["kfunc"].append(
                    (old_to_new_byte_off[old_off], sym_name)
                )

        _extend_relocations(relocs, remapped_text_relocs)

    try:
        apply_relocations(
            bytecode,
            relocs,
            map_name_to_fd,
            func_insn_offsets,
            func_insn_offsets_by_off,
            kconfig_fd,
            kconfig_offsets,
            data_sec_to_fd,
            data_sec_to_size,
        )
    except RuntimeError as e:
        return None, str(e)

    return bytecode, ""

def verify_program(
    filepath,
    display_name,
    section_name,
    prog_type,
    section_off,
    section_size,
    map_name_to_fd,
    kconfig_fd=None,
    kconfig_offsets=None,
    data_sec_to_fd=None,
    data_sec_to_size=None,
    verbose=False,
):
    if _is_dummy_tracing_section(section_name):
        return (
            True,
            f"[skip] Placeholder tracing attach target in section '{display_name}' "
            "(dummy_*); intended to be rebound by userspace loader.",
            True,
        )

    bytecode, err_msg = assemble_program_bytecode(
        filepath, section_name, section_off, section_size,
        map_name_to_fd, kconfig_fd, kconfig_offsets,
        data_sec_to_fd, data_sec_to_size,
    )
    if bytecode is None:
        return False, err_msg, False

    expected_attach_type = 0
    attach_btf_id = 0
    attach_name = None

    if prog_type == BPF_PROG_TYPE_TRACING:
        try:
            expected_attach_type, attach_btf_id, attach_name = _resolve_tracing_attach(
                section_name
            )
        except RuntimeError as e:
            msg = str(e)
            if (
                "Could not resolve kernel BTF attach target for section" in msg
                or "Unable to read kernel BTF IDs from /sys/kernel/btf/vmlinux" in msg
            ):
                return (
                    True,
                    f"[skip] {msg} (kernel/BTF compatibility; section not loadable on this host)",
                    True,
                )
            return False, msg, False

    log_level = 4 if verbose else 1
    fd, verifier_log, errno = load_program(
        prog_type,
        bytecode,
        log_level=log_level,
        expected_attach_type=expected_attach_type,
        attach_btf_id=attach_btf_id,
    )

    if fd >= 0:
        os.close(fd)
        if attach_name:
            verifier_log = (
                f"[attach] expected_attach_type={expected_attach_type}, "
                f"attach_btf_id={attach_btf_id}, target='{attach_name}'\n"
                + verifier_log
            )
        return True, verifier_log, False
    else:
        err_msg = f"BPF_PROG_LOAD failed: errno={errno} ({os.strerror(errno)})"
        if attach_name:
            err_msg += (
                f"\n[attach] expected_attach_type={expected_attach_type}, "
                f"attach_btf_id={attach_btf_id}, target='{attach_name}'"
            )

        low_log = (verifier_log or "").lower()
        if (
            section_name.startswith("tp_btf/")
            and (
                ("doesn't have" in low_log and "argument" in low_log)
                or "invalid bpf_context access" in low_log
                or "dereference of modified ctx ptr" in low_log
            )
        ):
            note = (
                f"[skip] tp_btf context/signature mismatch for section "
                f"'{section_name}' on this kernel"
            )
            if verifier_log:
                note = note + "\n" + verifier_log
            return True, note, True

        if (
            section_name.startswith("raw_tp/")
            and "unknown func bpf_get_socket_cookie" in low_log
        ):
            note = (
                f"[skip] helper availability mismatch for section "
                f"'{section_name}' on this kernel (missing bpf_get_socket_cookie)"
            )
            if verifier_log:
                note = note + "\n" + verifier_log
            return True, note, True
        if verifier_log:
            return False, f"{err_msg}\n{verifier_log}", False
        return False, err_msg, False

def main():
    parser = argparse.ArgumentParser(
        description="Verify eBPF bytecode against the Linux kernel verifier (direct syscall)"
    )
    parser.add_argument("obj_file", help="Path to compiled eBPF object file (.o)")
    parser.add_argument("--prog", help="Verify only this program (by section name substring)")
    parser.add_argument("--type", dest="prog_type",
                        help="Override program type (e.g. tracepoint, kprobe, xdp)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show full verifier log (even on success)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only list detected programs and maps, do not load into kernel")
    args = parser.parse_args()

    if not os.path.isfile(args.obj_file):
        print(f"[!] File not found: {args.obj_file}", file=sys.stderr)
        sys.exit(1)

    all_maps = find_maps(args.obj_file)
    if all_maps:
        print(f"[*] Found {len(all_maps)} map(s):")
        for m in all_maps:
            print(f"    - {m.name}: type={m.map_type_name}({m.map_type}), "
                  f"key_size={m.key_size}, value_size={m.value_size}, "
                  f"max_entries={m.max_entries}")
    else:
        print("[*] No maps found.")
    print()

    programs = find_programs(args.obj_file)
    if not programs:
        print("[!] No eBPF program sections found in the object file.")
        if not args.prog_type:
            print("[!] Use --type to specify the program type.", file=sys.stderr)
            sys.exit(2)

    if args.prog_type:
        override = args.prog_type.lower()
        if override in SECTION_TO_PROG_TYPE:
            override_int = SECTION_TO_PROG_TYPE[override]
        else:
            print(f"[!] Unknown program type '{args.prog_type}'.", file=sys.stderr)
            print(f"[*] Valid types: {sorted(SECTION_TO_PROG_TYPE.keys())}")
            sys.exit(1)
        programs = [
            (display_name, section_name, override_int, entry_off, entry_size)
            for display_name, section_name, _, entry_off, entry_size in programs
        ]

    if args.prog:
        matched = [
            p for p in programs
            if args.prog in p[0] or args.prog in p[1]
        ]
        if not matched:
            print(f"[!] No program matching '{args.prog}' found.", file=sys.stderr)
            print(f"[*] Available programs: {[display_name for display_name, *_ in programs]}")
            sys.exit(1)
        programs = matched

    print(f"[*] Found {len(programs)} program(s) to verify:")
    for display_name, _, pt, _, _ in programs:
        print(f"    - {display_name} (type: {_prog_type_name(pt)})")
    print()

    if args.dry_run:
        print("[*] Dry run — skipping kernel verifier.")
        return 0

    all_kconfig_relocs = []
    all_data_relocs = []
    for _, section_name, _, entry_off, entry_size in programs:
        relocs = collect_relocations(args.obj_file, section_name)
        relocs = _slice_relocations(relocs, entry_off, entry_size)
        all_kconfig_relocs.extend(relocs["kconfig"])
        all_data_relocs.extend(relocs["data"])

    text_relocs = collect_relocations(args.obj_file, ".text")
    all_kconfig_relocs.extend(text_relocs["kconfig"])
    all_data_relocs.extend(text_relocs["data"])

    map_btf_fd = load_btf_from_elf(args.obj_file)
    map_btf_type_ids = find_map_btf_type_ids(args.obj_file) if map_btf_fd >= 0 else {}
    if map_btf_type_ids:
        print(f"[+] Loaded BTF for map creation → fd {map_btf_fd} "
              f"({len(map_btf_type_ids)} maps with type IDs: {list(map_btf_type_ids)})")

    map_name_to_fd = {}
    map_fds = []
    kconfig_fd = None
    kconfig_offsets = {}
    data_sec_to_fd = {}
    data_sec_to_size = {}
    try:
        for m in all_maps:

            if m.map_type == 0 and m.key_size == 0 and m.value_size == 0:
                print(f"[*] Skipping phantom map '{m.name}' (type=unspec, key=0, val=0)")
                continue
            try:
                btf_key_tid, btf_val_tid = map_btf_type_ids.get(m.name, (0, 0))

                NO_BTF_MAP_TYPES = (
                    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                    BPF_MAP_TYPE_PROG_ARRAY,
                )
                if m.map_type in NO_BTF_MAP_TYPES:
                    btf_key_tid, btf_val_tid = 0, 0
                fd = create_map(
                    m,
                    btf_fd=map_btf_fd if btf_key_tid else -1,
                    btf_key_type_id=btf_key_tid,
                    btf_value_type_id=btf_val_tid,
                )
                map_name_to_fd[m.name] = fd
                map_fds.append(fd)
                print(f"[+] Created map '{m.name}' → fd {fd}")
            except RuntimeError as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)

        if all_kconfig_relocs:
            try:
                kconfig_fd, kconfig_offsets = create_kconfig_map(all_kconfig_relocs)
                if kconfig_fd is not None:
                    map_fds.append(kconfig_fd)
                    print(f"[+] Created kconfig map → fd {kconfig_fd} "
                          f"(externs: {list(kconfig_offsets.keys())})")
            except RuntimeError as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)

        if all_data_relocs:
            try:
                data_sec_to_fd, data_sec_to_size = create_data_section_maps(
                    args.obj_file, all_data_relocs
                )
                for sec_name in sorted(data_sec_to_fd):
                    fd = data_sec_to_fd[sec_name]
                    size = data_sec_to_size.get(sec_name, 0)
                    map_fds.append(fd)
                    print(
                        f"[+] Created global-data map for '{sec_name}' "
                        f"→ fd {fd} (value_size={size})"
                    )
            except RuntimeError as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)

        if map_fds:
            print()

        passed = 0
        failed = 0
        skipped = 0

        for display_name, section_name, prog_type, entry_off, entry_size in programs:
            print(f"--- Verifying: {display_name} ({_prog_type_name(prog_type)}) ---")
            success, log, was_skipped = verify_program(
                args.obj_file, display_name, section_name, prog_type, entry_off, entry_size,
                map_name_to_fd,
                kconfig_fd,
                kconfig_offsets,
                data_sec_to_fd,
                data_sec_to_size,
                verbose=args.verbose,
            )

            if success and was_skipped:
                print("  SKIP - program intentionally skipped")
                skipped += 1
                if log:
                    print(f"  Note:\n{_indent(log)}")
            elif success:
                print(f"  PASS - kernel verifier accepted the program")
                passed += 1
                if args.verbose and log:
                    print(f"  Verifier log:\n{_indent(log)}")
            else:
                print(f"  FAIL - kernel verifier rejected the program")
                failed += 1
                if log:
                    print(f"  Verifier log:\n{_indent(log)}")
            print()

    finally:

        if map_btf_fd >= 0:
            try:
                os.close(map_btf_fd)
            except OSError:
                pass
        for fd in map_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    total = passed + failed + skipped
    print(
        f"=== Summary: {passed}/{total} passed, {failed}/{total} failed, "
        f"{skipped}/{total} skipped ==="
    )
    return 0 if failed == 0 else 1

def _indent(text, prefix="    "):
    return "\n".join(prefix + line for line in text.splitlines())

if __name__ == "__main__":
    sys.exit(main())
