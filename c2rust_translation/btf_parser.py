"""
BTF (BPF Type Format) parser for extracting eBPF map metadata.

This module parses the .BTF section of eBPF ELF files to extract map definitions
including type, key_size, value_size, and max_entries.
"""

import struct
from elftools.elf.elffile import ELFFile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

BTF_MAGIC = 0xeB9F

BTF_KIND_UNKN = 0
BTF_KIND_INT = 1
BTF_KIND_PTR = 2
BTF_KIND_ARRAY = 3
BTF_KIND_STRUCT = 4
BTF_KIND_UNION = 5
BTF_KIND_ENUM = 6
BTF_KIND_FWD = 7
BTF_KIND_TYPEDEF = 8
BTF_KIND_VOLATILE = 9
BTF_KIND_CONST = 10
BTF_KIND_RESTRICT = 11
BTF_KIND_FUNC = 12
BTF_KIND_FUNC_PROTO = 13
BTF_KIND_VAR = 14
BTF_KIND_DATASEC = 15
BTF_KIND_FLOAT = 16
BTF_KIND_DECL_TAG = 17
BTF_KIND_TYPE_TAG = 18
BTF_KIND_ENUM64 = 19

BPF_MAP_TYPE_UNSPEC = 0
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PROG_ARRAY = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
BPF_MAP_TYPE_PERCPU_HASH = 5
BPF_MAP_TYPE_PERCPU_ARRAY = 6
BPF_MAP_TYPE_STACK_TRACE = 7
BPF_MAP_TYPE_CGROUP_ARRAY = 8
BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
BPF_MAP_TYPE_HASH_OF_MAPS = 13
BPF_MAP_TYPE_DEVMAP = 14
BPF_MAP_TYPE_SOCKMAP = 15
BPF_MAP_TYPE_CPUMAP = 16
BPF_MAP_TYPE_XSKMAP = 17
BPF_MAP_TYPE_SOCKHASH = 18
BPF_MAP_TYPE_CGROUP_STORAGE = 19
BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20
BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
BPF_MAP_TYPE_QUEUE = 22
BPF_MAP_TYPE_STACK = 23
BPF_MAP_TYPE_SK_STORAGE = 24
BPF_MAP_TYPE_DEVMAP_HASH = 25
BPF_MAP_TYPE_STRUCT_OPS = 26
BPF_MAP_TYPE_RINGBUF = 27
BPF_MAP_TYPE_INODE_STORAGE = 28
BPF_MAP_TYPE_TASK_STORAGE = 29
BPF_MAP_TYPE_BLOOM_FILTER = 30

MAP_TYPE_NAMES = {
    BPF_MAP_TYPE_HASH: "hash",
    BPF_MAP_TYPE_ARRAY: "array",
    BPF_MAP_TYPE_PROG_ARRAY: "prog_array",
    BPF_MAP_TYPE_PERF_EVENT_ARRAY: "perf_event_array",
    BPF_MAP_TYPE_PERCPU_HASH: "percpu_hash",
    BPF_MAP_TYPE_PERCPU_ARRAY: "percpu_array",
    BPF_MAP_TYPE_STACK_TRACE: "stack_trace",
    BPF_MAP_TYPE_CGROUP_ARRAY: "cgroup_array",
    BPF_MAP_TYPE_LRU_HASH: "lru_hash",
    BPF_MAP_TYPE_LRU_PERCPU_HASH: "lru_percpu_hash",
    BPF_MAP_TYPE_LPM_TRIE: "lpm_trie",
    BPF_MAP_TYPE_ARRAY_OF_MAPS: "array_of_maps",
    BPF_MAP_TYPE_HASH_OF_MAPS: "hash_of_maps",
    BPF_MAP_TYPE_DEVMAP: "devmap",
    BPF_MAP_TYPE_SOCKMAP: "sockmap",
    BPF_MAP_TYPE_CPUMAP: "cpumap",
    BPF_MAP_TYPE_XSKMAP: "xskmap",
    BPF_MAP_TYPE_SOCKHASH: "sockhash",
    BPF_MAP_TYPE_CGROUP_STORAGE: "cgroup_storage",
    BPF_MAP_TYPE_RINGBUF: "ringbuf",
}

@dataclass
class BTFType:
    """Base class for BTF type records."""
    type_id: int
    kind: int
    name: str

@dataclass
class BTFInt(BTFType):
    size: int
    encoding: int
    bits: int

@dataclass
class BTFPtr(BTFType):
    target_type_id: int

@dataclass
class BTFArray(BTFType):
    elem_type_id: int
    index_type_id: int
    nr_elems: int

@dataclass
class BTFStruct(BTFType):
    size: int
    members: List[Tuple[str, int, int]]

@dataclass
class BTFTypedef(BTFType):
    target_type_id: int

@dataclass
class BTFVar(BTFType):
    target_type_id: int
    linkage: int

@dataclass
class BTFFuncProto(BTFType):
    return_type_id: int

@dataclass
class BTFDatasec(BTFType):
    size: int
    vars: List[Tuple[int, int, int]]

@dataclass
class MapMetadata:
    """Extracted map metadata from BTF."""
    name: str
    map_type: int
    map_type_name: str
    key_size: int
    value_size: int
    max_entries: int

    inner_map_type: Optional[str] = None
    inner_key_size: int = 0
    inner_value_size: int = 0
    inner_max_entries: int = 0

class BTFParser:
    """Parser for BTF sections in eBPF ELF files."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.types: Dict[int, BTFType] = {}
        self.string_table: bytes = b""
        self._parse()

    def _parse(self):
        """Parse the BTF section from the ELF file."""
        with open(self.filepath, 'rb') as f:
            elf = ELFFile(f)
            btf_section = elf.get_section_by_name('.BTF')
            if btf_section is None:
                raise ValueError(f"No .BTF section found in {self.filepath}")

            btf_data = btf_section.data()
            self._parse_btf(btf_data)

    def _parse_btf(self, data: bytes):
        """Parse BTF header and type records."""

        magic, version, flags, hdr_len = struct.unpack_from('<HBBI', data, 0)
        type_off, type_len, str_off, str_len = struct.unpack_from('<IIII', data, 8)

        if magic != BTF_MAGIC:
            raise ValueError(f"Invalid BTF magic: {hex(magic)}")

        str_start = hdr_len + str_off
        self.string_table = data[str_start:str_start + str_len]

        type_start = hdr_len + type_off
        type_end = type_start + type_len
        type_data = data[type_start:type_end]

        self._parse_types(type_data)

    def _get_string(self, offset: int) -> str:
        """Get a null-terminated string from the string table."""
        if offset >= len(self.string_table):
            return ""
        end = self.string_table.find(b'\x00', offset)
        if end == -1:
            end = len(self.string_table)
        return self.string_table[offset:end].decode('utf-8', errors='replace')

    def _parse_types(self, data: bytes):
        """Parse all BTF type records."""
        offset = 0
        type_id = 1

        while offset < len(data):

            if offset + 12 > len(data):
                break

            name_off, info, size_or_type = struct.unpack_from('<III', data, offset)
            offset += 12

            kind = (info >> 24) & 0x1f
            vlen = info & 0xffff
            name = self._get_string(name_off)

            btf_type = None

            if kind == BTF_KIND_INT:

                int_info = struct.unpack_from('<I', data, offset)[0]
                offset += 4
                encoding = (int_info >> 24) & 0xf
                bits = int_info & 0xff
                btf_type = BTFInt(type_id, kind, name, size_or_type, encoding, bits)

            elif kind == BTF_KIND_PTR:
                btf_type = BTFPtr(type_id, kind, name, size_or_type)

            elif kind == BTF_KIND_ARRAY:

                elem_type, index_type, nelems = struct.unpack_from('<III', data, offset)
                offset += 12
                btf_type = BTFArray(type_id, kind, name, elem_type, index_type, nelems)

            elif kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):

                members = []
                for _ in range(vlen):
                    member_name_off, member_type, member_offset = struct.unpack_from('<III', data, offset)
                    offset += 12
                    member_name = self._get_string(member_name_off)
                    members.append((member_name, member_type, member_offset))
                btf_type = BTFStruct(type_id, kind, name, size_or_type, members)

            elif kind == BTF_KIND_ENUM:

                offset += vlen * 8
                btf_type = BTFType(type_id, kind, name)

            elif kind == BTF_KIND_FWD:
                btf_type = BTFType(type_id, kind, name)

            elif kind == BTF_KIND_TYPEDEF:
                btf_type = BTFTypedef(type_id, kind, name, size_or_type)

            elif kind in (BTF_KIND_VOLATILE, BTF_KIND_CONST, BTF_KIND_RESTRICT, BTF_KIND_TYPE_TAG):
                btf_type = BTFTypedef(type_id, kind, name, size_or_type)

            elif kind == BTF_KIND_FUNC:

                btf_type = BTFTypedef(type_id, kind, name, size_or_type)

            elif kind == BTF_KIND_FUNC_PROTO:

                offset += vlen * 8
                btf_type = BTFFuncProto(type_id, kind, name, size_or_type)

            elif kind == BTF_KIND_VAR:

                linkage = struct.unpack_from('<I', data, offset)[0]
                offset += 4
                btf_type = BTFVar(type_id, kind, name, size_or_type, linkage)

            elif kind == BTF_KIND_DATASEC:

                vars = []
                for _ in range(vlen):
                    var_type, var_offset, var_size = struct.unpack_from('<III', data, offset)
                    offset += 12
                    vars.append((var_type, var_offset, var_size))
                btf_type = BTFDatasec(type_id, kind, name, size_or_type, vars)

            elif kind == BTF_KIND_FLOAT:
                btf_type = BTFType(type_id, kind, name)

            elif kind == BTF_KIND_DECL_TAG:

                offset += 4
                btf_type = BTFType(type_id, kind, name)

            elif kind == BTF_KIND_ENUM64:

                offset += vlen * 12
                btf_type = BTFType(type_id, kind, name)

            else:

                btf_type = BTFType(type_id, kind, name)

            if btf_type:
                self.types[type_id] = btf_type
            type_id += 1

    def _resolve_type_size(self, type_id: int, visited: Optional[set] = None) -> int:
        """
        Resolve the size of a type.

        Important for map metadata:
        - pointer-typed keys/values (e.g. `struct sock *`) should resolve to
          pointer width (8 bytes on eBPF), not pointee struct size.
        """
        if visited is None:
            visited = set()

        if type_id in visited:
            return 0
        visited.add(type_id)

        if type_id not in self.types:
            return 0

        t = self.types[type_id]

        if isinstance(t, BTFInt):
            return t.size
        elif isinstance(t, BTFPtr):

            return 8
        elif isinstance(t, BTFTypedef):
            return self._resolve_type_size(t.target_type_id, visited)
        elif isinstance(t, BTFStruct):
            return t.size
        elif isinstance(t, BTFArray):
            elem_size = self._resolve_type_size(t.elem_type_id, visited)
            return elem_size * t.nr_elems

        return 0

    def _resolve_array_nelems(self, type_id: int) -> int:
        """Follow PTR -> ARRAY chain to get nr_elems (used for type and max_entries)."""
        if type_id not in self.types:
            return 0

        t = self.types[type_id]

        if isinstance(t, BTFPtr):
            return self._resolve_array_nelems(t.target_type_id)
        elif isinstance(t, BTFArray):
            return t.nr_elems

        return 0

    def _parse_inner_map_template(self, outer_fields: dict) -> Optional[Tuple[str, int, int, int]]:
        """Parse inner map template from the 'values' member of a map-of-maps.

        In BTF, __array(values, struct { ... }) encodes as:
            values member type_id -> ARRAY -> elem_type_id -> PTR -> target -> STRUCT
        The inner STRUCT has the same layout as an outer map definition
        (type, key/key_size, value/value_size, max_entries).

        Returns (inner_map_type_name, inner_key_size, inner_value_size, inner_max_entries)
        or None if parsing fails.
        """
        if 'values' not in outer_fields:
            return None

        values_tid = outer_fields['values']
        inner_struct = None

        t = self.types.get(values_tid)
        if t is None:
            return None

        visited = set()
        queue = [t]
        while queue:
            cur = queue.pop(0)
            if id(cur) in visited:
                continue
            visited.add(id(cur))

            if isinstance(cur, BTFStruct) and any(
                name in ('type', 'key', 'value', 'key_size', 'value_size')
                for name, _, _ in cur.members
            ):
                inner_struct = cur
                break
            elif isinstance(cur, BTFPtr) and cur.target_type_id in self.types:
                queue.append(self.types[cur.target_type_id])
            elif isinstance(cur, BTFArray) and cur.elem_type_id in self.types:
                queue.append(self.types[cur.elem_type_id])
            elif isinstance(cur, BTFTypedef) and cur.target_type_id in self.types:
                queue.append(self.types[cur.target_type_id])

        if inner_struct is None:
            return None

        inner_fields = {name: tid for name, tid, _ in inner_struct.members}

        inner_map_type = 0
        inner_key_size = 0
        inner_value_size = 0
        inner_max_entries = 0

        if 'type' in inner_fields:
            inner_map_type = self._resolve_array_nelems(inner_fields['type'])

        if 'key' in inner_fields:
            key_tid = inner_fields['key']
            if key_tid in self.types:
                ptr = self.types[key_tid]
                if isinstance(ptr, BTFPtr):
                    inner_key_size = self._resolve_type_size(ptr.target_type_id)
        elif 'key_size' in inner_fields:
            inner_key_size = self._resolve_array_nelems(inner_fields['key_size'])

        if 'value' in inner_fields:
            val_tid = inner_fields['value']
            if val_tid in self.types:
                ptr = self.types[val_tid]
                if isinstance(ptr, BTFPtr):
                    inner_value_size = self._resolve_type_size(ptr.target_type_id)
        elif 'value_size' in inner_fields:
            inner_value_size = self._resolve_array_nelems(inner_fields['value_size'])

        if 'max_entries' in inner_fields:
            inner_max_entries = self._resolve_array_nelems(inner_fields['max_entries'])

        inner_type_name = MAP_TYPE_NAMES.get(inner_map_type, "hash")
        return (inner_type_name, inner_key_size, inner_value_size, inner_max_entries)

    def get_maps_datasec(self) -> Optional[BTFDatasec]:
        """Find the .maps DATASEC."""
        for t in self.types.values():
            if isinstance(t, BTFDatasec) and t.name == '.maps':
                return t
        return None

    def parse_map_definition(self, var_type_id: int) -> Optional[MapMetadata]:
        """
        Parse a map definition from a VAR type.

        Standard format (hash, array, etc.):
        - type: PTR -> ARRAY (nr_elems = BPF map type)
        - key: PTR -> type (resolved size = key_size)
        - value: PTR -> type (resolved size = value_size)
        - max_entries: PTR -> ARRAY (nr_elems = max_entries)

        Alternative format (stack_trace, ringbuf, etc.):
        - type: PTR -> ARRAY (nr_elems = BPF map type)
        - key_size: PTR -> ARRAY (nr_elems = key_size in bytes)
        - value_size: PTR -> ARRAY (nr_elems = value_size in bytes)
        - max_entries: PTR -> ARRAY (nr_elems = max_entries)
        """
        if var_type_id not in self.types:
            return None

        var = self.types[var_type_id]
        if not isinstance(var, BTFVar):
            return None

        struct_type_id = var.target_type_id
        if struct_type_id not in self.types:
            return None

        struct = self.types[struct_type_id]
        if not isinstance(struct, BTFStruct):
            return None

        fields = {name: tid for name, tid, _ in struct.members}

        map_type = 0
        key_size = 0
        value_size = 0
        max_entries = 0

        if 'type' in fields:
            map_type = self._resolve_array_nelems(fields['type'])

        if 'key' in fields:
            key_tid = fields['key']
            if key_tid in self.types:
                ptr = self.types[key_tid]
                if isinstance(ptr, BTFPtr):
                    key_size = self._resolve_type_size(ptr.target_type_id)

        elif 'key_size' in fields:
            key_size = self._resolve_array_nelems(fields['key_size'])

        if 'value' in fields:
            value_tid = fields['value']
            if value_tid in self.types:
                ptr = self.types[value_tid]
                if isinstance(ptr, BTFPtr):
                    value_size = self._resolve_type_size(ptr.target_type_id)

        elif 'value_size' in fields:
            value_size = self._resolve_array_nelems(fields['value_size'])

        if 'max_entries' in fields:
            max_entries = self._resolve_array_nelems(fields['max_entries'])

        map_type_name = MAP_TYPE_NAMES.get(map_type, "unknown")

        if map_type == BPF_MAP_TYPE_STACK_TRACE:
            if key_size == 0:
                key_size = 4
            if value_size == 0:
                value_size = 8 * 127
            if max_entries == 0:
                max_entries = 1024
        elif map_type == BPF_MAP_TYPE_RINGBUF:
            if max_entries == 0:
                max_entries = 256 * 1024

        inner_map_type = None
        inner_key_size = 0
        inner_value_size = 0
        inner_max_entries = 0
        if map_type in (BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS):
            inner = self._parse_inner_map_template(fields)
            if inner:
                inner_map_type, inner_key_size, inner_value_size, inner_max_entries = inner

        return MapMetadata(
            name=var.name,
            map_type=map_type,
            map_type_name=map_type_name,
            key_size=key_size,
            value_size=value_size,
            max_entries=max_entries,
            inner_map_type=inner_map_type,
            inner_key_size=inner_key_size,
            inner_value_size=inner_value_size,
            inner_max_entries=inner_max_entries,
        )

    def is_func_void_return(self, func_name: str) -> bool:
        """Return True if the BTF-declared function has a void return type.

        BTF encodes void as return_type_id == 0 in the FUNC_PROTO record.
        """
        for t in self.types.values():
            if t.kind == BTF_KIND_FUNC and t.name == func_name:
                if not isinstance(t, BTFTypedef):
                    continue
                proto = self.types.get(t.target_type_id)
                if proto is None or not isinstance(proto, BTFFuncProto):
                    continue
                return proto.return_type_id == 0
        return False

    def get_all_maps(self) -> List[MapMetadata]:
        """Extract metadata for all maps defined in the .maps section."""
        maps = []
        datasec = self.get_maps_datasec()
        if datasec is None:
            return maps

        for var_type_id, _, _ in datasec.vars:
            map_meta = self.parse_map_definition(var_type_id)
            if map_meta:
                maps.append(map_meta)

        return maps

def parse_map_metadata_from_btf(filepath: str) -> Dict[str, MapMetadata]:
    """
    Parse map metadata from the BTF section of an eBPF ELF file.

    Returns a dictionary mapping map name to MapMetadata.
    """
    try:
        parser = BTFParser(filepath)
        maps = parser.get_all_maps()
        return {m.name: m for m in maps}
    except Exception as e:
        print(f"[!] Warning: Failed to parse BTF from {filepath}: {e}")
        return {}

def is_void_return_via_btf(filepath: str, func_name: str) -> bool:
    """Return True if func_name's BTF-declared return type is void.

    Used by the equivalence checker to skip R0 comparison for void callbacks
    (e.g. BPF struct_ops void functions) where the kernel ignores R0 entirely.
    Returns False (i.e., do compare R0) on any parse error or if func not found.
    """
    try:
        parser = BTFParser(filepath)
        return parser.is_func_void_return(func_name)
    except Exception:
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ebpf.o>")
        sys.exit(1)

    filepath = sys.argv[1]
    maps = parse_map_metadata_from_btf(filepath)

    if not maps:
        print("No maps found or BTF parsing failed.")
        sys.exit(1)

    print(f"Found {len(maps)} maps:")
    for name, meta in maps.items():
        print(f"  {name}:")
        print(f"    type: {meta.map_type_name} ({meta.map_type})")
        print(f"    key_size: {meta.key_size}")
        print(f"    value_size: {meta.value_size}")
        print(f"    max_entries: {meta.max_entries}")
        if meta.inner_map_type:
            print(f"    inner_map_type: {meta.inner_map_type}")
            print(f"    inner_key_size: {meta.inner_key_size}")
            print(f"    inner_value_size: {meta.inner_value_size}")
            print(f"    inner_max_entries: {meta.inner_max_entries}")
