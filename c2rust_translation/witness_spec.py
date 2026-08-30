"""
witness_spec.py — optional equivalence "witness" input for Heimdall.

A witness file makes the previously *implicit* assumptions of the equivalence
checker explicit and adjustable. It has three blocks:

  bindings      how objects (variables / maps) in the ORIGINAL program correspond
                to the OPTIMIZED program. Fully consumed in a later stage; stage 1
                only validates them and derives map specs from
                `map_correspondence` entries.

  assumptions   extra facts the solver may assume while proving equivalence, e.g.
                an input range. Stage 1 turns each assumption's `expression` into
                a claripy constraint that is appended to the shared
                `ctx_constraints` list (the same channel the built-in structural
                constraints such as XDP `data <= data_end` already use).

  observations  which outputs the proof must compare. Consumed in a later stage;
                stage 1 only validates the shape.

Only `assumptions` changes verifier behaviour in stage 1.

File format: JSON (recommended). YAML is also accepted when PyYAML is installed.
The document may either be the witness object itself or `{"witness": {...}}`.

Expression mini-language (used by `assumptions`, and later by `bindings`)
------------------------------------------------------------------------
An expression node is one of:

  "original.ctx.<field>"          path reference (string form)
  {"path": "optimized.ctx.<f>"}   path reference (explicit form)
  {"value": 65535, "type": "u32"} integer literal of the given width

  {"truncate":    {"value": <e>, "width": 16}}   low 16 bits of <e>
  {"zero_extend": {"value": <e>, "width": 64}}   zero-extend <e> to 64 bits
  {"sign_extend": {"value": <e>, "width": 64}}   sign-extend <e> to 64 bits
  {"bitnot": <e>}                                bitwise NOT

  {"add"|"sub"|"mul"|"bitand"|"bitor"|"bitxor"|"shl"|"lshr"|"ashr":
        {"left": <e>, "right": <e>}}             arithmetic, returns a bitvector

  {"eq"|"ne"|"unsigned_le"|"unsigned_lt"|"unsigned_ge"|"unsigned_gt"
       |"signed_le"|"signed_lt"|"signed_ge"|"signed_gt":
        {"left": <e>, "right": <e>}}             comparison, returns a boolean

  {"not": <e>}                                   logical NOT (boolean)
  {"all_of": [<e>, ...]}                         logical AND (boolean)
  {"any_of": [<e>, ...]}                         logical OR  (boolean)

An `assumptions[].expression` must evaluate to a boolean.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import claripy

SUPPORTED_VERSIONS = ("0.1",)


class WitnessError(ValueError):
    """Raised for any malformed / unsupported witness content."""


def _looks_like_map(type_name: str) -> bool:
    return str(type_name or "").strip().lower().startswith("map<")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Binding:
    name: str
    original: dict
    optimized: dict
    relation: dict

    @property
    def is_map(self) -> bool:
        return "map_correspondence" in (self.relation or {}) or _looks_like_map(
            self.original.get("type", "")
        ) or _looks_like_map(self.optimized.get("type", ""))


@dataclass
class Assumption:
    id: str
    expression: dict
    provenance: dict = field(default_factory=dict)
    description: str = ""

    @property
    def provenance_kind(self) -> str:
        return str((self.provenance or {}).get("kind", "unspecified"))


@dataclass
class Observation:
    name: str
    original: Optional[str]
    optimized: Optional[str]
    relation: Any


@dataclass
class WitnessSpec:
    version: str
    name: str
    bindings: list
    assumptions: list
    observations: list
    source_path: str = ""

    # -- map specs implied by `map_correspondence` bindings ----------------- #
    def derived_map_specs(self) -> list:
        """Return ['name:type', ...] map specs implied by map bindings.

        The optimized side's object name is used (that is the program whose
        formula enumerates maps in `run_verification_rust_only`); the kind
        defaults to 'hash' unless the binding carries an explicit
        `map_kind: hash|array`.
        """
        specs = []
        for b in self.bindings:
            if not b.is_map:
                continue
            name = (b.optimized or {}).get("object") or (b.original or {}).get(
                "object"
            ) or b.name
            kind = str(
                (b.relation or {}).get("map_kind")
                or (b.optimized or {}).get("map_kind")
                or "hash"
            ).lower()
            if kind not in ("hash", "array"):
                kind = "hash"
            specs.append(f"{name}:{kind}")
        return specs


# --------------------------------------------------------------------------- #
# Loading / structural parsing
# --------------------------------------------------------------------------- #
def load_witness(path: str) -> WitnessSpec:
    """Load and structurally validate a witness file (JSON or YAML)."""
    with open(path, "r") as f:
        raw = f.read()

    doc = _parse_document(raw, path)
    if isinstance(doc, dict) and set(doc.keys()) == {"witness"}:
        doc = doc["witness"]
    if not isinstance(doc, dict):
        raise WitnessError(f"{path}: top level must be a mapping/object")

    version = str(doc.get("version", "0.1"))
    if version not in SUPPORTED_VERSIONS:
        print(
            f"[!] witness: version {version!r} is not one of "
            f"{SUPPORTED_VERSIONS}; proceeding on a best-effort basis"
        )
    name = str(doc.get("name", "") or "")

    bindings = [_parse_binding(i, b) for i, b in enumerate(doc.get("bindings", []) or [])]
    assumptions = [
        _parse_assumption(i, a) for i, a in enumerate(doc.get("assumptions", []) or [])
    ]
    observations = [
        _parse_observation(i, o)
        for i, o in enumerate(doc.get("observations", []) or [])
    ]

    return WitnessSpec(
        version=version,
        name=name,
        bindings=bindings,
        assumptions=assumptions,
        observations=observations,
        source_path=path,
    )


def _parse_document(raw: str, path: str):
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on env
            raise WitnessError(
                f"{path}: YAML witness needs PyYAML (`pip install pyyaml`), "
                f"or convert the file to JSON"
            ) from exc
        return yaml.safe_load(raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # A YAML file passed without the extension is a common mistake.
        raise WitnessError(f"{path}: not valid JSON ({exc})") from exc


def _parse_binding(idx: int, b: dict) -> Binding:
    if not isinstance(b, dict):
        raise WitnessError(f"bindings[{idx}] must be a mapping")
    name = str(b.get("name", f"binding_{idx}"))
    original = b.get("original") or {}
    optimized = b.get("optimized") or {}
    relation = b.get("relation") or {}
    if not isinstance(original, dict) or not isinstance(optimized, dict):
        raise WitnessError(f"bindings[{idx}] ({name}): original/optimized must be mappings")
    if not isinstance(relation, dict):
        raise WitnessError(f"bindings[{idx}] ({name}): relation must be a mapping")
    return Binding(name=name, original=original, optimized=optimized, relation=relation)


def _parse_assumption(idx: int, a: dict) -> Assumption:
    if not isinstance(a, dict):
        raise WitnessError(f"assumptions[{idx}] must be a mapping")
    aid = str(a.get("id", f"A{idx + 1}"))
    expr = a.get("expression")
    if not isinstance(expr, (dict, str)):
        raise WitnessError(f"assumptions[{idx}] ({aid}): missing/!invalid 'expression'")
    prov = a.get("provenance") or {}
    if not isinstance(prov, dict):
        raise WitnessError(f"assumptions[{idx}] ({aid}): provenance must be a mapping")
    return Assumption(
        id=aid,
        expression=expr,
        provenance=prov,
        description=str(a.get("description", "") or "").strip(),
    )


def _parse_observation(idx: int, o: dict) -> Observation:
    if not isinstance(o, dict):
        raise WitnessError(f"observations[{idx}] must be a mapping")
    return Observation(
        name=str(o.get("name", f"observation_{idx}")),
        original=o.get("original"),
        optimized=o.get("optimized"),
        relation=o.get("relation"),
    )


# --------------------------------------------------------------------------- #
# Expression evaluation
# --------------------------------------------------------------------------- #
_TYPE_RE = re.compile(r"^\s*([uisUIS])\s*(\d{1,3})\s*$")


def _bits_of_type(tname: str) -> int:
    """Map a witness type name to a bit width. Pointers -> 64."""
    t = str(tname or "").strip().lower()
    if not t:
        return 64
    if t in ("bool", "_bool"):
        return 1
    if "*" in t or t.startswith("struct ") or t.endswith(" *"):
        return 64
    aliases = {
        "u8": 8, "s8": 8, "i8": 8, "char": 8, "__u8": 8,
        "u16": 16, "s16": 16, "i16": 16, "short": 16, "__u16": 16,
        "u32": 32, "s32": 32, "i32": 32, "int": 32, "unsigned": 32, "__u32": 32,
        "u64": 64, "s64": 64, "i64": 64, "long": 64, "__u64": 64,
        "size_t": 64, "uintptr_t": 64,
    }
    if t in aliases:
        return aliases[t]
    m = _TYPE_RE.match(t)
    if m:
        n = int(m.group(2))
        if 1 <= n <= 512:
            return n
    raise WitnessError(f"unrecognised type name {tname!r}")


class ExprContext:
    """Resolves witness path references against a built `shared_vars` dict."""

    def __init__(self, shared_vars: dict, bindings=None):
        self.shared_vars = shared_vars or {}
        self.ctx_fields = self.shared_vars.get("ctx_fields", {}) or {}
        self.bindings = {b.name: b for b in (bindings or [])}

    def field_names(self):
        return sorted(self.ctx_fields.keys())

    def resolve_path(self, path: str):
        parts = [p for p in str(path).split(".") if p != ""]
        if not parts:
            raise WitnessError("empty path reference")

        side = "original"
        if parts[0] in ("original", "optimized"):
            side = parts.pop(0)
        if parts and parts[0] == "ctx":
            parts.pop(0)

        if not parts:
            raise WitnessError(f"path {path!r} does not name a field")
        if parts == ["return"] or parts[-1] == "return":
            raise WitnessError(
                f"path {path!r}: 'return' is only usable in observations, "
                f"not in assumption expressions (stage 1)"
            )

        field_name = parts[0]
        entry = self.ctx_fields.get(field_name)
        if entry is None:
            raise WitnessError(
                f"path {path!r}: no context field {field_name!r} for this "
                f"program type. Known fields: {self.field_names()}"
            )
        # entry is (byte_offset, bit_width, claripy_bvs)
        bvs = entry[2]

        if len(parts) > 1:
            raise WitnessError(
                f"path {path!r}: sub-field access ({'.'.join(parts[1:])}) is "
                f"not supported in stage 1"
            )
        # `side` is accepted but original/optimized ctx fields resolve to the
        # same symbol in stage 1 (the unifier merges same-named inputs).
        _ = side
        return bvs


def _coerce_pair(a, b, signed: bool):
    """Widen two bitvectors to a common width."""
    sa, sb = a.size(), b.size()
    if sa == sb:
        return a, b
    if sa < sb:
        ext = claripy.SignExt if signed else claripy.ZeroExt
        return ext(sb - sa, a), b
    ext = claripy.SignExt if signed else claripy.ZeroExt
    return a, ext(sa - sb, b)


_BIN_BV_OPS = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
    "bitand": lambda a, b: a & b,
    "bitor": lambda a, b: a | b,
    "bitxor": lambda a, b: a ^ b,
    "shl": lambda a, b: a << b,
    "lshr": lambda a, b: claripy.LShR(a, b),
    "ashr": lambda a, b: a >> b,
}

_BIN_CMP_OPS = {
    "eq": (lambda a, b: a == b, False),
    "ne": (lambda a, b: a != b, False),
    "unsigned_le": (claripy.ULE, False),
    "unsigned_lt": (claripy.ULT, False),
    "unsigned_ge": (claripy.UGE, False),
    "unsigned_gt": (claripy.UGT, False),
    "signed_le": (claripy.SLE, True),
    "signed_lt": (claripy.SLT, True),
    "signed_ge": (claripy.SGE, True),
    "signed_gt": (claripy.SGT, True),
}


def eval_expr(node: Any, ectx: ExprContext):
    """Evaluate a witness expression node to a claripy AST (BV or Bool)."""
    if isinstance(node, bool):
        return claripy.true if node else claripy.false
    if isinstance(node, int):
        return claripy.BVV(node, 64)
    if isinstance(node, str):
        return ectx.resolve_path(node)
    if not isinstance(node, dict):
        raise WitnessError(f"cannot evaluate expression node: {node!r}")

    if "path" in node:
        return ectx.resolve_path(node["path"])
    if "value" in node:
        bits = _bits_of_type(node.get("type", "u64"))
        mask = (1 << bits) - 1
        return claripy.BVV(int(node["value"]) & mask, bits)

    if len(node) != 1:
        raise WitnessError(
            f"expression object must have exactly one operator key, got {sorted(node)}"
        )
    (op, arg), = node.items()

    if op in ("truncate", "zero_extend", "sign_extend"):
        if not isinstance(arg, dict) or "width" not in arg or "value" not in arg:
            raise WitnessError(f"'{op}' needs {{value, width}}")
        v = eval_expr(arg["value"], ectx)
        width = int(arg["width"])
        cur = v.size()
        if op == "truncate":
            if width > cur:
                raise WitnessError(f"truncate width {width} > value width {cur}")
            return claripy.Extract(width - 1, 0, v)
        if width < cur:
            raise WitnessError(f"{op} width {width} < value width {cur}")
        if width == cur:
            return v
        return (claripy.ZeroExt if op == "zero_extend" else claripy.SignExt)(
            width - cur, v
        )

    if op == "bitnot":
        return ~eval_expr(arg, ectx)
    if op == "not":
        return claripy.Not(_as_bool(eval_expr(arg, ectx), "not"))
    if op in ("all_of", "any_of"):
        if not isinstance(arg, list) or not arg:
            raise WitnessError(f"'{op}' needs a non-empty list")
        parts = [_as_bool(eval_expr(x, ectx), op) for x in arg]
        return claripy.And(*parts) if op == "all_of" else claripy.Or(*parts)

    if op in _BIN_BV_OPS or op in _BIN_CMP_OPS:
        if not isinstance(arg, dict) or "left" not in arg or "right" not in arg:
            raise WitnessError(f"'{op}' needs {{left, right}}")
        left = eval_expr(arg["left"], ectx)
        right = eval_expr(arg["right"], ectx)
        if op in _BIN_BV_OPS:
            left, right = _coerce_pair(left, right, signed=False)
            return _BIN_BV_OPS[op](left, right)
        fn, signed = _BIN_CMP_OPS[op]
        left, right = _coerce_pair(left, right, signed=signed)
        return fn(left, right)

    raise WitnessError(f"unknown expression operator {op!r}")


def _as_bool(ast, op):
    if isinstance(ast, claripy.ast.Bool):
        return ast
    raise WitnessError(f"'{op}' expects a boolean operand, got a bitvector")


def _expr_summary(node: Any) -> str:
    """Compact one-line rendering of an expression tree, for logs."""
    if isinstance(node, str):
        return node
    if isinstance(node, (int, bool)):
        return str(node)
    if not isinstance(node, dict):
        return repr(node)
    if "value" in node:
        return f"{node['value']}:{node.get('type', 'u64')}"
    if "path" in node:
        return str(node["path"])
    if len(node) == 1:
        (op, arg), = node.items()
        if isinstance(arg, dict) and {"left", "right"} <= set(arg):
            return f"({_expr_summary(arg['left'])} {op} {_expr_summary(arg['right'])})"
        if isinstance(arg, dict) and {"value", "width"} <= set(arg):
            return f"{op}({_expr_summary(arg['value'])}, {arg['width']})"
        if isinstance(arg, list):
            return f"{op}[" + ", ".join(_expr_summary(x) for x in arg) + "]"
        return f"{op}({_expr_summary(arg)})"
    return repr(node)


# --------------------------------------------------------------------------- #
# Stage-1 entry point: assumptions -> constraints
# --------------------------------------------------------------------------- #
def build_assumption_constraints(witness: WitnessSpec, shared_vars: dict) -> list:
    """Evaluate every assumption to a claripy boolean constraint.

    Returns the list of constraints (to be appended to `ctx_constraints`).
    Logs one `ASSUMPTION` line per assumption. Raises WitnessError if any
    assumption is malformed or does not evaluate to a boolean.
    """
    if witness is None or not witness.assumptions:
        return []

    ectx = ExprContext(shared_vars, bindings=witness.bindings)
    constraints = []
    for a in witness.assumptions:
        try:
            c = eval_expr(a.expression, ectx)
        except WitnessError as exc:
            raise WitnessError(f"assumption {a.id}: {exc}") from None
        if not isinstance(c, claripy.ast.Bool):
            raise WitnessError(
                f"assumption {a.id}: expression must be a boolean predicate, "
                f"got a bitvector"
            )
        constraints.append(c)
        print(
            f"ASSUMPTION {a.id} [{a.provenance_kind}] "
            f"{_expr_summary(a.expression)}"
        )
    print(
        f"[*] witness: added {len(constraints)} assumption constraint(s) "
        f"from {witness.source_path}"
    )
    return constraints


# --------------------------------------------------------------------------- #
# Stage-2 entry point: observations -> comparison selection
# --------------------------------------------------------------------------- #
RETURN_KEY = "\x00return"
_RETURN_TOKENS = {"return", "return_value", "retval", "ret", "r0"}


def observation_target(obs: Observation):
    """Classify what an observation points at.

    Returns ('return', <label>) for the program return value, or
    ('name', <symbol>) for a map / .data global identified by symbol name.
    The reference is read from `original` (falling back to `optimized`, then
    the observation `name`); a leading `original.` / `optimized.` / `ctx.`
    is stripped.
    """
    ref = obs.original or obs.optimized or obs.name or ""
    parts = [p for p in str(ref).split(".") if p]
    if parts and parts[0] in ("original", "optimized"):
        parts = parts[1:]
    if parts and parts[0] == "ctx":
        parts = parts[1:]
    token = parts[-1] if parts else str(obs.name or "")
    if token.lower() in _RETURN_TOKENS:
        return ("return", token)
    return ("name", token)


@dataclass
class ObservationSelection:
    """The set of outputs a witness restricts the equivalence proof to."""

    want_return: bool
    names: set                       # map / global symbol names to compare
    relations: dict                  # key (symbol name or RETURN_KEY) -> raw relation
    labels: dict                     # same keys -> observation `name`, for messages

    def size(self) -> int:
        return len(self.names) + (1 if self.want_return else 0)


def build_observation_selection(witness) -> Optional[ObservationSelection]:
    """Return an ObservationSelection, or None to compare everything.

    None is returned when there is no witness or its `observations` block is
    empty — in that case the checker keeps its default behaviour of comparing
    the return value plus every map and every .data global.
    """
    obs = list(getattr(witness, "observations", None) or []) if witness is not None else []
    if not obs:
        return None
    want_return = False
    names, relations, labels = set(), {}, {}
    for o in obs:
        kind, token = observation_target(o)
        key = RETURN_KEY if kind == "return" else token
        if kind == "return":
            want_return = True
        else:
            names.add(token)
        relations[key] = o.relation
        labels[key] = o.name
    return ObservationSelection(want_return, names, relations, labels)


def find_binding(witness, name):
    for b in getattr(witness, "bindings", None) or []:
        if b.name == name:
            return b
    return None


def _binding_is_identity_equal(b: Binding) -> bool:
    """True if a binding asserts plain equality with no transform."""
    rel = b.relation or {}
    if rel.get("equal") is True:
        return True
    mc = rel.get("map_correspondence")
    if isinstance(mc, dict):
        vr = mc.get("value_relation")
        value_equal = (
            vr is True
            or vr == "equal"
            or (isinstance(vr, dict) and vr.get("equal") is True)
        )
        opt_key = mc.get("optimized_key")
        key_identity = opt_key is None or opt_key == mc.get("original_key")
        return bool(value_equal and key_identity)
    return False


def relation_is_plain_equal(relation, witness) -> bool:
    """True if an observation `relation` means 'compare for exact equality'
    with no transform (the only thing stage 2 can actually enforce)."""
    if relation in (None, True, "equal", "eq"):
        return True
    if isinstance(relation, dict):
        if relation.get("equal") is True:
            return True
        ub = relation.get("use_binding")
        if ub is not None:
            b = find_binding(witness, ub)
            return b is not None and _binding_is_identity_equal(b)
    return False
