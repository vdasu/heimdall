"""
Stage-1 tests for the --witness input (witness_spec.py).

Standalone, no pytest dependency. Run:

    python3 test_witness_spec.py

Exercises: JSON + YAML loading, structural parsing, the expression
mini-language, assumption -> claripy constraint lowering (semantics checked
with a solver), map-spec derivation, and error handling. Does not run angr /
the full symbolic pipeline.
"""

import json
import os
import sys
import tempfile
import traceback

import claripy

from witness_spec import (
    ExprContext,
    Observation,
    RETURN_KEY,
    WitnessError,
    _bits_of_type,
    build_assumption_constraints,
    build_binding_plan,
    build_observation_selection,
    eval_expr,
    find_binding,
    load_witness,
    observation_target,
    relation_is_plain_equal,
)
from generate_formula import build_ctx_shared_vars

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, "witnesses", "reduce_queue_key_width.json")

_passed = 0
_failed = 0


def check(name, fn):
    global _passed, _failed
    try:
        fn()
    except Exception:
        _failed += 1
        print(f"[FAIL] {name}")
        traceback.print_exc()
    else:
        _passed += 1
        print(f"[ok]   {name}")


def expect_error(name, fn, needle=None):
    global _passed, _failed
    try:
        fn()
    except WitnessError as exc:
        if needle and needle not in str(exc):
            _failed += 1
            print(f"[FAIL] {name}: message {str(exc)!r} lacks {needle!r}")
        else:
            _passed += 1
            print(f"[ok]   {name}  ->  {exc}")
    except Exception:
        _failed += 1
        print(f"[FAIL] {name}: wrong exception type")
        traceback.print_exc()
    else:
        _failed += 1
        print(f"[FAIL] {name}: expected WitnessError, none raised")


def xdp_ctx():
    sv, _ = build_ctx_shared_vars("xdp", 24)
    return sv


# --------------------------------------------------------------------------- #
# structural parsing
# --------------------------------------------------------------------------- #
def t_load_example():
    w = load_witness(EXAMPLE)
    assert w.version == "0.1"
    assert w.name == "reduce_queue_key_width"
    assert [b.name for b in w.bindings] == ["context", "queue_id", "queue_packets"]
    assert {b.name: b.is_map for b in w.bindings} == {
        "context": False,
        "queue_id": False,
        "queue_packets": True,
    }
    assert w.derived_map_specs() == ["queue_packets:hash"]
    assert [a.id for a in w.assumptions] == ["A1"]
    assert w.assumptions[0].provenance_kind == "developer_approved"
    assert [o.name for o in w.observations] == ["return_value", "queue_packets"]


def t_load_yaml_and_unwrap():
    doc = """
witness:
  version: "0.1"
  name: y
  bindings:
    - name: m
      original:  {object: m, type: "map<u32, u64>"}
      optimized: {object: m, type: "map<u16, u64>"}
      relation:
        map_correspondence:
          original_key: k
          optimized_key: {truncate: {value: k, width: 16}}
          value_relation: {equal: true}
  assumptions: []
  observations: []
"""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.write(fd, doc.encode())
    os.close(fd)
    try:
        w = load_witness(path)
    finally:
        os.unlink(path)
    assert w.name == "y"
    assert w.derived_map_specs() == ["m:hash"]


def t_bare_object_no_wrapper():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps({"version": "0.1", "name": "bare"}).encode())
    os.close(fd)
    try:
        w = load_witness(path)
    finally:
        os.unlink(path)
    assert w.name == "bare"
    assert w.bindings == [] and w.assumptions == [] and w.observations == []


# --------------------------------------------------------------------------- #
# expression mini-language
# --------------------------------------------------------------------------- #
def t_literal_widths():
    ectx = ExprContext(xdp_ctx())
    v = eval_expr({"value": 65535, "type": "u32"}, ectx)
    assert v.size() == 32 and (v == 0xFFFF).is_true()
    v2 = eval_expr({"value": 0x1FF, "type": "u8"}, ectx)  # masked to width
    assert v2.size() == 8 and (v2 == 0xFF).is_true()


def t_path_resolution():
    sv = xdp_ctx()
    ectx = ExprContext(sv)
    a = ectx.resolve_path("original.ctx.rx_queue_index")
    b = ectx.resolve_path("optimized.ctx.rx_queue_index")
    c = ectx.resolve_path("rx_queue_index")  # bare, side/ctx optional
    assert a is sv["ctx_fields"]["rx_queue_index"][2]
    assert a is b is c  # stage 1: original/optimized ctx fields are the same sym


def t_truncate_concrete():
    ectx = ExprContext(xdp_ctx())
    e = {"truncate": {"value": {"value": 0x1234ABCD, "type": "u32"}, "width": 16}}
    v = eval_expr(e, ectx)
    assert v.size() == 16 and (v == 0xABCD).is_true()


def t_zero_and_sign_extend():
    ectx = ExprContext(xdp_ctx())
    z = eval_expr({"zero_extend": {"value": {"value": 0xFF, "type": "u8"}, "width": 32}}, ectx)
    assert z.size() == 32 and (z == 0xFF).is_true()
    s = eval_expr({"sign_extend": {"value": {"value": 0xFF, "type": "u8"}, "width": 32}}, ectx)
    assert s.size() == 32 and (s == 0xFFFFFFFF).is_true()


def t_arith_coercion():
    ectx = ExprContext(xdp_ctx())
    # u8 + u32 -> widths reconciled, no exception, 32-bit result
    e = {"add": {"left": {"value": 1, "type": "u8"}, "right": {"value": 2, "type": "u32"}}}
    v = eval_expr(e, ectx)
    assert v.size() == 32 and (v == 3).is_true()


def t_comparisons_and_logic():
    ectx = ExprContext(xdp_ctx())
    e = {
        "all_of": [
            {"unsigned_le": {"left": {"value": 1, "type": "u32"}, "right": {"value": 2, "type": "u32"}}},
            {"any_of": [
                {"eq": {"left": {"value": 5, "type": "u32"}, "right": {"value": 6, "type": "u32"}}},
                {"ne": {"left": {"value": 5, "type": "u32"}, "right": {"value": 6, "type": "u32"}}},
            ]},
        ]
    }
    c = eval_expr(e, ectx)
    assert isinstance(c, claripy.ast.Bool) and c.is_true()


# --------------------------------------------------------------------------- #
# assumption lowering (semantics via solver)
# --------------------------------------------------------------------------- #
def t_assumption_constraint_semantics():
    sv = xdp_ctx()
    w = load_witness(EXAMPLE)
    cons = build_assumption_constraints(w, sv)
    assert len(cons) == 1
    c = cons[0]
    assert isinstance(c, claripy.ast.Bool)

    rqi = sv["ctx_fields"]["rx_queue_index"][2]
    assert any("input_ctx_rx_queue_index" in v for v in c.variables)

    s = claripy.Solver()
    s.add(c)
    s.add(rqi == 65535)
    assert s.satisfiable(), "rx_queue_index == 65535 must satisfy A1"

    s2 = claripy.Solver()
    s2.add(c)
    s2.add(rqi == 65536)
    assert not s2.satisfiable(), "rx_queue_index == 65536 must violate A1"


def t_no_assumptions_is_empty():
    sv = xdp_ctx()
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps({"witness": {"version": "0.1", "name": "n"}}).encode())
    os.close(fd)
    try:
        w = load_witness(path)
    finally:
        os.unlink(path)
    assert build_assumption_constraints(w, sv) == []


# --------------------------------------------------------------------------- #
# type helper
# --------------------------------------------------------------------------- #
def t_observation_target():
    assert observation_target(Observation("return_value", "original.return", "optimized.return", "equal")) == ("return", "return")
    assert observation_target(Observation("queue_packets", "original.queue_packets", None, None)) == ("name", "queue_packets")
    assert observation_target(Observation("return_value", None, None, None)) == ("return", "return_value")
    assert observation_target(Observation("events", None, None, None)) == ("name", "events")
    assert observation_target(Observation("x", "original.ctx.foo", None, None)) == ("name", "foo")


def t_build_observation_selection():
    assert build_observation_selection(None) is None

    w = load_witness(EXAMPLE)
    sel = build_observation_selection(w)
    assert sel is not None
    assert sel.want_return is True
    assert sel.names == {"queue_packets"}
    assert sel.size() == 2
    assert sel.relations[RETURN_KEY] == "equal"
    assert sel.relations["queue_packets"] == {"use_binding": "queue_packets"}

    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps({"witness": {"version": "0.1", "name": "e", "observations": []}}).encode())
    os.close(fd)
    try:
        assert build_observation_selection(load_witness(path)) is None
    finally:
        os.unlink(path)


def t_relation_is_plain_equal():
    w = load_witness(EXAMPLE)  # has bindings: context(equal:true), queue_id(equal:{..}), queue_packets(map_correspondence w/ truncate)
    assert relation_is_plain_equal(None, w) is True
    assert relation_is_plain_equal("equal", w) is True
    assert relation_is_plain_equal({"equal": True}, w) is True
    assert relation_is_plain_equal({"equal": {"left": "a", "right": "b"}}, w) is False
    assert relation_is_plain_equal({"use_binding": "context"}, w) is True          # equal: true
    assert relation_is_plain_equal({"use_binding": "queue_id"}, w) is False        # structured equal
    assert relation_is_plain_equal({"use_binding": "queue_packets"}, w) is False   # key truncate
    assert relation_is_plain_equal({"use_binding": "does_not_exist"}, w) is False
    assert find_binding(w, "queue_id").name == "queue_id"
    assert find_binding(w, "nope") is None


def t_build_binding_plan():
    w = load_witness(EXAMPLE)
    plan = build_binding_plan(w)
    assert plan is not None
    # context -> identity, queue_id -> unsupported scalar, queue_packets -> map
    assert "context" in plan.identity
    assert any(name == "queue_id" for name, _ in plan.unsupported)
    assert "queue_packets" in plan.maps
    mb = plan.maps["queue_packets"]
    assert mb.original_key == "k"
    assert mb.optimized_key == {"truncate": {"value": "k", "width": 16}}
    assert mb.value_is_identity() is True
    assert mb.assume is None
    assert build_binding_plan(None) is None

    # a map_correspondence with an explicit key-domain `assume`
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps({"witness": {"version": "0.1", "name": "d", "bindings": [
        {"name": "m",
         "original": {"object": "m"}, "optimized": {"object": "m"},
         "relation": {"map_correspondence": {
             "original_key": "k",
             "assume": {"unsigned_le": {"left": "k", "right": {"value": 65535, "type": "u32"}}},
             "optimized_key": {"truncate": {"value": "k", "width": 16}},
             "value_relation": {"equal": True}}}},
    ]}}).encode())
    os.close(fd)
    try:
        p2 = build_binding_plan(load_witness(path))
    finally:
        os.unlink(path)
    assert p2.maps["m"].assume == {"unsigned_le": {"left": "k", "right": {"value": 65535, "type": "u32"}}}


def t_eval_witness_expr_z3():
    import z3
    from verify_equivalence import eval_witness_expr_z3

    k = z3.BitVec("k", 32)
    env = {"k": k}
    def resolve(tok):
        return env[tok]

    # identity
    assert z3.simplify(eval_witness_expr_z3("k", resolve) == k)
    # truncate a literal
    v = eval_witness_expr_z3({"truncate": {"value": {"value": 0x1234, "type": "u32"}, "width": 8}}, resolve)
    assert v.size() == 8
    assert z3.simplify(v).as_long() == 0x34
    # truncate a bound var, then it is k[7:0]
    tk = eval_witness_expr_z3({"truncate": {"value": "k", "width": 8}}, resolve)
    assert tk.size() == 8
    assert z3.eq(z3.simplify(tk), z3.simplify(z3.Extract(7, 0, k)))
    # comparison returns a Bool
    b = eval_witness_expr_z3({"unsigned_le": {"left": "k", "right": {"value": 10, "type": "u32"}}}, resolve)
    assert z3.is_bool(b)


def t_bits_of_type():
    assert _bits_of_type("u8") == 8
    assert _bits_of_type("u16") == 16
    assert _bits_of_type("u32") == 32
    assert _bits_of_type("u64") == 64
    assert _bits_of_type("bool") == 1
    assert _bits_of_type("struct xdp_md *") == 64
    assert _bits_of_type("s24") == 24


# --------------------------------------------------------------------------- #
# error handling
# --------------------------------------------------------------------------- #
def t_err_unknown_field():
    ectx = ExprContext(xdp_ctx())
    expect_error(
        "unknown ctx field",
        lambda: eval_expr("original.ctx.nonesuch", ectx),
        needle="nonesuch",
    )


def t_err_non_boolean_assumption():
    sv = xdp_ctx()
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps({"witness": {"version": "0.1", "name": "nb", "assumptions": [
        {"id": "A1", "provenance": {"kind": "x"},
         "expression": {"truncate": {"value": "original.ctx.rx_queue_index", "width": 16}}},
    ]}}).encode())
    os.close(fd)
    try:
        w = load_witness(path)
    finally:
        os.unlink(path)
    expect_error(
        "non-boolean assumption",
        lambda: build_assumption_constraints(w, sv),
        needle="boolean",
    )


def t_err_malformed_json():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, b"{ not json")
    os.close(fd)
    try:
        expect_error("malformed JSON", lambda: load_witness(path), needle="not valid JSON")
    finally:
        os.unlink(path)


def t_err_truncate_too_wide():
    ectx = ExprContext(xdp_ctx())
    expect_error(
        "truncate width > value width",
        lambda: eval_expr(
            {"truncate": {"value": {"value": 1, "type": "u8"}, "width": 16}}, ectx
        ),
        needle="truncate width",
    )


def t_err_bad_type_name():
    expect_error("bad type name", lambda: _bits_of_type("wat"), needle="wat")


# --------------------------------------------------------------------------- #
def main():
    tests = [
        ("load example JSON", t_load_example),
        ("load YAML + unwrap witness:", t_load_yaml_and_unwrap),
        ("bare object (no wrapper)", t_bare_object_no_wrapper),
        ("literal widths + masking", t_literal_widths),
        ("path resolution (side/ctx optional)", t_path_resolution),
        ("truncate (concrete)", t_truncate_concrete),
        ("zero_extend / sign_extend", t_zero_and_sign_extend),
        ("arith width coercion", t_arith_coercion),
        ("comparisons + all_of/any_of", t_comparisons_and_logic),
        ("assumption constraint semantics", t_assumption_constraint_semantics),
        ("no assumptions -> []", t_no_assumptions_is_empty),
        ("observation_target classification", t_observation_target),
        ("build_observation_selection", t_build_observation_selection),
        ("relation_is_plain_equal / find_binding", t_relation_is_plain_equal),
        ("build_binding_plan classification", t_build_binding_plan),
        ("eval_witness_expr_z3", t_eval_witness_expr_z3),
        ("_bits_of_type table", t_bits_of_type),
    ]
    for name, fn in tests:
        check(name, fn)

    # error-path tests manage their own pass/fail accounting
    t_err_unknown_field()
    t_err_non_boolean_assumption()
    t_err_malformed_json()
    t_err_truncate_too_wide()
    t_err_bad_type_name()

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
