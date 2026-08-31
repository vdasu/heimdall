"""
Verify C vs Rust eBPF equivalence using different entry symbols.

This script does not call any LLM APIs. It only runs the symbolic verifier.

Example:
  python verify_mixed_entries.py \
    c_bpf_programs/libbpf-tools/funclatency.o \
    aya-tracepoint-obj \
    exit \
    dummy_fexit \
    cgroup_map:array starts:hash
"""

import argparse
import sys

sys.setrecursionlimit(20000)

from generate_formula import get_entry_section_type, program_types_compatible
from verify_equivalence import (
    prepare_verification,
    generate_c_formula,
    run_verification_rust_only,
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify equivalence with different C and Rust entry symbols."
    )
    parser.add_argument("c_obj", help="Path to C eBPF object (.o)")
    parser.add_argument("rust_obj", help="Path to Rust eBPF object (.o)")
    parser.add_argument("c_entry", help="C entry symbol (e.g., exit)")
    parser.add_argument("rust_entry", help="Rust entry symbol (e.g., dummy_fexit)")
    parser.add_argument(
        "map_specs",
        nargs="*",
        help="Map specs in name[:type] form, e.g. cgroup_map:array starts:hash. "
             "Optional when --witness supplies map_correspondence bindings.",
    )
    parser.add_argument(
        "--witness",
        default=None,
        help="Path to a witness file (JSON, or YAML with PyYAML) declaring "
             "bindings / assumptions / observations. See witness_spec.py.",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="Also write the final verdict as JSON to this path: "
             '{"equivalent": bool|null, "result_type": str, "counter_example": str|null}.',
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=50000,
        help="Max angr exploration steps per program (default: 50000)",
    )
    parser.add_argument(
        "--ringbuf-track-max",
        type=int,
        default=512,
        help="Max ringbuf reservation size (bytes) to track symbolically. "
             "Reservations larger than this are treated as output-sink no-ops. "
             "Set to 0 to disable all ringbuf tracking (default: 512).",
    )
    parser.add_argument(
        "--helper-fail-mode",
        choices=["off", "all", "selected"],
        default="off",
        help="Model failable-helper failure paths during the equivalence check. "
             "'off' (default) = every helper succeeds; 'all' = every failable "
             "helper may also return an error (so an unchecked-helper C bug "
             "diverges from safe Rust that handles the error); 'selected' = only "
             "the helpers named in --helper-fail-helpers.",
    )
    parser.add_argument(
        "--helper-fail-helpers",
        default=None,
        help="Comma/space-separated helper names for --helper-fail-mode selected.",
    )
    parser.add_argument(
        "--symbolic-uninit",
        action="store_true",
        help="Model unwritten memory as fresh symbols instead of zero-filling. "
             "Lets an uninitialized/partial-init leak in C diverge from the "
             "fully-initialized Rust. Trade-off: more symbolic reads => risk of "
             "spurious divergence / path blow-up. Off by default.",
    )
    return parser.parse_args()

def main() -> int:
    args = parse_args()

    def _finish(rc, equivalent, result_type, counter_example=None):
        if args.json_output:
            import json
            try:
                with open(args.json_output, "w") as f:
                    json.dump({
                        "equivalent": equivalent,
                        "result_type": result_type,
                        "counter_example": counter_example,
                    }, f, indent=2)
            except OSError as exc:
                print(f"[!] could not write --json-output: {exc}")
        return rc

    witness = None
    if args.witness:
        from witness_spec import load_witness, WitnessError
        try:
            witness = load_witness(args.witness)
        except WitnessError as exc:
            print(f"[!] witness: {exc}")
            return _finish(2, None, "witness_error", str(exc))
        print(f"[*] witness: loaded '{witness.name or witness.source_path}' "
              f"({len(witness.bindings)} bindings, {len(witness.assumptions)} "
              f"assumptions, {len(witness.observations)} observations)")

    c_type = get_entry_section_type(args.c_obj, args.c_entry)
    r_type = get_entry_section_type(args.rust_obj, args.rust_entry)
    if not program_types_compatible(c_type, r_type):
        print(f"[!] Entry point type mismatch:")
        print(f"    C    '{args.c_entry}' is of type '{c_type}'")
        print(f"    Rust '{args.rust_entry}' is of type '{r_type}'")
        print(f"    These BPF program types are incompatible — cannot be equivalent.")
        ce = f"C entry type '{c_type}' is incompatible with Rust entry type '{r_type}'"
        print("\n[=] Final Result [=]")
        print("equivalent: False")
        print("result_type: type_mismatch")
        print(f"counter_example: {ce}")
        return _finish(1, False, "type_mismatch", ce)

    print("[*] Preparing verification context...")
    try:
        vctx = prepare_verification(
            args.c_obj, args.map_specs,
            helper_fail_mode=args.helper_fail_mode,
            helper_fail_helpers=args.helper_fail_helpers,
            symbolic_uninit=args.symbolic_uninit,
            witness=witness,
        )
    except Exception as exc:
        from witness_spec import WitnessError
        if isinstance(exc, WitnessError):
            print(f"[!] witness: {exc}")
            return _finish(2, None, "witness_error", str(exc))
        raise

    print(f"[*] Generating C formula with entry '{args.c_entry}'...")
    err = generate_c_formula(vctx, args.c_obj, args.c_entry, max_steps=args.max_steps,
                             ringbuf_track_max=args.ringbuf_track_max)
    if err is not None:
        print("[!] Failed to generate C formula")
        print(f"    result_type: {err.result_type}")
        if err.counter_example:
            print(f"    detail: {err.counter_example}")
        return _finish(2, err.equivalent, err.result_type, err.counter_example or None)

    print(f"[*] Verifying Rust object with entry '{args.rust_entry}'...")
    result = run_verification_rust_only(vctx, args.rust_obj, args.rust_entry, max_steps=args.max_steps,
                                        ringbuf_track_max=args.ringbuf_track_max)

    print("\n[=] Final Result [=]")
    print(f"equivalent: {result.equivalent}")
    print(f"result_type: {result.result_type}")
    if result.counter_example:
        print("counter_example:")
        print(result.counter_example)

    return _finish(0 if result.equivalent else 1,
                   result.equivalent, result.result_type, result.counter_example or None)

if __name__ == "__main__":
    sys.exit(main())
