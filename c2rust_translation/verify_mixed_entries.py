

import argparse
import sys

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
        help="Map specs in name[:type] form, e.g. cgroup_map:array starts:hash",
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
    return parser.parse_args()

def main() -> int:
    args = parse_args()

    c_type = get_entry_section_type(args.c_obj, args.c_entry)
    r_type = get_entry_section_type(args.rust_obj, args.rust_entry)
    if not program_types_compatible(c_type, r_type):
        print(f"[!] Entry point type mismatch:")
        print(f"    C    '{args.c_entry}' is of type '{c_type}'")
        print(f"    Rust '{args.rust_entry}' is of type '{r_type}'")
        print(f"    These BPF program types are incompatible — cannot be equivalent.")
        print("\n[=] Final Result [=]")
        print("equivalent: False")
        print("result_type: type_mismatch")
        print(f"counter_example: C entry type '{c_type}' is incompatible with Rust entry type '{r_type}'")
        return 1

    print("[*] Preparing verification context...")
    vctx = prepare_verification(args.c_obj, args.map_specs)

    print(f"[*] Generating C formula with entry '{args.c_entry}'...")
    err = generate_c_formula(vctx, args.c_obj, args.c_entry, max_steps=args.max_steps,
                             ringbuf_track_max=args.ringbuf_track_max)
    if err is not None:
        print("[!] Failed to generate C formula")
        print(f"    result_type: {err.result_type}")
        if err.counter_example:
            print(f"    detail: {err.counter_example}")
        return 2

    print(f"[*] Verifying Rust object with entry '{args.rust_entry}'...")
    result = run_verification_rust_only(vctx, args.rust_obj, args.rust_entry, max_steps=args.max_steps,
                                        ringbuf_track_max=args.ringbuf_track_max)

    print("\n[=] Final Result [=]")
    print(f"equivalent: {result.equivalent}")
    print(f"result_type: {result.result_type}")
    if result.counter_example:
        print("counter_example:")
        print(result.counter_example)

    return 0 if result.equivalent else 1

if __name__ == "__main__":
    sys.exit(main())
