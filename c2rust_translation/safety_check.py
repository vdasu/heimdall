
"""
Framework safety checker for verified translation workflows.

Checks a translated .rs file for banned patterns and runs the safety audit.
Imports from safety_policy.py (the strict 11-rule policy; the prior weaker
policy is preserved as safety_policy_deprecated.py).

Usage:
    python3 safety_check.py <path_to_rs_file>

Exit codes:
    0 — clean (no banned patterns; audit warnings may be printed)
    1 — banned pattern found (result should be downgraded)
    2 — file not found or read error
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safety_policy import analyze_safety, format_safety_report

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_rs_file>", file=sys.stderr)
        sys.exit(2)

    rs_path = sys.argv[1]

    if not os.path.isfile(rs_path):
        print(f"[safety_check] File not found: {rs_path}", file=sys.stderr)
        sys.exit(2)

    with open(rs_path, "r") as f:
        source = f.read()

    report = analyze_safety(source)
    print(format_safety_report(report, rs_path=rs_path))
    sys.exit(1 if report["blocking"] else 0)

if __name__ == "__main__":
    main()
