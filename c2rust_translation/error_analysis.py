"""Compiler and kernel verifier error analysis for eBPF translation pipeline."""

import os
import re
import sys
import subprocess

from prompts import error_prompt, text_content_block

VERIFY_KERNEL_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "verify_ebpf_kernel.py"
)

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

def _strip_ansi(text):
    """Remove ANSI escape sequences from tool output."""
    return ANSI_ESCAPE_RE.sub("", text)

def _truncate_middle(text, max_chars, label):
    """Truncate long text by keeping both head and tail context."""
    if not max_chars or max_chars <= 0 or len(text) <= max_chars:
        return text

    marker = f"\n\n... [{label}; {len(text) - max_chars} chars omitted] ...\n\n"
    budget = max_chars - len(marker)
    if budget <= 0:
        return text[:max_chars]

    head = int(budget * 0.6)
    tail = budget - head
    return text[:head] + marker + text[-tail:]

def _count_rustc_error_headers(text):
    """Count rustc-style top-level error headers."""
    return len(re.findall(r"(?m)^error(?:\[[A-Za-z0-9_]+\])?:", text))

def build_verifier_error_prompt(verifier_log):
    """Prompt the LLM to fix kernel verifier failures.

    The caller can pre-process verifier_log for size, but should preserve the
    most relevant rejection diagnostics.
    """
    return (
        "The Rust code compiles, but the kernel eBPF verifier rejected the bytecode.\n\n"
        "Verifier output:\n\n"
        "```text\n"
        f"{verifier_log}\n"
        "```\n\n"
        "Fix the Rust program so it passes kernel verification while preserving "
        "the original behavior, map names, section/hook attachment, and function names.\n\n"
        "Return only corrected Rust code:\n\n"
        "```rust\n"
        "```"
    )

def run_kernel_verifier(obj_path, verbose=True, timeout_s=180):
    """
    Run verify_ebpf_kernel.py on an object.

    Returns (ok, output, status) where status ∈ {"ok", "permission", "rejected", "error"}.
    """
    cmd = [sys.executable, VERIFY_KERNEL_SCRIPT, obj_path]
    if verbose:
        cmd.append("--verbose")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False, "Kernel verifier timed out.", "error"

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return True, output, "ok"

    low = output.lower()

    if (
        "operation not permitted" in low
        or "cap_bpf" in low
        or "cap_sys_admin" in low
        or "errno=1)" in low
    ):
        return False, output, "permission"

    if (
        "kernel verifier rejected" in low
        or "bpf_prog_load failed" in low
        or "invalid mem access" in low
        or "verification time" in low
        or "processed " in low and " insns" in low
        or "errno=13" in low
        or "permission denied" in low
        or "failed" in low
    ):
        return False, output, "rejected"

    return False, output, "error"

def summarize_compiler_errors(build_log, tail_lines=40):
    """Extract a concise summary of Rust compiler errors from cargo output."""
    lines = build_log.splitlines()
    raw_items = []

    for i, line in enumerate(lines):
        text = line.strip()
        if re.match(r"^error(\[[A-Za-z0-9_]+\])?:", text):
            location = ""
            for j in range(i + 1, min(i + 7, len(lines))):
                nxt = lines[j].strip()
                if nxt.startswith("-->"):
                    location = nxt[3:].strip()
                    break

            item = text
            if location:
                item = f"{item} ({location})"
            raw_items.append(item)

    items = []
    seen = set()
    for item in raw_items:
        if item in seen:
            continue
        seen.add(item)
        items.append(item)

    if items:
        summary_lines = [
            f"found {len(items)} compiler error(s):",
        ]
        summary_lines.extend([f"  - {item}" for item in items])
        return "\n".join(summary_lines)

    tail = "\n".join(lines[-tail_lines:]).strip()
    if tail:
        return "no structured 'error:' lines found; build log tail:\n" + tail
    return "build failed but log output was empty."

def classify_build_errors(build_log):
    """Classify compiler errors into categories. Returns (category_counts, total)."""
    categories = {
        "import_error": [r"E0432", r"E0433", r"unresolved import"],
        "type_error": [r"E0308", r"mismatched types"],
        "method_error": [r"E0599", r"method not found"],
        "argument_error": [r"E0061", r"wrong number of"],
        "borrow_error": [r"E0502", r"E0505", r"cannot borrow"],
        "lifetime_error": [r"E0106", r"lifetime"],
        "syntax_error": [r"expected .* found", r"unexpected token"],
        "unsafe_error": [r"E0133", r"requires unsafe"],
        "name_error": [r"E0412", r"cannot find type"],
        "macro_error": [r"invalid argument.*macro", r"macro expansion"],
    }
    counts = {}
    total = 0
    for line in build_log.splitlines():
        s = line.strip()
        if not re.match(r"^error", s):
            continue
        total += 1
        matched = False
        for cat, patterns in categories.items():
            if any(re.search(p, s, re.IGNORECASE) for p in patterns):
                counts[cat] = counts.get(cat, 0) + 1
                matched = True
                break
        if not matched:
            counts["other"] = counts.get("other", 0) + 1
    return counts, total

def summarize_verifier_rejection(verifier_log, tail_lines=40, max_sections=10):
    """Extract a concise summary of kernel verifier rejection reasons."""
    lines = verifier_log.splitlines()
    section_summaries = []
    generic_reasons = []

    def _extract_section_reason(section_lines):
        """Pick the most informative verifier reason line from one failed section."""

        errno_line = None
        for raw in section_lines:
            s = raw.strip()
            if s.startswith("BPF_PROG_LOAD failed:"):
                errno_line = s
                break

        signal_patterns = [
            r"invalid mem access",
            r"invalid indirect read from stack",
            r"invalid indirect access to stack",
            r"unbounded memory access",
            r"out of bounds",
            r"misaligned",
            r"reference leak",
            r"unreleased reference",
            r"not allowed",
            r"unknown func",
            r"helper call",
            r"stack depth",
            r"R\d+ .* !read_ok",
            r"map_value_or_null",
            r"infinite loop",
            r"back-edge",
        ]
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in signal_patterns]

        def _is_wrapper(s):
            low = s.lower()
            if not s:
                return True
            if s.startswith("FAIL - kernel verifier rejected"):
                return True
            if s.startswith("PASS - kernel verifier accepted"):
                return True
            if s.startswith("Verifier log:"):
                return True
            if s.startswith("BPF_PROG_LOAD failed:"):
                return True
            if s.startswith("[attach]"):
                return True
            if low.startswith("verification time"):
                return True
            if low.startswith("stack depth"):
                return True
            if low.startswith("processed "):
                return True
            return False

        fallback = None
        for raw in section_lines:
            s = raw.strip()
            if _is_wrapper(s):
                continue
            if fallback is None:
                fallback = s
            if any(p.search(s) for p in compiled_patterns):
                if errno_line:
                    return f"{s} ({errno_line})"
                return s

        if fallback is not None:
            if errno_line:
                return f"{fallback} ({errno_line})"
            return fallback
        return errno_line or "kernel verifier rejected bytecode"

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line.startswith("--- Verifying:"):
            i += 1
            continue

        m = re.match(r"^--- Verifying:\s+(.+?)\s+\(", line)
        section_name = m.group(1) if m else line.replace("--- Verifying:", "").strip(" -")

        j = i + 1
        in_fail = False
        section_lines = []
        while j < len(lines):
            raw = lines[j]
            s = raw.strip()
            if s.startswith("--- Verifying:"):
                break
            section_lines.append(raw)
            if s.startswith("FAIL - kernel verifier rejected"):
                in_fail = True
            j += 1

        if in_fail:
            reason = _extract_section_reason(section_lines)
            section_summaries.append(f"{section_name}: {reason}")

        i = j

    if section_summaries:
        out = [
            f"found {len(section_summaries)} verifier rejection(s):",
        ]
        out.extend([f"  - {item}" for item in section_summaries])
        return "\n".join(out)

    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        low = s.lower()
        if (
            s.startswith("BPF_PROG_LOAD failed:")
            or "bpf_map_create failed" in low
            or "invalid mem access" in low
            or "not a typedef" in low
            or "must provide btf_id" in low
            or "unknown func" in low
            or "permission denied" in low
            or "operation not permitted" in low
        ):
            generic_reasons.append(s)

    deduped = []
    seen = set()
    for r in generic_reasons:
        if r in seen:
            continue
        seen.add(r)
        deduped.append(r)

    if deduped:
        shown = deduped[:max_sections]
        out = [f"verifier rejection summary ({len(deduped)} reason line(s)):"]
        out.extend([f"  - {item}" for item in shown])
        if len(deduped) > max_sections:
            out.append(f"  - ... and {len(deduped) - max_sections} more")
        return "\n".join(out)

    tail = "\n".join(lines[-tail_lines:]).strip()
    if tail:
        return "no structured verifier reasons found; verifier log tail:\n" + tail
    return "kernel verifier failed but log output was empty."

def extract_verifier_feedback(verifier_log, max_chars=24_000):
    """Extract verifier feedback with section-aware truncation.

    If logs are large, prioritize failed verification sections instead of
    blindly taking only the tail, which can hide the actual rejection reason.
    """
    if not verifier_log:
        return ""

    cleaned = _strip_ansi(verifier_log).replace("\r\n", "\n")
    if len(cleaned) <= max_chars:
        return cleaned

    lines = cleaned.splitlines()
    failed_chunks = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line.startswith("--- Verifying:"):
            i += 1
            continue

        chunk_start = i
        j = i + 1
        failed = False
        while j < len(lines) and not lines[j].strip().startswith("--- Verifying:"):
            s = lines[j].strip().lower()
            if (
                "fail - kernel verifier rejected" in s
                or "bpf_prog_load failed" in s
                or "invalid mem access" in s
                or "permission denied" in s
                or "operation not permitted" in s
            ):
                failed = True
            j += 1

        if failed:
            failed_chunks.extend(lines[chunk_start:j])
            failed_chunks.append("")

        i = j

    prioritized = "\n".join(failed_chunks).strip() if failed_chunks else cleaned
    return _truncate_middle(
        prioritized,
        max_chars=max_chars,
        label="verifier feedback truncated",
    )

def extract_structured_errors(build_log, max_chars=24_000):
    """Extract error/help/note lines from cargo output for LLM consumption.

    Keeps rustc's structured output: error headers, source code lines (e.g.
    ``23 |     let val = ...``), caret/annotation lines (``   | ^^^``),
    location arrows (``-->``), help/note lines, and their continuation lines.
    """
    if not build_log:
        return ""

    cleaned_log = _strip_ansi(build_log).replace("\r\n", "\n")
    lines = cleaned_log.splitlines()
    relevant = []
    prev_kept = False
    for line in lines:
        stripped = line.strip()
        keep = False

        if stripped.startswith("warning: profiles for the non root package will be ignored"):
            prev_kept = False
            continue

        if stripped.startswith((
            'error',
            'warning',
            '-->',
            '|',
            'help:',
            'note:',
            '= note:',
            '= help:',
            'Some errors have detailed explanations',
            'For more information about this error',
        )):
            keep = True
        elif re.match(r'^\s*\d+\s*[|+-]', line):

            keep = True
        elif stripped.startswith('error: could not compile'):
            keep = True
        elif prev_kept and stripped and not stripped.startswith((
            'Compiling',
            'Finished',
            'Running',
            'workspace:',
            'package:',
        )):

            keep = True
        prev_kept = keep
        if keep:
            relevant.append(line)

    if relevant:
        structured = "\n".join(relevant)

        raw_errs = _count_rustc_error_headers(cleaned_log)
        structured_errs = _count_rustc_error_headers(structured)
        if raw_errs > 0 and structured_errs < raw_errs:
            return _truncate_middle(
                cleaned_log,
                max_chars=max_chars,
                label="compiler log truncated",
            )

        return _truncate_middle(
            structured,
            max_chars=max_chars,
            label="compiler diagnostics truncated",
        )

    return _truncate_middle(
        cleaned_log,
        max_chars=max_chars,
        label="compiler fallback log truncated",
    )

def build_error_messages(first_prompt_msg, rust_code, error_log,
                         attempt_history=None, last_k=0):
    """Build error fix messages, optionally including history of prior failed attempts.

    attempt_history: list of {"rust_code": ..., "error_log": ...} dicts from prior attempts.
    last_k: how many prior attempts to include as multi-turn context (0 = fresh 3-message).
    """
    prior = (attempt_history or [])[-last_k:] if last_k > 0 else []

    messages = [first_prompt_msg]
    for entry in prior:
        messages.append({
            "role": "assistant",
            "content": [{"type": "text", "text": f"```rust\n{entry['rust_code']}\n```"}],
        })
        prior_prompt = error_prompt.replace("{{rust_code}}", entry["rust_code"]).replace("{{error_log}}", entry["error_log"])
        messages.append({
            "role": "user",
            "content": [text_content_block(prior_prompt)],
        })

    messages.append({
        "role": "assistant",
        "content": [{"type": "text", "text": f"```rust\n{rust_code}\n```"}],
    })
    prompt = error_prompt.replace("{{rust_code}}", rust_code).replace("{{error_log}}", error_log)
    messages.append({
        "role": "user",
        "content": [text_content_block(prompt)],
    })
    return messages
