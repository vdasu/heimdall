import os
import re
import sys
import time
import signal
import tempfile
import shutil
import argparse
from datetime import datetime

from llm_client import LLMClient, extract_rust_code
from build import (write_rust_source, compile_rust, copy_rust_binary, check_build_prereqs,
                   RUST_SRC_PATH, RUST_OBJ_SRC, RUST_OBJ_DST)
from error_analysis import (summarize_compiler_errors, classify_build_errors,
                            summarize_verifier_rejection, extract_structured_errors,
                            build_error_messages, build_verifier_error_prompt,
                            extract_verifier_feedback,
                            run_kernel_verifier)
from run_log import (LLMCallRecord, CompileAttemptRecord, EquivCheckRecord,
                     RunLog, save_verified_translation, save_failed_run)
from prompts import (
    first_prompt,
    error_prompt,
    safety_fix_prompt,
    equivalence_fix_prompt,
    CONDENSED_TRANSLATION_RULES,
    build_equivalence_fix_user_message,
    text_content_block,
    user_text_message,
)
from safety_policy import analyze_safety, format_safety_report
from verify_equivalence import (
    run_verification,
    prepare_verification,
    generate_c_formula,
    run_verification_rust_only,
)
from generate_formula import extract_entry_symbols

try:
    from counter_example_formatter import heuristic_annotate_helpers
except ImportError:
    from c2rust_translation.counter_example_formatter import heuristic_annotate_helpers

def _error_fingerprint(error_log: str) -> frozenset:
    """Return a frozenset of error codes (E0xxx) found in error_log.

    Used for cycle detection: if the same set of error codes appears on
    two consecutive compile attempts the LLM is looping and needs a
    targeted break-out hint.
    """
    return frozenset(re.findall(r'E\d{4}', error_log))

_CYCLE_BREAK_HINT = """
⚠️  OSCILLATION WARNING: The compiler reported the exact same error codes as
the previous attempt. You are stuck in a loop where fixing one error re-introduces
another. Break out by fixing BOTH issues simultaneously in one response:

  - If you see E0133 / "call to unsafe function": wrap ONLY that specific call
    in `unsafe { }`.
  - If you see E0133 together with "unnecessary `unsafe` block": an unsafe block
    somewhere else is not needed — remove just its `unsafe { }` wrapper while
    keeping the code inside, AND simultaneously add `unsafe { }` around the
    truly-unsafe call.
  - Do NOT revert to an earlier version. Resolve the conflicting requirements
    at the same time in a single edit.
"""

def _evaluate_safety(rust_code, rs_path="generated Rust source"):
    """Return (report, formatted_text, result_label) for a Rust source string."""
    report = analyze_safety(rust_code)
    report_text = format_safety_report(report, rs_path=rs_path)
    result_label = "failed" if report["blocking"] else ("warn_only" if report["warnings"] else "passed")
    return report, report_text, result_label

def _wrap_client_with_dump(client, dump_path):
    """Wrap client.chat so every LLM call appends its full I/O to dump_path."""
    original_chat = client.chat
    call_counter = [0]

    def _format_content(content):
        """Extract plain text from Anthropic-style message content."""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(
                block.get("text", "") for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            )
        return str(content)

    def _escape_for_dump(text):
        """Keep trace file plain-text by escaping embedded NUL bytes."""
        return text.replace("\x00", r"\0")

    def dumping_chat(messages, **kwargs):
        call_counter[0] += 1
        n = call_counter[0]
        result = original_chat(messages, **kwargs)

        with open(dump_path, "a") as f:
            cache_read = getattr(result, "cache_read_input_tokens", getattr(result, "cached_input_tokens", None))
            cache_write = getattr(result, "cache_creation_input_tokens", None)
            raw_in = getattr(result, "raw_input_tokens", None)
            f.write(f"\n{'='*80}\n")
            f.write(f"LLM CALL #{n}  |  {datetime.now().isoformat()}  |  "
                    f"model={client.model}  |  {result.wall_time_s}s  |  "
                    f"in={result.input_tokens}  out={result.output_tokens}  "
                    f"cache_read_in={cache_read}  "
                    f"cache_write_in={cache_write}  "
                    f"uncached_in={getattr(result, 'uncached_input_tokens', None)}  "
                    f"raw_in={raw_in}\n")
            f.write(f"kwargs: {kwargs}\n")
            f.write(f"{'='*80}\n\n")

            for i, msg in enumerate(messages, 1):
                role = msg.get("role", "?")
                text = _format_content(msg.get("content", ""))
                dump_text = _escape_for_dump(text)
                f.write(f"--- MESSAGE {i} [{role}] ({len(text)} chars) ---\n")
                f.write(dump_text)
                f.write("\n\n")

            f.write(f"--- RESPONSE ({len(result.text)} chars) ---\n")
            f.write(_escape_for_dump(result.text))
            f.write(f"\n{'='*80}\n\n")

        return result

    client.chat = dumping_chat

def stage_translate(client, c_source, aya_docs="", run_log=None):
    """Stage 1: Initial C→Rust translation.

    Returns (rust_code, messages).
    """
    prompt_text = first_prompt.replace("{{target_c_code}}", c_source)
    prompt_text = prompt_text.replace("{{aya_api_docs}}", aya_docs)
    messages = [user_text_message(prompt_text, cache=True)]

    llm_result = client.chat(messages, temperature=0.7)
    response = llm_result.text
    rust_code = extract_rust_code(response)

    if run_log:
        run_log.record_llm_call(
            stage="translation", attempt_number=1, equiv_round=0,
            llm_result=llm_result, prompt_text=prompt_text, rust_code=rust_code,
        )

    if not rust_code:
        print("[Stage 1] ERROR: Could not extract Rust code from LLM response. Preview:")
        print(response[:500] if response else "(empty response)")
    messages.append({
        "role": "assistant",
        "content": [{"type": "text", "text": response}],
    })

    print("[Stage 1] Translation complete")
    return rust_code, messages

def stage_compile(
    client,
    rust_code,
    messages,
    max_compile_attempts=10,
    max_verifier_attempts=5,
    kernel_verify_mode="strict",
    aya_docs_path=None,
    run_log=None,
    equiv_round=0,
    last_k_attempts=3,
):
    """Stage 2: Compile with error feedback loop using nested retry loops.

    Outer loop: verifier retries. Inner loop: compile retries.
    Each error fix uses a conversation seeded with the last_k_attempts prior
    (code, error) pairs so the LLM can see what it already tried.

    Returns (success, rust_code, messages).
    """
    kernel_verify_enabled = kernel_verify_mode != "off"
    first_prompt_msg = messages[0] if messages else None

    for verifier_attempt in range(max(max_verifier_attempts, 1)):

        compiled = False
        compile_history = []
        for compile_attempt in range(max_compile_attempts):
            if not rust_code or not rust_code.strip():
                print(f"[Stage 2] Compile attempt {compile_attempt + 1}: empty code, skipping compile")
                if run_log:
                    run_log.record_compile_attempt(
                        attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                        rust_code="", compile_success=False, build_log="(empty code)",
                        compile_wall_time_s=0.0,
                    )
                return False, rust_code, messages
            write_rust_source(rust_code)
            t0 = time.monotonic()
            success, build_log = compile_rust()
            compile_wall = time.monotonic() - t0

            if not success:
                if (
                    "cargo not found in PATH" in build_log
                    or "failed to execute cargo" in build_log
                ):
                    print("[Stage 2] Toolchain error: cargo is unavailable; cannot compile.")
                    print(build_log)
                    if run_log:
                        run_log.record_compile_attempt(
                            attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                            rust_code=rust_code, compile_success=False, build_log=build_log,
                            compile_wall_time_s=compile_wall,
                        )
                    return False, rust_code, messages

                if (
                    "rust/library/Cargo.lock\" does not exist" in build_log
                    or "rustup component add rust-src" in build_log
                    or "missing rust-src" in build_log.lower()
                ):
                    print("[Stage 2] Toolchain error: nightly rust-src is missing.")
                    print(build_log)
                    if run_log:
                        run_log.record_compile_attempt(
                            attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                            rust_code=rust_code, compile_success=False, build_log=build_log,
                            compile_wall_time_s=compile_wall,
                        )
                    return False, rust_code, messages

                if run_log:
                    run_log.record_compile_attempt(
                        attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                        rust_code=rust_code, compile_success=False, build_log=build_log,
                        compile_wall_time_s=compile_wall,
                    )

                error_log = extract_structured_errors(build_log, max_chars=24_000)

                print(
                    f"[Stage 2] Compile attempt {compile_attempt + 1}/{max_compile_attempts} "
                    f"(verifier round {verifier_attempt + 1}): compiler errors:"
                )
                print(error_log)

                if aya_docs_path:
                    from aya_doc_extractor import extract_docs_for_error
                    api_docs = extract_docs_for_error(rust_code, build_log, aya_docs_path)
                    if api_docs:
                        error_log = f"{error_log}\n\n{api_docs}"

                compile_history.append({"rust_code": rust_code, "error_log": error_log})

                fp = _error_fingerprint(error_log)
                cycling = (
                    len(compile_history) >= 2
                    and fp == _error_fingerprint(compile_history[-2]["error_log"])
                    and len(fp) > 0
                )
                if cycling:
                    print(f"[Stage 2] ⚠️  Cycle detected (same errors as attempt {compile_attempt}); injecting break-out hint.")
                    error_log = error_log + _CYCLE_BREAK_HINT
                compile_temperature = 0.7 if cycling else 0.3

                prompt_text = error_log
                if first_prompt_msg:
                    messages = build_error_messages(
                        first_prompt_msg, rust_code, error_log,
                        attempt_history=compile_history[:-1],
                        last_k=max(0, last_k_attempts - 1),
                    )
                else:
                    prompt = error_prompt.replace("{{rust_code}}", rust_code).replace("{{error_log}}", error_log)
                    prompt_text = prompt
                    messages = [user_text_message(prompt, cache=True)]

                llm_result = client.chat(messages, temperature=compile_temperature)
                response = llm_result.text
                rust_code = extract_rust_code(response)

                if run_log:
                    run_log.record_llm_call(
                        stage="compile_fix", attempt_number=compile_attempt + 1,
                        equiv_round=equiv_round, llm_result=llm_result,
                        prompt_text=prompt_text, rust_code=rust_code,
                    )

                messages.append({
                    "role": "assistant",
                    "content": [{"type": "text", "text": response}],
                })
                continue

            print(
                f"[Stage 2] Compiled successfully on compile attempt {compile_attempt + 1} "
                f"(verifier round {verifier_attempt + 1})"
            )
            compiled = True
            break

        if not compiled:
            print(
                f"[Stage 2] FAILED: Could not compile after {max_compile_attempts} attempts "
                f"(verifier round {verifier_attempt + 1})"
            )
            return False, rust_code, messages

        kernel_verify_run = False
        kernel_verify_result = None
        verifier_log = ""
        verifier_wall = 0.0

        if kernel_verify_enabled:
            print("[Stage 2] Running kernel verifier on compiled Rust bytecode...")
            t0 = time.monotonic()
            kv_ok, kv_out, kv_status = run_kernel_verifier(RUST_OBJ_SRC, verbose=True)
            verifier_wall = time.monotonic() - t0
            kernel_verify_run = True
            kernel_verify_result = "accepted" if kv_ok else kv_status
            verifier_log = kv_out or ""

            if kv_ok:
                print("[Stage 2] Kernel verifier accepted the program")
            elif kv_status == "permission":
                msg = (
                    "[Stage 2] Kernel verifier unavailable due to permissions "
                    "(need CAP_BPF/root)."
                )
                if kv_out:
                    print("[Stage 2] Kernel verifier summary:")
                    print(summarize_verifier_rejection(kv_out))
                if kernel_verify_mode == "warn":
                    print(f"{msg} Continuing without kernel-verifier gate (warn mode).")
                else:
                    if run_log:
                        run_log.record_compile_attempt(
                            attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                            rust_code=rust_code, compile_success=True, build_log=build_log,
                            compile_wall_time_s=compile_wall,
                            kernel_verify_run=True, kernel_verify_result=kernel_verify_result,
                            verifier_log=verifier_log, verifier_wall_time_s=verifier_wall,
                        )
                    print(f"{msg} Failing in strict mode.")
                    return False, rust_code, messages
            else:
                if run_log:
                    run_log.record_compile_attempt(
                        attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                        rust_code=rust_code, compile_success=True, build_log=build_log,
                        compile_wall_time_s=compile_wall,
                        kernel_verify_run=True, kernel_verify_result=kernel_verify_result,
                        verifier_log=verifier_log, verifier_wall_time_s=verifier_wall,
                    )

                print(
                    f"[Stage 2] Verifier round {verifier_attempt + 1}/{max_verifier_attempts}: "
                    "kernel verifier rejected bytecode, sending verifier log to LLM..."
                )
                summary = summarize_verifier_rejection(kv_out)
                print("[Stage 2] Kernel verifier summary:")
                print(summary)

                verifier_context = extract_verifier_feedback(kv_out, max_chars=24_000)

                if aya_docs_path:
                    from aya_doc_extractor import extract_docs_for_error
                    api_docs = extract_docs_for_error(rust_code, kv_out, aya_docs_path)
                    if api_docs:
                        verifier_context = f"{verifier_context}\n\n{api_docs}"

                verifier_prompt = build_verifier_error_prompt(verifier_context)
                if first_prompt_msg:
                    messages = [
                        first_prompt_msg,
                        {
                            "role": "assistant",
                            "content": [{"type": "text", "text": f"```rust\n{rust_code}\n```"}],
                        },
                        {
                            "role": "user",
                            "content": [text_content_block(verifier_prompt)],
                        },
                    ]
                else:
                    messages = [user_text_message(verifier_prompt, cache=True)]

                llm_result = client.chat(messages, temperature=0.5)
                response = llm_result.text
                rust_code = extract_rust_code(response)

                if run_log:
                    run_log.record_llm_call(
                        stage="verifier_fix", attempt_number=verifier_attempt + 1,
                        equiv_round=equiv_round, llm_result=llm_result,
                        prompt_text=verifier_prompt, rust_code=rust_code,
                    )

                messages.append({
                    "role": "assistant",
                    "content": [{"type": "text", "text": response}],
                })
                continue

        report, safety_report, safety_result = _evaluate_safety(rust_code)
        if report["blocking"]:
            print("[Stage 2] Safety checker rejected the source; sending report to LLM...")
            print(safety_report)
            if run_log:
                run_log.record_compile_attempt(
                    attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                    rust_code=rust_code, compile_success=True, build_log=build_log,
                    compile_wall_time_s=compile_wall,
                    kernel_verify_run=kernel_verify_run, kernel_verify_result=kernel_verify_result,
                    verifier_log=verifier_log, verifier_wall_time_s=verifier_wall,
                    safety_run=True, safety_result=safety_result, safety_log=safety_report,
                )

            safety_context = safety_report
            if aya_docs_path:
                from aya_doc_extractor import extract_docs_for_error
                api_docs = extract_docs_for_error(rust_code, safety_report, aya_docs_path)
                if api_docs:
                    safety_context = f"{safety_context}\n\n{api_docs}"

            safety_prompt = safety_fix_prompt\
                .replace("{{rust_code}}", rust_code)\
                .replace("{{safety_report}}", safety_context)
            if first_prompt_msg:
                messages = [
                    first_prompt_msg,
                    {
                        "role": "assistant",
                        "content": [{"type": "text", "text": f"```rust\n{rust_code}\n```"}],
                    },
                    {
                        "role": "user",
                        "content": [text_content_block(safety_prompt)],
                    },
                ]
            else:
                messages = [user_text_message(safety_prompt, cache=True)]

            llm_result = client.chat(messages, temperature=0.3)
            response = llm_result.text
            rust_code = extract_rust_code(response)

            if run_log:
                run_log.record_llm_call(
                    stage="safety_fix", attempt_number=compile_attempt + 1,
                    equiv_round=equiv_round, llm_result=llm_result,
                    prompt_text=safety_prompt, rust_code=rust_code,
                )

            messages.append({
                "role": "assistant",
                "content": [{"type": "text", "text": response}],
            })
            continue

        if report["warnings"]:
            print(safety_report)
        else:
            print("[Stage 2] Safety checker passed.")

        if run_log:
            run_log.record_compile_attempt(
                attempt_in_stage=compile_attempt + 1, equiv_round=equiv_round,
                rust_code=rust_code, compile_success=True, build_log=build_log,
                compile_wall_time_s=compile_wall,
                kernel_verify_run=kernel_verify_run, kernel_verify_result=kernel_verify_result,
                verifier_log=verifier_log, verifier_wall_time_s=verifier_wall,
                safety_run=True, safety_result=safety_result, safety_log=safety_report,
            )

        return True, rust_code, messages

    print(
        f"[Stage 2] FAILED: Could not pass kernel verification "
        f"after {max_verifier_attempts} verifier rounds"
    )
    return False, rust_code, messages

def stage_verify(
    c_obj_path,
    rust_obj_path,
    c_entry_symbol,
    rust_entry_symbol,
    map_specs,
    helper_fail_mode="off",
    helper_fail_helpers=None,
    run_log=None,
    equiv_round=0,
    pkt_size=None,
    preflight_vctx=None,
    max_steps=50000,
):
    """Stage 3: Symbolic equivalence check (initial, generates both formulas).

    If preflight_vctx is provided (with a cached C formula from preflight),
    it is reused to avoid regenerating the C formula.

    Returns (VerificationResult, VerificationContext).
    """
    print("[Stage 3] Running symbolic equivalence verification...")

    if preflight_vctx is not None and preflight_vctx.c_formula is not None:
        vctx = preflight_vctx
        print("[Stage 3] Reusing C formula from preflight.")
    else:

        vctx = prepare_verification(
            c_obj_path,
            map_specs,
            helper_fail_mode=helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers,
            pkt_size=pkt_size,
        )
        err = generate_c_formula(vctx, c_obj_path, c_entry_symbol)
        if err is not None:
            if run_log:
                run_log.record_equiv_check(equiv_round=equiv_round, result="error")
            return err, vctx

    t0 = time.monotonic()
    result = run_verification_rust_only(vctx, rust_obj_path, rust_entry_symbol)
    verify_wall = time.monotonic() - t0

    if run_log:
        res_str = "equivalent" if result.equivalent else (result.result_type or "mismatch")
        ce = getattr(result, "counter_example", "") or ""
        run_log.record_equiv_check(
            equiv_round=equiv_round, result=res_str,
            counter_example=ce, wall_time_s=verify_wall,
        )

    return result, vctx

def stage_fix_equivalence(client, c_source, rust_code, verification_result,
                          messages, vctx, rust_entry_symbol,
                          max_attempts=5, max_compile_retries=10,
                          max_verifier_retries=5,
                          kernel_verify_mode="strict", aya_docs_path=None,
                          run_log=None, last_k_attempts=3):
    """Stage 3b: Fix equivalence issues with LLM feedback loop.

    Uses cached C formula from vctx to avoid re-generating it each iteration.
    Returns (success, rust_code, messages).
    """
    result = verification_result

    for attempt in range(max_attempts):
        print(f"\n[Stage 3b] Equivalence fix attempt {attempt + 1}/{max_attempts}")

        annotated_rust = rust_code
        sv_values = getattr(result, "shared_var_values", None)
        if sv_values:
            try:
                annotated_rust = heuristic_annotate_helpers(rust_code, sv_values)
            except Exception as e:
                print(f"[!] Helper annotation failed (non-fatal): {e}")

        prompt = CONDENSED_TRANSLATION_RULES + "\n" + equivalence_fix_prompt\
            .replace("{{c_source}}", c_source)\
            .replace("{{rust_source}}", annotated_rust)\
            .replace("{{counter_example}}", result.counter_example)

        eq_messages = [
            build_equivalence_fix_user_message(
                c_source,
                annotated_rust,
                result.counter_example,
            )
        ]

        llm_result = client.chat(eq_messages, temperature=0.5)
        response = llm_result.text
        rust_code = extract_rust_code(response)

        if run_log:
            run_log.record_llm_call(
                stage="equiv_fix", attempt_number=attempt + 1,
                equiv_round=attempt + 1, llm_result=llm_result,
                prompt_text=prompt, rust_code=rust_code,
            )

        eq_messages.append({
            "role": "assistant",
            "content": [{"type": "text", "text": response}],
        })

        compile_ok, rust_code, eq_messages = stage_compile(
            client,
            rust_code,
            eq_messages,
            max_compile_attempts=max_compile_retries,
            max_verifier_attempts=max_verifier_retries,
            kernel_verify_mode=kernel_verify_mode,
            aya_docs_path=aya_docs_path,
            run_log=run_log,
            equiv_round=attempt + 1,
            last_k_attempts=last_k_attempts,
        )
        messages = eq_messages
        if not compile_ok:
            print("[Stage 3b] Could not compile equivalence fix, aborting")
            return False, rust_code, messages

        copy_ok, copy_err = copy_rust_binary()
        if not copy_ok:
            print(f"[Stage 3b] Could not copy compiled binary: {copy_err}")
            return False, rust_code, messages

        print("[Stage 3b] Re-verifying (reusing cached C formula)...")
        t0 = time.monotonic()
        result = run_verification_rust_only(vctx, RUST_OBJ_DST, rust_entry_symbol)
        verify_wall = time.monotonic() - t0

        if run_log:
            res_str = "equivalent" if result.equivalent else (result.result_type or "mismatch")
            ce = getattr(result, "counter_example", "") or ""
            run_log.record_equiv_check(
                equiv_round=attempt + 1, result=res_str,
                counter_example=ce, wall_time_s=verify_wall,
            )

        if result.equivalent:
            print(f"[Stage 3b] Equivalence achieved on attempt {attempt + 1}!")
            return True, rust_code, messages

        print(f"[Stage 3b] Still not equivalent: {result.result_type}")

    print(f"[Stage 3b] FAILED: Could not achieve equivalence after {max_attempts} attempts")
    return False, rust_code, messages

def _copy_dump_to_archive(dump_path, out_dir):
    """Copy the LLM I/O dump file into the archive directory, then delete the temp file."""
    if not dump_path or not out_dir:
        return
    try:
        dest = os.path.join(out_dir, "llm_io_dump.txt")
        shutil.copy2(dump_path, dest)
    except Exception:
        pass
    try:
        os.unlink(dump_path)
    except Exception:
        pass

def main(c_file_path, c_ebpf_obj_path, entry_symbol, map_specs,
         provider="anthropic", model=None, skip_translation=False,
         max_compile_retries=10, max_verifier_retries=5, max_equiv_retries=5,
         kernel_verify_mode="strict", base_url=None, api_key=None,
         inject_docs=False, aya_docs_path=None,
         run_tag=None, rust_entry_symbol=None,
         helper_fail_mode="off", helper_fail_helpers=None,
         pkt_size=None, last_k_compile_attempts=3):

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    client = LLMClient(provider, model, base_url=base_url, api_key=api_key)

    rust_entry_symbol = rust_entry_symbol or entry_symbol
    helper_fail_helpers = helper_fail_helpers or []

    _dump_fd, _dump_path = tempfile.mkstemp(suffix=".llm_io.txt", prefix="c2rust_")
    os.close(_dump_fd)
    os.chmod(_dump_path, 0o644)
    with open(_dump_path, "w") as f:
        f.write(f"# LLM I/O Dump — {datetime.now().isoformat()}\n")
        f.write(f"# Provider: {provider}  Model: {client.model}\n")
        f.write(f"# Anthropic prompt cache TTL: {os.environ.get('ANTHROPIC_CACHE_TTL', '5m')}\n")
        f.write(
            f"# C source: {c_file_path}  C Entry: {entry_symbol}  "
            f"Rust Entry: {rust_entry_symbol}\n"
        )
        f.write(
            f"# Helper fail mode: {helper_fail_mode}  "
            f"helpers: {','.join(helper_fail_helpers) if helper_fail_helpers else '(none)'}\n\n"
        )
    _wrap_client_with_dump(client, _dump_path)

    args_dict = {
        "c_file": c_file_path, "c_binary": c_ebpf_obj_path,
        "entry_symbol": entry_symbol, "map_specs": map_specs,
        "rust_entry_symbol": rust_entry_symbol,
        "provider": provider, "model": client.model,
        "skip_translation": skip_translation,
        "helper_fail_mode": helper_fail_mode,
        "helper_fail_helpers": helper_fail_helpers,
        "anthropic_cache_ttl": os.environ.get("ANTHROPIC_CACHE_TTL", "5m"),
        "max_compile_retries": max_compile_retries,
        "max_verifier_retries": max_verifier_retries,
        "max_equiv_retries": max_equiv_retries,
        "last_k_compile_attempts": last_k_compile_attempts,
        "kernel_verify_mode": kernel_verify_mode,
        "inject_docs": inject_docs,
        "run_tag": run_tag,
    }
    run_log = RunLog(
        provider=provider, model=client.model,
        c_source_file=c_file_path, entry_symbol=entry_symbol,
        map_specs=map_specs, args_dict=args_dict,
    )

    with open(c_file_path, "r") as f:
        c_source = f.read()
    run_log.c_source_chars = len(c_source)
    run_log.c_source_lines = c_source.count('\n') + 1

    rust_code = ""
    messages = []

    try:
        prereq_ok, prereq_msg = check_build_prereqs()
        if not prereq_ok:
            run_log.result = "compile_failed"
            print("[Preflight] FAILED: Rust build prerequisites are not satisfied.")
            print(prereq_msg)
            return False

        if kernel_verify_mode != "off":
            print("[Preflight] Verifying C object with kernel verifier...")
            kv_ok, kv_out, kv_status = run_kernel_verifier(
                c_ebpf_obj_path, verbose=False
            )
            if not kv_ok:
                if kv_status == "permission":
                    print(
                        "[Preflight] Kernel verifier unavailable (permissions); "
                        "skipping C preflight check."
                    )
                else:
                    run_log.result = "c_kernel_verify_failed"
                    print(
                        "[Preflight] FAILED: C object does not pass kernel "
                        "verifier — aborting before LLM translation."
                    )
                    if kv_out:
                        print(kv_out)
                    return False
            else:
                print("[Preflight] C object passed kernel verifier.")

        print("[Preflight] Generating C formula (symbolic execution)...")
        preflight_vctx = prepare_verification(
            c_ebpf_obj_path, map_specs,
            helper_fail_mode=helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers,
            pkt_size=pkt_size,
        )
        preflight_err = generate_c_formula(
            preflight_vctx, c_ebpf_obj_path, entry_symbol
        )
        if preflight_err is not None:
            run_log.result = "c_formula_failed"
            print(
                "[Preflight] FAILED: Could not generate C formula — "
                "aborting before LLM translation."
            )
            if hasattr(preflight_err, 'counter_example') and preflight_err.counter_example:
                print(preflight_err.counter_example)
            return False
        print("[Preflight] C formula generated successfully.")

        if skip_translation:
            print("Skipping translation (reusing existing Rust code)")
            with open(RUST_SRC_PATH, "r") as f:
                rust_code = f.read()

            t0 = time.monotonic()
            success, build_log = compile_rust()
            compile_wall = time.monotonic() - t0
            if not success:
                run_log.result = "compile_failed"
                print("FAILED: Could not compile existing Rust source in --skip-translation mode")
                if build_log:
                    print("[Stage 2] Compiler errors:")
                    print(extract_structured_errors(build_log))
                return False

            kernel_verify_run = False
            kernel_verify_result = None
            verifier_log = ""
            verifier_wall = 0.0
            if kernel_verify_mode != "off":
                print("[Stage 2] Running kernel verifier on existing Rust bytecode...")
                t0 = time.monotonic()
                kv_ok, kv_out, kv_status = run_kernel_verifier(RUST_OBJ_SRC, verbose=True)
                verifier_wall = time.monotonic() - t0
                kernel_verify_run = True
                kernel_verify_result = "accepted" if kv_ok else kv_status
                verifier_log = kv_out or ""
                if not kv_ok:
                    if kv_status == "permission" and kernel_verify_mode == "warn":
                        print(
                            "[Stage 2] Kernel verifier unavailable due to permissions "
                            "(warn mode); continuing."
                        )
                    else:
                        run_log.result = "kernel_verify_failed"
                        print("[Stage 2] FAILED: Kernel verifier rejected the program")
                        if kv_out:
                            print("[Stage 2] Kernel verifier summary:")
                            print(summarize_verifier_rejection(kv_out))
                            print(kv_out)
                        return False

            report, safety_report, safety_result = _evaluate_safety(rust_code, rs_path=RUST_SRC_PATH)
            print(safety_report)
            run_log.record_compile_attempt(
                attempt_in_stage=1, equiv_round=0,
                rust_code=rust_code, compile_success=True, build_log=build_log,
                compile_wall_time_s=compile_wall,
                kernel_verify_run=kernel_verify_run, kernel_verify_result=kernel_verify_result,
                verifier_log=verifier_log, verifier_wall_time_s=verifier_wall,
                safety_run=True, safety_result=safety_result, safety_log=safety_report,
            )
            if report["blocking"]:
                run_log.result = "compile_failed"
                print("FAILED: Existing Rust source violates the safety policy in --skip-translation mode")
                return False

            copy_ok, copy_err = copy_rust_binary()
            if not copy_ok:
                run_log.result = "copy_failed"
                print(f"FAILED: Could not copy compiled Rust object: {copy_err}")
                return False
        else:

            aya_docs = ""
            if inject_docs:
                if not aya_docs_path:
                    print("[Warning] --inject-docs requires --aya-docs-path or AYA_DOCS_PATH env var; skipping doc injection")
                else:
                    from aya_doc_extractor import extract_relevant_docs
                    aya_docs = extract_relevant_docs(c_source, aya_docs_path)
                    print(f"[*] Injected {len(aya_docs)} chars of Aya API docs into prompt")

            t0 = time.monotonic()
            rust_code, messages = stage_translate(client, c_source, aya_docs=aya_docs, run_log=run_log)
            run_log.stage_timings["translate"] = round(time.monotonic() - t0, 2)

            t0 = time.monotonic()
            success, rust_code, messages = stage_compile(
                client,
                rust_code,
                messages,
                max_compile_attempts=max_compile_retries,
                max_verifier_attempts=max_verifier_retries,
                kernel_verify_mode=kernel_verify_mode,
                aya_docs_path=aya_docs_path if inject_docs else None,
                run_log=run_log,
                last_k_attempts=last_k_compile_attempts,
            )
            run_log.stage_timings["compile"] = round(time.monotonic() - t0, 2)
            if not success:
                run_log.result = "compile_failed"
                print("FAILED: Could not compile and pass kernel verification after retries")
                return False

            copy_ok, copy_err = copy_rust_binary()
            if not copy_ok:
                run_log.result = "copy_failed"
                print(f"FAILED: Could not copy compiled Rust object: {copy_err}")
                return False

        t0 = time.monotonic()
        result, vctx = stage_verify(
            c_ebpf_obj_path,
            RUST_OBJ_DST,
            entry_symbol,
            rust_entry_symbol,
            map_specs,
            helper_fail_mode=helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers,
            run_log=run_log,
            pkt_size=pkt_size,
            preflight_vctx=preflight_vctx,
        )
        run_log.stage_timings["verify"] = round(time.monotonic() - t0, 2)

        if result.equivalent:
            run_log.result = "equivalent"
            print("\nSUCCESS: Programs are equivalent!")
            out_dir = save_verified_translation(c_file_path, rust_code, entry_symbol, map_specs, run_log)
            _copy_dump_to_archive(_dump_path, out_dir)
            return True

        if result.result_type == "error":
            run_log.result = "equivalence_failed"
            print("\nFAILED: Could not complete symbolic equivalence check")
            if result.counter_example:
                print(result.counter_example)
            return False

        t0 = time.monotonic()
        success, rust_code, messages = stage_fix_equivalence(
            client, c_source, rust_code, result, messages,
            vctx, rust_entry_symbol,
            max_attempts=max_equiv_retries,
            max_compile_retries=max_compile_retries,
            max_verifier_retries=max_verifier_retries,
            kernel_verify_mode=kernel_verify_mode,
            aya_docs_path=aya_docs_path if inject_docs else None,
            run_log=run_log,
            last_k_attempts=last_k_compile_attempts,
        )
        run_log.stage_timings["fix_equivalence"] = round(time.monotonic() - t0, 2)

        if success:
            run_log.result = "equivalent_after_fixes"
            print("\nSUCCESS: Programs are equivalent after fixes!")
            out_dir = save_verified_translation(c_file_path, rust_code, entry_symbol, map_specs, run_log)
            _copy_dump_to_archive(_dump_path, out_dir)
        else:
            run_log.result = "equivalence_failed"
            print("\nFAILED: Could not achieve equivalence after retries")
        return success

    finally:

        if run_log.result in ("unknown", "compile_failed", "copy_failed",
                               "kernel_verify_failed", "equivalence_failed"):
            out_dir = save_failed_run(c_file_path, rust_code, entry_symbol, map_specs, run_log)
            _copy_dump_to_archive(_dump_path, out_dir)

def main_multi(c_file_path, c_ebpf_obj_path, entry_symbols, map_specs,
               provider="anthropic", model=None, skip_translation=False,
               max_compile_retries=10, max_verifier_retries=5, max_equiv_retries=5,
               kernel_verify_mode="strict", base_url=None, api_key=None,
               inject_docs=False, aya_docs_path=None,
               run_tag=None,
               helper_fail_mode="off", helper_fail_helpers=None,
               pkt_size=None, last_k_compile_attempts=3):
    """Translate once, then verify each entry point in the C binary.

    Stages 1+2 run once (whole file). Stage 3 runs per-entry.
    If any entry fails verification, the fix loop targets that entry.
    After all fix loops, a re-verification pass catches regressions.
    """

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    client = LLMClient(provider, model, base_url=base_url, api_key=api_key)
    helper_fail_helpers = helper_fail_helpers or []

    _dump_fd, _dump_path = tempfile.mkstemp(suffix=".llm_io.txt", prefix="c2rust_multi_")
    os.close(_dump_fd)
    os.chmod(_dump_path, 0o644)
    with open(_dump_path, "w") as f:
        f.write(f"# LLM I/O Dump (multi-entry) — {datetime.now().isoformat()}\n")
        f.write(f"# Provider: {provider}  Model: {client.model}\n")
        f.write(f"# Anthropic prompt cache TTL: {os.environ.get('ANTHROPIC_CACHE_TTL', '5m')}\n")
        f.write(f"# C source: {c_file_path}  Entries: {entry_symbols}\n")
        f.write(f"# Helper fail mode: {helper_fail_mode}  "
                f"helpers: {','.join(helper_fail_helpers) if helper_fail_helpers else '(none)'}\n\n")
    _wrap_client_with_dump(client, _dump_path)

    args_dict = {
        "c_file": c_file_path, "c_binary": c_ebpf_obj_path,
        "entry_symbols": entry_symbols, "map_specs": map_specs,
        "provider": provider, "model": client.model,
        "skip_translation": skip_translation,
        "helper_fail_mode": helper_fail_mode,
        "helper_fail_helpers": helper_fail_helpers,
        "anthropic_cache_ttl": os.environ.get("ANTHROPIC_CACHE_TTL", "5m"),
        "max_compile_retries": max_compile_retries,
        "max_verifier_retries": max_verifier_retries,
        "max_equiv_retries": max_equiv_retries,
        "last_k_compile_attempts": last_k_compile_attempts,
        "kernel_verify_mode": kernel_verify_mode,
        "inject_docs": inject_docs,
        "run_tag": run_tag,
        "all_entries": True,
    }
    run_log = RunLog(
        provider=provider, model=client.model,
        c_source_file=c_file_path, entry_symbol="all",
        map_specs=map_specs, args_dict=args_dict,
    )
    run_log.entry_symbols = entry_symbols

    with open(c_file_path, "r") as f:
        c_source = f.read()
    run_log.c_source_chars = len(c_source)
    run_log.c_source_lines = c_source.count('\n') + 1

    rust_code = ""
    messages = []

    try:
        prereq_ok, prereq_msg = check_build_prereqs()
        if not prereq_ok:
            run_log.result = "compile_failed"
            print("[Preflight] FAILED: Rust build prerequisites are not satisfied.")
            print(prereq_msg)
            return False

        if kernel_verify_mode != "off":
            print("[Preflight] Verifying C object with kernel verifier...")
            kv_ok, kv_out, kv_status = run_kernel_verifier(
                c_ebpf_obj_path, verbose=False
            )
            if not kv_ok:
                if kv_status == "permission":
                    print(
                        "[Preflight] Kernel verifier unavailable (permissions); "
                        "skipping C preflight check."
                    )
                else:
                    run_log.result = "c_kernel_verify_failed"
                    print(
                        "[Preflight] FAILED: C object does not pass kernel "
                        "verifier — aborting before LLM translation."
                    )
                    if kv_out:
                        print(kv_out)
                    return False
            else:
                print("[Preflight] C object passed kernel verifier.")

        print(f"[Preflight] Generating C formulas for {len(entry_symbols)} entries...")
        preflight_vctx = prepare_verification(
            c_ebpf_obj_path, map_specs,
            helper_fail_mode=helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers,
            pkt_size=pkt_size,
        )
        for entry_sym in entry_symbols:
            preflight_vctx.c_formula = None
            preflight_vctx.c_program_data = None
            preflight_err = generate_c_formula(
                preflight_vctx, c_ebpf_obj_path, entry_sym
            )
            if preflight_err is not None:
                run_log.result = "c_formula_failed"
                print(
                    f"[Preflight] FAILED: Could not generate C formula for "
                    f"entry '{entry_sym}' — aborting before LLM translation."
                )
                if hasattr(preflight_err, 'counter_example') and preflight_err.counter_example:
                    print(preflight_err.counter_example)
                return False
        print("[Preflight] All C formulas generated successfully.")

        if skip_translation:
            print("Skipping translation (reusing existing Rust code)")
            with open(RUST_SRC_PATH, "r") as f:
                rust_code = f.read()

            t0 = time.monotonic()
            success, build_log = compile_rust()
            compile_wall = time.monotonic() - t0
            if not success:
                run_log.result = "compile_failed"
                print("FAILED: Could not compile existing Rust source in --skip-translation mode")
                if build_log:
                    print("[Stage 2] Compiler errors:")
                    from error_analysis import extract_structured_errors
                    print(extract_structured_errors(build_log))
                return False

            kernel_verify_run = False
            kernel_verify_result = None
            verifier_log = ""
            verifier_wall = 0.0
            if kernel_verify_mode != "off":
                print("[Stage 2] Running kernel verifier on existing Rust bytecode...")
                t0 = time.monotonic()
                kv_ok, kv_out, kv_status = run_kernel_verifier(RUST_OBJ_SRC, verbose=True)
                verifier_wall = time.monotonic() - t0
                kernel_verify_run = True
                kernel_verify_result = "accepted" if kv_ok else kv_status
                verifier_log = kv_out or ""
                if not kv_ok:
                    if kv_status == "permission" and kernel_verify_mode == "warn":
                        print("[Stage 2] Kernel verifier unavailable (warn mode); continuing.")
                    else:
                        run_log.result = "kernel_verify_failed"
                        print("[Stage 2] FAILED: Kernel verifier rejected the program")
                        if kv_out:
                            print(summarize_verifier_rejection(kv_out))
                        return False

            report, safety_report, safety_result = _evaluate_safety(rust_code, rs_path=RUST_SRC_PATH)
            print(safety_report)
            run_log.record_compile_attempt(
                attempt_in_stage=1, equiv_round=0,
                rust_code=rust_code, compile_success=True, build_log=build_log,
                compile_wall_time_s=compile_wall,
                kernel_verify_run=kernel_verify_run, kernel_verify_result=kernel_verify_result,
                verifier_log=verifier_log, verifier_wall_time_s=verifier_wall,
                safety_run=True, safety_result=safety_result, safety_log=safety_report,
            )
            if report["blocking"]:
                run_log.result = "compile_failed"
                print("FAILED: Existing Rust source violates the safety policy in --skip-translation mode")
                return False

            copy_ok, copy_err = copy_rust_binary()
            if not copy_ok:
                run_log.result = "copy_failed"
                print(f"FAILED: Could not copy compiled Rust object: {copy_err}")
                return False
        else:
            aya_docs = ""
            if inject_docs:
                if not aya_docs_path:
                    print("[Warning] --inject-docs requires --aya-docs-path; skipping")
                else:
                    from aya_doc_extractor import extract_relevant_docs
                    aya_docs = extract_relevant_docs(c_source, aya_docs_path)
                    print(f"[*] Injected {len(aya_docs)} chars of Aya API docs into prompt")

            t0 = time.monotonic()
            rust_code, messages = stage_translate(client, c_source, aya_docs=aya_docs, run_log=run_log)
            run_log.stage_timings["translate"] = round(time.monotonic() - t0, 2)

            t0 = time.monotonic()
            success, rust_code, messages = stage_compile(
                client, rust_code, messages,
                max_compile_attempts=max_compile_retries,
                max_verifier_attempts=max_verifier_retries,
                kernel_verify_mode=kernel_verify_mode,
                aya_docs_path=aya_docs_path if inject_docs else None,
                run_log=run_log,
                last_k_attempts=last_k_compile_attempts,
            )
            run_log.stage_timings["compile"] = round(time.monotonic() - t0, 2)
            if not success:
                run_log.result = "compile_failed"
                print("FAILED: Could not compile after retries")
                return False

            copy_ok, copy_err = copy_rust_binary()
            if not copy_ok:
                run_log.result = "copy_failed"
                print(f"FAILED: Could not copy compiled Rust object: {copy_err}")
                return False

        print(f"\n[Multi-entry] Verifying {len(entry_symbols)} entry points...")

        vctx = prepare_verification(
            c_ebpf_obj_path, map_specs,
            helper_fail_mode=helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers,
            pkt_size=pkt_size,
        )

        entry_results = {}
        any_fix_applied = False

        t0_verify_all = time.monotonic()

        for entry_symbol in entry_symbols:
            print(f"\n{'='*60}")
            print(f"  [Multi-entry] Verifying entry: {entry_symbol}")
            print(f"{'='*60}")

            vctx.c_formula = None
            vctx.c_program_data = None

            err = generate_c_formula(vctx, c_ebpf_obj_path, entry_symbol)
            if err is not None:
                print(f"[Multi-entry] ERROR generating C formula for {entry_symbol}")
                entry_results[entry_symbol] = "error"
                if run_log:
                    run_log.record_equiv_check(equiv_round=0, result="error")
                continue

            t0 = time.monotonic()
            result = run_verification_rust_only(vctx, RUST_OBJ_DST, entry_symbol)
            verify_wall = time.monotonic() - t0

            if run_log:
                res_str = "equivalent" if result.equivalent else (result.result_type or "mismatch")
                ce = getattr(result, "counter_example", "") or ""
                run_log.record_equiv_check(
                    equiv_round=0, result=res_str,
                    counter_example=ce, wall_time_s=verify_wall,
                )

            if result.equivalent:
                print(f"[Multi-entry] {entry_symbol}: EQUIVALENT")
                entry_results[entry_symbol] = "equivalent"
                continue

            if result.result_type == "error":
                print(f"[Multi-entry] {entry_symbol}: ERROR during verification")
                entry_results[entry_symbol] = "error"
                continue

            print(f"[Multi-entry] {entry_symbol}: mismatch, entering fix loop...")
            t0_fix = time.monotonic()
            fix_ok, rust_code, messages = stage_fix_equivalence(
                client, c_source, rust_code, result, messages,
                vctx, entry_symbol,
                max_attempts=max_equiv_retries,
                max_compile_retries=max_compile_retries,
                max_verifier_retries=max_verifier_retries,
                kernel_verify_mode=kernel_verify_mode,
                aya_docs_path=aya_docs_path if inject_docs else None,
                run_log=run_log,
                last_k_attempts=last_k_compile_attempts,
            )
            run_log.stage_timings[f"fix_equivalence_{entry_symbol}"] = round(
                time.monotonic() - t0_fix, 2
            )

            if fix_ok:
                print(f"[Multi-entry] {entry_symbol}: EQUIVALENT after fixes")
                entry_results[entry_symbol] = "equivalent"
                any_fix_applied = True
            else:
                print(f"[Multi-entry] {entry_symbol}: FAILED after fix loop")
                entry_results[entry_symbol] = "failed"

        if any_fix_applied:
            passing_entries = [
                sym for sym, res in entry_results.items() if res == "equivalent"
            ]
            if passing_entries:
                print(f"\n[Multi-entry] Re-verifying {len(passing_entries)} "
                      f"previously-passing entries against final binary...")
                for entry_symbol in passing_entries:
                    vctx.c_formula = None
                    vctx.c_program_data = None

                    err = generate_c_formula(vctx, c_ebpf_obj_path, entry_symbol)
                    if err is not None:
                        print(f"[Re-verify] {entry_symbol}: ERROR generating C formula")
                        entry_results[entry_symbol] = "regressed"
                        run_log.record_equiv_check(equiv_round=0, result="re-verify_error")
                        continue

                    t0 = time.monotonic()
                    result = run_verification_rust_only(vctx, RUST_OBJ_DST, entry_symbol)
                    verify_wall = time.monotonic() - t0

                    if result.equivalent:
                        print(f"[Re-verify] {entry_symbol}: still equivalent")
                        run_log.record_equiv_check(
                            equiv_round=0, result="re-verify_equivalent",
                            wall_time_s=verify_wall,
                        )
                    else:
                        print(f"[Re-verify] {entry_symbol}: REGRESSED!")
                        entry_results[entry_symbol] = "regressed"
                        ce = getattr(result, "counter_example", "") or ""
                        run_log.record_equiv_check(
                            equiv_round=0, result="re-verify_regressed",
                            counter_example=ce, wall_time_s=verify_wall,
                        )

        run_log.stage_timings["verify_all_entries"] = round(
            time.monotonic() - t0_verify_all, 2
        )
        run_log.entry_results = entry_results

        print(f"\n{'='*60}")
        print("  Multi-entry verification summary")
        print(f"{'='*60}")
        all_ok = True
        for sym, res in entry_results.items():
            status_marker = "OK" if res == "equivalent" else "FAIL"
            print(f"  {sym}: {res} [{status_marker}]")
            if res != "equivalent":
                all_ok = False

        if all_ok:
            run_log.result = "equivalent"
            print(f"\nSUCCESS: All {len(entry_symbols)} entries are equivalent!")
            out_dir = save_verified_translation(
                c_file_path, rust_code, "all", map_specs, run_log
            )
            _copy_dump_to_archive(_dump_path, out_dir)
        else:
            equiv_count = sum(1 for v in entry_results.values() if v == "equivalent")
            run_log.result = "equivalence_failed"
            print(f"\nPARTIAL: {equiv_count}/{len(entry_symbols)} entries equivalent")
            out_dir = save_failed_run(
                c_file_path, rust_code, "all", map_specs, run_log
            )
            _copy_dump_to_archive(_dump_path, out_dir)

            if equiv_count > 0:
                passing = [s for s, r in entry_results.items()
                           if r == "equivalent"]
                snapshot_tag = "partial_" + "_".join(passing)
                snapshot_dir = save_verified_translation(
                    c_file_path, rust_code, snapshot_tag, map_specs, run_log
                )
                _copy_dump_to_archive(_dump_path, snapshot_dir)
                print(f"[Archive] Snapshot of passing entries saved to {snapshot_dir}/")

        return all_ok

    finally:

        if run_log.result in ("unknown", "compile_failed", "copy_failed",
                               "kernel_verify_failed"):
            out_dir = save_failed_run(
                c_file_path, rust_code, "all", map_specs, run_log
            )
            _copy_dump_to_archive(_dump_path, out_dir)

if __name__ == "__main__":
    default_anthropic_cache_ttl = os.environ.get("ANTHROPIC_CACHE_TTL", "5m").strip().lower()
    if default_anthropic_cache_ttl not in {"off", "5m", "1h"}:
        default_anthropic_cache_ttl = "5m"

    parser = argparse.ArgumentParser(
        description="Translate C eBPF programs to Rust and verify equivalence"
    )
    parser.add_argument("c_file", nargs="?", help="Path to C source file")
    parser.add_argument("c_binary", nargs="?", help="Path to compiled C eBPF object (.o)")
    parser.add_argument("entry_symbol", nargs="?", help="Entry symbol name")
    parser.add_argument("map_specs", nargs="*", help="Map specs as name:type (e.g. my_map:hash)")
    parser.add_argument("--provider", choices=["anthropic", "openai", "ollama", "openai-compat"],
                        default="anthropic",
                        help="LLM provider (default: anthropic)")
    parser.add_argument("--model", default=None, help="Model name override")
    parser.add_argument(
        "--anthropic-cache-ttl",
        choices=["off", "5m", "1h"],
        default=default_anthropic_cache_ttl,
        help=(
            "Prompt-cache TTL for Anthropic cached prompt blocks in this pipeline. "
            "Default: 5m. Use 'off' to disable."
        ),
    )
    parser.add_argument("--base-url", default=os.environ.get("OPENAI_COMPAT_BASE_URL"),
                        help="Base URL for OpenAI-compatible endpoint (e.g. http://gpu-server:8000/v1). "
                             "Also reads OPENAI_COMPAT_BASE_URL env var. "
                             "When set, --provider defaults to openai-compat.")
    parser.add_argument("--api-key", default=os.environ.get("OPENAI_COMPAT_API_KEY"),
                        help="API key for the LLM provider (overrides env var). "
                             "Also reads OPENAI_COMPAT_API_KEY env var.")
    parser.add_argument("--inject-docs", action="store_true",
                        help="Inject relevant Aya API docs into the translation prompt. "
                             "Uses --aya-docs-path or AYA_DOCS_PATH env var for the docs location.")
    parser.add_argument("--aya-docs-path", default=os.environ.get("AYA_DOCS_PATH"),
                        help="Path to Aya repo with cargo doc output (target/doc/). "
                             "Also reads AYA_DOCS_PATH env var. Only used with --inject-docs.")
    parser.add_argument("--skip-translation", action="store_true",
                        help="Skip C→Rust translation, reuse existing code")
    parser.add_argument(
        "--rust-entry-symbol",
        default=None,
        help=(
            "Optional Rust-side entry symbol for equivalence formula generation. "
            "Defaults to positional entry_symbol (used for C). Useful with "
            "--skip-translation when Rust entry naming differs."
        ),
    )
    parser.add_argument(
        "--compile-only",
        action="store_true",
        help=(
            "Only compile existing Rust eBPF code (no translation/verification/LLM calls) "
            "and exit."
        ),
    )
    parser.add_argument("--max-compile-retries", type=int, default=10,
                        help="Max compilation retry attempts per verifier round (default: 10)")
    parser.add_argument("--max-verifier-retries", type=int, default=5,
                        help="Max kernel verifier retry rounds (default: 5)")
    parser.add_argument("--max-equiv-retries", type=int, default=5,
                        help="Max equivalence fix attempts (default: 5)")
    parser.add_argument("--last-k-compile-attempts", type=int, default=3,
                        help=(
                            "Number of prior (code, error) compile attempts to include "
                            "as multi-turn context when retrying compilation failures "
                            "(default: 3, use 1 for the original fresh-3-message behavior)"
                        ))
    parser.add_argument(
        "--helper-fail-mode",
        choices=["off", "all", "selected"],
        default="off",
        help=(
            "Helper failure modeling mode for symbolic verification: "
            "'off' (success-only), 'all' (all failable helpers), "
            "'selected' (only helpers from --helper-fail-helpers)."
        ),
    )
    parser.add_argument(
        "--helper-fail-helpers",
        default="",
        help=(
            "Comma-separated helper names for selected mode, e.g. "
            "bpf_probe_read,get_current_comm,ringbuf_reserve"
        ),
    )
    parser.add_argument("--run-tag", default=None,
                        help="Optional user-defined label stored in run_log args for later aggregation")
    parser.add_argument(
        "--check-build-prereqs",
        action="store_true",
        help="Check Rust toolchain prerequisites and exit (no LLM calls).",
    )
    parser.add_argument(
        "--kernel-verify-mode",
        choices=["off", "warn", "strict"],
        default="strict",
        help=(
            "Kernel verifier gating mode: "
            "'off' disables kernel verification, "
            "'warn' uses it when available but continues on permission issues, "
            "'strict' requires successful kernel verification."
        ),
    )
    parser.add_argument(
        "--pkt-size",
        type=int,
        default=None,
        help=(
            "Packet buffer size in bytes for XDP/socket programs "
            "(default: 1500). Only applies to program types with "
            "direct packet access."
        ),
    )
    parser.add_argument(
        "--all-entries",
        action="store_true",
        help=(
            "Auto-detect and verify ALL entry points in the C binary. "
            "When set, the positional entry_symbol is ignored. "
            "Maps are still required."
        ),
    )

    args, remaining = parser.parse_known_args()
    if remaining and args.all_entries:
        args.map_specs = (args.map_specs or []) + remaining
    elif remaining:
        parser.error(f"unrecognized arguments: {' '.join(remaining)}")

    os.environ["ANTHROPIC_CACHE_TTL"] = args.anthropic_cache_ttl

    if args.base_url and args.provider == "anthropic":
        args.provider = "openai-compat"

    if args.check_build_prereqs:
        ok, msg = check_build_prereqs()
        if ok:
            print("[Preflight] OK: Rust toolchain prerequisites look good.")
            sys.exit(0)
        print("[Preflight] FAILED")
        if msg:
            print(msg)
        sys.exit(1)

    if args.compile_only:
        prereq_ok, prereq_msg = check_build_prereqs()
        if not prereq_ok:
            print("[Compile-only] Preflight failed")
            print(prereq_msg)
            sys.exit(1)

        print("[Compile-only] Building current Rust eBPF source...")
        ok, build_log = compile_rust()
        if not ok:
            print("[Compile-only] FAILED")
            if build_log:
                print(extract_structured_errors(build_log))
            sys.exit(1)

        copy_ok, copy_err = copy_rust_binary()
        if not copy_ok:
            print(f"[Compile-only] Build succeeded but copy failed: {copy_err}")
            sys.exit(1)

        print(f"[Compile-only] SUCCESS: build passed and object copied to {RUST_OBJ_DST}")
        sys.exit(0)

    def _sigterm_handler(signum, frame):
        print("\n[Signal] Received SIGTERM — shutting down gracefully...")
        raise SystemExit(1)
    signal.signal(signal.SIGTERM, _sigterm_handler)

    helper_fail_helpers_list = [
        h.strip() for h in args.helper_fail_helpers.split(",") if h.strip()
    ]

    if args.all_entries:

        if not args.c_file or not args.c_binary:
            parser.error(
                "c_file and c_binary are required for --all-entries mode"
            )

        entry_symbols = extract_entry_symbols(args.c_binary)
        if not entry_symbols:
            print(f"ERROR: No entry symbols found in {args.c_binary}")
            sys.exit(1)
        print(f"[Multi-entry] Detected {len(entry_symbols)} entry points: {entry_symbols}")

        success = main_multi(
            args.c_file,
            args.c_binary,
            entry_symbols,
            args.map_specs,
            provider=args.provider,
            model=args.model,
            skip_translation=args.skip_translation,
            max_compile_retries=args.max_compile_retries,
            max_verifier_retries=args.max_verifier_retries,
            max_equiv_retries=args.max_equiv_retries,
            kernel_verify_mode=args.kernel_verify_mode,
            base_url=args.base_url,
            api_key=args.api_key,
            inject_docs=args.inject_docs,
            aya_docs_path=args.aya_docs_path,
            run_tag=args.run_tag,
            helper_fail_mode=args.helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers_list,
            pkt_size=args.pkt_size,
            last_k_compile_attempts=args.last_k_compile_attempts,
        )
    else:

        if not args.c_file or not args.c_binary or not args.entry_symbol or not args.map_specs:
            parser.error(
                "c_file, c_binary, entry_symbol, and at least one map_spec are required "
                "unless --compile-only is used"
            )

        success = main(
            args.c_file,
            args.c_binary,
            args.entry_symbol,
            args.map_specs,
            provider=args.provider,
            model=args.model,
            skip_translation=args.skip_translation,
            max_compile_retries=args.max_compile_retries,
            max_verifier_retries=args.max_verifier_retries,
            max_equiv_retries=args.max_equiv_retries,
            kernel_verify_mode=args.kernel_verify_mode,
            base_url=args.base_url,
            api_key=args.api_key,
            inject_docs=args.inject_docs,
            aya_docs_path=args.aya_docs_path,
            run_tag=args.run_tag,
            rust_entry_symbol=args.rust_entry_symbol,
            helper_fail_mode=args.helper_fail_mode,
            helper_fail_helpers=helper_fail_helpers_list,
            pkt_size=args.pkt_size,
            last_k_compile_attempts=args.last_k_compile_attempts,
        )

    sys.exit(0 if success else 1)
