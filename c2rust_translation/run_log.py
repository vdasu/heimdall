"""Run logging, stats tracking, and archival for translation pipeline."""

import os
import re
import json
import shutil
from datetime import datetime
from dataclasses import dataclass, asdict

from error_analysis import classify_build_errors

@dataclass
class LLMCallRecord:
    call_index: int
    stage: str
    attempt_number: int
    equiv_round: int
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    uncached_input_tokens: int | None
    cache_creation_input_tokens: int | None
    cache_read_input_tokens: int | None
    raw_input_tokens: int | None
    wall_time_s: float
    prompt_chars: int
    response_chars: int
    rust_code_chars: int
    rust_code_lines: int
    timestamp: str

@dataclass
class CompileAttemptRecord:
    attempt_index: int
    attempt_in_stage: int
    equiv_round: int
    rust_code_chars: int
    rust_code_lines: int
    compile_success: bool
    kernel_verify_run: bool
    kernel_verify_result: str | None
    safety_run: bool
    safety_result: str | None
    build_log_chars: int
    verifier_log_chars: int
    safety_log_chars: int
    compile_wall_time_s: float
    verifier_wall_time_s: float
    error_categories: dict
    error_count: int
    timestamp: str

@dataclass
class EquivCheckRecord:
    equiv_round: int
    result: str
    counter_example_chars: int
    wall_time_s: float
    timestamp: str

VERIFIED_DIR = os.environ.get("TRANSLATION_VERIFIED_DIR", "./verified_translations")
FAILED_DIR = os.environ.get("TRANSLATION_FAILED_DIR", "./failed_translations")

class RunLog:
    """Comprehensive logging for a single translation run."""

    def __init__(self, provider, model, c_source_file, entry_symbol, map_specs, args_dict=None):
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.provider = provider
        self.model = model
        self.args = args_dict or {}
        self.c_source_file = c_source_file
        self.c_source_chars = 0
        self.c_source_lines = 0
        self.entry_symbol = entry_symbol
        self.map_specs = map_specs
        self.started_at = datetime.now().isoformat()
        self.finished_at = None
        self.result = "unknown"

        self.entry_symbols = None
        self.entry_results = {}
        self.stage_timings = {}
        self.llm_calls: list = []
        self.compile_attempts: list = []
        self.equiv_checks: list = []
        self.rust_snapshots: dict = {}
        self.build_logs: dict = {}
        self.verifier_logs: dict = {}
        self._call_counter = 0
        self._compile_counter = 0

    @property
    def compile_attempt_count(self):
        return len(self.compile_attempts)

    @property
    def verifier_attempt_count(self):
        return sum(1 for c in self.compile_attempts if c.kernel_verify_run)

    @property
    def equiv_attempt_count(self):
        return len(self.equiv_checks)

    def record_llm_call(self, stage, attempt_number, equiv_round, llm_result, prompt_text, rust_code):
        in_tok = llm_result.input_tokens
        cache_read_in = getattr(llm_result, "cache_read_input_tokens", None)
        cache_create_in = getattr(llm_result, "cache_creation_input_tokens", None)
        cached_in = getattr(llm_result, "cached_input_tokens", None)
        if cached_in is None:
            cached_in = cache_read_in
        uncached_in = getattr(llm_result, "uncached_input_tokens", None)
        raw_in = getattr(llm_result, "raw_input_tokens", None)

        if raw_in is None and in_tok is not None:
            known_cached = (cache_read_in or 0) + (cache_create_in or 0)
            if known_cached <= in_tok:
                raw_in = in_tok - known_cached
            elif not known_cached:
                raw_in = in_tok

        if uncached_in is None and in_tok is not None:
            if cached_in is not None:
                uncached_in = max(in_tok - cached_in, 0)
            else:
                uncached_in = in_tok

        rec = LLMCallRecord(
            call_index=self._call_counter,
            stage=stage, attempt_number=attempt_number, equiv_round=equiv_round,
            input_tokens=in_tok, output_tokens=llm_result.output_tokens,
            cached_input_tokens=cached_in, uncached_input_tokens=uncached_in,
            cache_creation_input_tokens=cache_create_in,
            cache_read_input_tokens=cache_read_in,
            raw_input_tokens=raw_in,
            wall_time_s=llm_result.wall_time_s,
            prompt_chars=len(prompt_text), response_chars=len(llm_result.text),
            rust_code_chars=len(rust_code), rust_code_lines=rust_code.count('\n') + 1,
            timestamp=datetime.now().isoformat(),
        )
        self._call_counter += 1
        self.llm_calls.append(rec)

    def record_compile_attempt(self, attempt_in_stage, equiv_round, rust_code,
                                compile_success, build_log, compile_wall_time_s,
                                kernel_verify_run=False, kernel_verify_result=None,
                                verifier_log="", verifier_wall_time_s=0.0,
                                safety_run=False, safety_result=None,
                                safety_log=""):
        idx = self._compile_counter
        cats, ecount = classify_build_errors(build_log) if not compile_success else ({}, 0)
        rec = CompileAttemptRecord(
            attempt_index=idx, attempt_in_stage=attempt_in_stage, equiv_round=equiv_round,
            rust_code_chars=len(rust_code), rust_code_lines=rust_code.count('\n') + 1,
            compile_success=compile_success,
            kernel_verify_run=kernel_verify_run, kernel_verify_result=kernel_verify_result,
            safety_run=safety_run, safety_result=safety_result,
            build_log_chars=len(build_log), verifier_log_chars=len(verifier_log),
            safety_log_chars=len(safety_log),
            compile_wall_time_s=compile_wall_time_s, verifier_wall_time_s=verifier_wall_time_s,
            error_categories=cats, error_count=ecount,
            timestamp=datetime.now().isoformat(),
        )
        self._compile_counter += 1
        self.compile_attempts.append(rec)
        self.rust_snapshots[idx] = rust_code
        self.build_logs[idx] = build_log
        if verifier_log:
            self.verifier_logs[idx] = verifier_log

    def record_equiv_check(self, equiv_round, result, counter_example="", wall_time_s=0.0):
        rec = EquivCheckRecord(
            equiv_round=equiv_round, result=result,
            counter_example_chars=len(counter_example),
            wall_time_s=wall_time_s,
            timestamp=datetime.now().isoformat(),
        )
        self.equiv_checks.append(rec)

    def _compute_summary(self):
        total_in = sum(c.input_tokens or 0 for c in self.llm_calls)
        total_out = sum(c.output_tokens or 0 for c in self.llm_calls)
        total_cache_read_in = sum(
            (c.cache_read_input_tokens if c.cache_read_input_tokens is not None else c.cached_input_tokens) or 0
            for c in self.llm_calls
        )
        total_cache_create_in = sum(c.cache_creation_input_tokens or 0 for c in self.llm_calls)
        total_raw_in = sum(c.raw_input_tokens or 0 for c in self.llm_calls)
        total_cached_in = total_cache_read_in
        total_uncached_in = sum(c.uncached_input_tokens or 0 for c in self.llm_calls)
        code_sizes = [c.rust_code_chars for c in self.compile_attempts]
        first_success_idx = next((i for i, c in enumerate(self.compile_attempts) if c.compile_success), None)
        agg_errors = {}
        for c in self.compile_attempts:
            for k, v in c.error_categories.items():
                agg_errors[k] = agg_errors.get(k, 0) + v
        llm_times = [c.wall_time_s for c in self.llm_calls]
        compile_times = [c.compile_wall_time_s for c in self.compile_attempts]

        stage_summary = {}
        for c in self.llm_calls:
            st = stage_summary.setdefault(
                c.stage,
                {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cached_input_tokens": 0,
                    "uncached_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                    "raw_input_tokens": 0,
                    "llm_wall_time_s": 0.0,
                },
            )
            st["calls"] += 1
            st["input_tokens"] += c.input_tokens or 0
            st["output_tokens"] += c.output_tokens or 0
            st["cached_input_tokens"] += c.cached_input_tokens or 0
            st["uncached_input_tokens"] += c.uncached_input_tokens or 0
            st["cache_creation_input_tokens"] += c.cache_creation_input_tokens or 0
            st["cache_read_input_tokens"] += (
                c.cache_read_input_tokens if c.cache_read_input_tokens is not None else c.cached_input_tokens
            ) or 0
            st["raw_input_tokens"] += c.raw_input_tokens or 0
            st["llm_wall_time_s"] += c.wall_time_s or 0.0

        for item in stage_summary.values():
            if item["calls"] > 0:
                item["avg_input_tokens_per_call"] = round(item["input_tokens"] / item["calls"], 2)
                item["avg_output_tokens_per_call"] = round(item["output_tokens"] / item["calls"], 2)
                item["avg_llm_wall_time_s"] = round(item["llm_wall_time_s"] / item["calls"], 3)
            else:
                item["avg_input_tokens_per_call"] = None
                item["avg_output_tokens_per_call"] = None
                item["avg_llm_wall_time_s"] = None
            item["llm_wall_time_s"] = round(item["llm_wall_time_s"], 3)

        total_in_for_ratio = total_cached_in + total_uncached_in
        cache_hit_ratio = (
            round(total_cached_in / total_in_for_ratio, 4)
            if total_in_for_ratio > 0 else None
        )

        return {
            "total_llm_calls": len(self.llm_calls),
            "total_compile_attempts": len(self.compile_attempts),
            "total_equiv_checks": len(self.equiv_checks),
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "total_tokens": total_in + total_out,
            "total_cached_input_tokens": total_cached_in,
            "total_uncached_input_tokens": total_uncached_in,
            "total_cache_creation_input_tokens": total_cache_create_in,
            "total_cache_read_input_tokens": total_cache_read_in,
            "total_raw_input_tokens": total_raw_in,
            "input_cache_hit_ratio": cache_hit_ratio,
            "tokens_to_first_compile_success": sum(
                (c.input_tokens or 0) + (c.output_tokens or 0)
                for c in self.llm_calls[:first_success_idx + 1]
            ) if first_success_idx is not None else None,
            "code_size_initial_chars": code_sizes[0] if code_sizes else None,
            "code_size_final_chars": code_sizes[-1] if code_sizes else None,
            "code_size_delta_pct": round(100 * (code_sizes[-1] - code_sizes[0]) / code_sizes[0], 1) if len(code_sizes) >= 2 and code_sizes[0] else None,
            "code_sizes_over_attempts": code_sizes,
            "error_category_counts": agg_errors,
            "avg_llm_call_time_s": round(sum(llm_times) / len(llm_times), 2) if llm_times else None,
            "avg_compile_time_s": round(sum(compile_times) / len(compile_times), 2) if compile_times else None,
            "total_llm_time_s": round(sum(llm_times), 2),
            "total_compile_time_s": round(sum(compile_times), 2),
            "compile_attempts_to_first_success": first_success_idx + 1 if first_success_idx is not None else None,
            "equiv_rounds_to_success": next((i for i, e in enumerate(self.equiv_checks) if e.result == "equivalent"), None),
            "llm_stage_breakdown": stage_summary,
            "compile_fix_calls": sum(1 for c in self.llm_calls if c.stage == "compile_fix"),
            "verifier_fix_calls": sum(1 for c in self.llm_calls if c.stage == "verifier_fix"),
            "safety_fix_calls": sum(1 for c in self.llm_calls if c.stage == "safety_fix"),
            "equiv_fix_calls": sum(1 for c in self.llm_calls if c.stage == "equiv_fix"),
            "safety_checked_attempts": sum(1 for c in self.compile_attempts if c.safety_run),
        }

    def to_dict(self):
        self.finished_at = datetime.now().isoformat()
        d = {
            "run_id": self.run_id,
            "provider": self.provider, "model": self.model,
            "args": self.args,
            "c_source_file": self.c_source_file,
            "c_source_chars": self.c_source_chars, "c_source_lines": self.c_source_lines,
            "entry_symbol": self.entry_symbol, "map_specs": self.map_specs,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "result": self.result,
            "stage_timings": self.stage_timings,
            "summary": self._compute_summary(),
            "llm_calls": [asdict(r) for r in self.llm_calls],
            "compile_attempts": [asdict(r) for r in self.compile_attempts],
            "equiv_checks": [asdict(r) for r in self.equiv_checks],
        }
        if self.entry_symbols is not None:
            d["entry_symbols"] = self.entry_symbols
        if self.entry_results:
            d["entry_results"] = self.entry_results
        return d

    def to_legacy_stats_dict(self):
        return {
            "provider": self.provider, "model": self.model,
            "compile_attempts": self.compile_attempt_count,
            "verifier_attempts": self.verifier_attempt_count,
            "equiv_attempts": self.equiv_attempt_count,
            "started_at": self.started_at,
            "finished_at": datetime.now().isoformat(),
            "result": self.result,
        }

def _sanitize_model(model):
    """Sanitize a model name for use as a directory component."""
    return re.sub(r'[/\s\\]', '_', model)

def _next_run_number(parent_dir):
    """Return the next run number by scanning existing run_* directories."""
    if not os.path.isdir(parent_dir):
        return 1
    max_n = 0
    for name in os.listdir(parent_dir):
        m = re.match(r'^run_(\d+)$', name)
        if m:
            max_n = max(max_n, int(m.group(1)))
    return max_n + 1

def _save_run_log(out_dir, run_log, c_file_path, rust_code, entry_symbol, map_specs):
    """Write run_log.json, stats.json, and attempt snapshots to out_dir."""
    os.makedirs(out_dir, exist_ok=True)

    shutil.copy2(c_file_path, os.path.join(out_dir, os.path.basename(c_file_path)))

    program_name = os.path.splitext(os.path.basename(c_file_path))[0]
    rs_filename = f"{program_name}.rs"
    with open(os.path.join(out_dir, rs_filename), "w") as f:
        f.write(rust_code)

    with open(os.path.join(out_dir, "run_log.json"), "w") as f:
        json.dump(run_log.to_dict(), f, indent=2)

    stats_data = run_log.to_legacy_stats_dict()
    stats_data["c_source"] = os.path.basename(c_file_path)
    stats_data["rust_source"] = rs_filename
    stats_data["entry_symbol"] = entry_symbol
    stats_data["map_specs"] = map_specs
    with open(os.path.join(out_dir, "stats.json"), "w") as f:
        json.dump(stats_data, f, indent=2)

    try:
        from build import RUST_OBJ_SRC
        if os.path.exists(RUST_OBJ_SRC):
            shutil.copy2(RUST_OBJ_SRC, os.path.join(out_dir, f"{program_name}.o"))
    except Exception:
        pass

    try:
        prompts_src = os.path.join(os.path.dirname(__file__), "prompts.py")
        if os.path.exists(prompts_src):
            shutil.copy2(prompts_src, os.path.join(out_dir, "prompts.py"))
    except Exception:
        pass

    attempts_dir = os.path.join(out_dir, "attempts")
    if run_log.rust_snapshots:
        os.makedirs(attempts_dir, exist_ok=True)
    for idx, code in run_log.rust_snapshots.items():
        with open(os.path.join(attempts_dir, f"attempt_{idx:03d}.rs"), "w") as f:
            f.write(code)
    for idx, log in run_log.build_logs.items():
        with open(os.path.join(attempts_dir, f"attempt_{idx:03d}_build.log"), "w") as f:
            f.write(log)
    for idx, log in run_log.verifier_logs.items():
        with open(os.path.join(attempts_dir, f"attempt_{idx:03d}_verifier.log"), "w") as f:
            f.write(log)

def _extract_dataset_prefix(c_file_path):
    """Extract dataset directory name from c_file_path for namespacing.

    e.g. 'c_bpf_programs/linux_bpf_standalone/foo.c' -> 'linux_bpf_standalone__'
         'c_bpf_programs/foo.c' -> '' (no prefix for top-level files)
    """
    parts = os.path.normpath(c_file_path).split(os.sep)
    try:
        idx = parts.index("c_bpf_programs")

        if len(parts) > idx + 2:
            return parts[idx + 1] + "__"
    except ValueError:
        pass
    return ""

def save_translation_run(c_file_path, rust_code, entry_symbol, map_specs, run_log, *, verified):
    """Archive a translation run under {base}/{dataset}__{prog}__{entry}/{model}/run_{N}/.

    Returns the output directory path so the caller can copy additional files
    (e.g. the LLM I/O dump) into it.
    """
    base_dir = VERIFIED_DIR if verified else FAILED_DIR
    dataset_prefix = _extract_dataset_prefix(c_file_path)
    program_name = os.path.splitext(os.path.basename(c_file_path))[0]
    sanitized_model = _sanitize_model(run_log.model or "unknown")
    parent_dir = os.path.join(base_dir, f"{dataset_prefix}{program_name}__{entry_symbol}", sanitized_model)
    run_n = _next_run_number(parent_dir)
    out_dir = os.path.join(parent_dir, f"run_{run_n}")
    _save_run_log(out_dir, run_log, c_file_path, rust_code, entry_symbol, map_specs)
    label = "Verified" if verified else "Failed"
    print(f"[Archive] {label} translation saved to {out_dir}/")
    return out_dir

def save_verified_translation(c_file_path, rust_code, entry_symbol, map_specs, run_log):
    """Archive a verified translation. Returns the output directory path."""
    return save_translation_run(c_file_path, rust_code, entry_symbol, map_specs, run_log, verified=True)

def save_failed_run(c_file_path, rust_code, entry_symbol, map_specs, run_log):
    """Archive a failed translation run. Returns the output directory path."""
    return save_translation_run(c_file_path, rust_code, entry_symbol, map_specs, run_log, verified=False)
