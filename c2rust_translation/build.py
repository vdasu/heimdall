"""Rust eBPF build tooling: write source, compile, copy binary."""

import os
import pwd
import shutil
import subprocess

RUST_SRC_PATH = "./aya-ebpf/src/main.rs"
RUST_BUILD_DIR = "./aya-ebpf"
RUST_BUILD_LOG = "./aya-ebpf/build.log"
RUST_OBJ_SRC = "./aya-ebpf/target/bpfel-unknown-none-atomic/release/aya-ebpf-translated"
RUST_OBJ_DST = "aya-tracepoint-obj"

UNSAFE_LINTS = (
    "#![deny(clippy::multiple_unsafe_ops_per_block)]\n"
    "#![deny(clippy::undocumented_unsafe_blocks)]\n"
    "#![deny(unused_unsafe)]\n"
    "#![deny(unused_must_use)]\n"
)

RUST_TARGET_JSON = "bpfel-unknown-none-atomic.json"

def _resolve_build_context():
    """Resolve build environment, target user context, and cargo path.

    Returns (env, compile_as_user, cargo_bin, error_message).
    """
    env = os.environ.copy()
    env["RUSTFLAGS"] = "-C debuginfo=2 -C link-arg=--btf -C target-cpu=v3"

    compile_as_user = None
    compile_as_home = None
    if os.geteuid() == 0:
        sudo_user = env.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            compile_as_user = sudo_user
            try:
                compile_as_home = pwd.getpwnam(sudo_user).pw_dir
            except KeyError:
                compile_as_home = None
            if compile_as_home:
                env["HOME"] = compile_as_home
                env.setdefault("CARGO_HOME", os.path.join(compile_as_home, ".cargo"))
                env.setdefault("RUSTUP_HOME", os.path.join(compile_as_home, ".rustup"))

    cargo_bin = env.get("CARGO")
    if cargo_bin is None and compile_as_home:
        user_cargo = os.path.join(compile_as_home, ".cargo", "bin", "cargo")
        if os.path.isfile(user_cargo) and os.access(user_cargo, os.X_OK):
            cargo_bin = user_cargo
    if cargo_bin is None:
        cargo_bin = shutil.which("cargo")
    if cargo_bin is None:

        home_cargo = os.path.join(env.get("HOME", ""), ".cargo", "bin", "cargo")
        for candidate in (
            home_cargo,
            "/usr/bin/cargo",
            "/usr/local/bin/cargo",
        ):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                cargo_bin = candidate
                break

    if cargo_bin is None:
        return (
            env,
            compile_as_user,
            None,
            (
                "[run_translation] cargo not found in PATH.\n"
                f"PATH={env.get('PATH', '')}\n"
                "If running with sudo, preserve PATH (and your env) so cargo is visible."
            ),
        )

    return env, compile_as_user, cargo_bin, ""

def _maybe_wrap_compile_user(cmd, compile_as_user):
    """Wrap a command with sudo -u when compile user override is needed."""
    if not compile_as_user:
        return cmd, ""

    sudo_bin = shutil.which("sudo")
    if sudo_bin is None:
        return [], "[run_translation] sudo not found; cannot switch compile user."

    preserve = "PATH,HOME,CARGO_HOME,RUSTUP_HOME,RUSTFLAGS,VIRTUAL_ENV"
    wrapped = [
        sudo_bin,
        "-u",
        compile_as_user,
        f"--preserve-env={preserve}",
    ] + cmd
    return wrapped, ""

def check_build_prereqs():
    """Check toolchain prerequisites before spending any LLM/API tokens.

    Returns (ok, message). On failure, message contains actionable remediation.
    """
    env, compile_as_user, cargo_bin, err = _resolve_build_context()
    if err:
        return False, err

    target_path = os.path.join(RUST_BUILD_DIR, RUST_TARGET_JSON)
    if not os.path.exists(target_path):
        return (
            False,
            (
                "[run_translation] Missing target specification JSON:\n"
                f"  {target_path}\n"
                "Cannot compile eBPF target without this file."
            ),
        )

    tool_dir = os.path.dirname(cargo_bin) if cargo_bin else ""
    rustup_bin = env.get("RUSTUP")
    if not rustup_bin and tool_dir:
        candidate = os.path.join(tool_dir, "rustup")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            rustup_bin = candidate

    rustc_bin = env.get("RUSTC")
    if not rustc_bin and tool_dir:
        candidate = os.path.join(tool_dir, "rustc")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            rustc_bin = candidate
    if not rustc_bin:
        rustc_bin = shutil.which("rustc")

    if rustup_bin:
        sysroot_cmd = [rustup_bin, "run", "nightly", "rustc", "--print", "sysroot"]
    elif rustc_bin:
        sysroot_cmd = [rustc_bin, "+nightly", "--print", "sysroot"]
    else:
        return (
            False,
            (
                "[run_translation] Could not find rustc/rustup for nightly toolchain.\n"
                f"cargo={cargo_bin}\n"
                f"PATH={env.get('PATH', '')}"
            ),
        )

    sysroot_cmd, wrap_err = _maybe_wrap_compile_user(sysroot_cmd, compile_as_user)
    if wrap_err:
        return False, wrap_err

    try:
        proc = subprocess.run(
            sysroot_cmd,
            cwd=RUST_BUILD_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        return False, f"[run_translation] failed to execute rustc/rustup: {exc}"

    sysroot_out = (proc.stdout or "").strip()
    rustc_log = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 or not sysroot_out:
        return (
            False,
            (
                "[run_translation] Failed to resolve nightly rust sysroot.\n"
                f"{rustc_log}"
            ),
        )

    sysroot = sysroot_out.splitlines()[-1].strip()
    cargo_lock = os.path.join(
        sysroot, "lib", "rustlib", "src", "rust", "library", "Cargo.lock"
    )
    if not os.path.exists(cargo_lock):
        install_cmd = "rustup component add rust-src --toolchain nightly"
        if compile_as_user:
            install_cmd = (
                f"sudo -u {compile_as_user} "
                "--preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME "
                "rustup component add rust-src --toolchain nightly"
            )
        return (
            False,
            (
                "[run_translation] Missing rust-src for nightly toolchain.\n"
                f"Expected file: {cargo_lock}\n"
                f"Install with:\n  {install_cmd}"
            ),
        )

    return True, ""

from safety_policy import check_banned, safety_audit

def write_rust_source(rust_code):
    """Write Rust source code to the aya-tracepoint project.

    Injects Clippy lints after #![no_main] to enforce minimal, documented unsafe usage.
    Rejects code containing banned patterns (e.g., core::mem::transmute for raw helper calls).
    Returns False if code is empty/invalid, True otherwise.
    """
    if not rust_code or not rust_code.strip():
        print("[Warning] write_rust_source called with empty code, skipping write")
        return False

    violations = check_banned(rust_code)
    banned_error_line = ""
    if violations:
        pattern, msg = violations[0]
        print(f"[REJECTED] Source contains banned pattern: `{pattern}`")
        print(f"           {msg}")
        banned_error_line = f'\ncompile_error!("BANNED: {msg}");\n'
    if UNSAFE_LINTS.splitlines()[0] not in rust_code:

        rust_code = rust_code.replace(
            "#![no_main]\n",
            "#![no_main]\n" + UNSAFE_LINTS,
            1,
        )

    if banned_error_line:
        last_deny = rust_code.rfind("#![deny(")
        if last_deny >= 0:

            newline_after = rust_code.index("\n", last_deny)
            rust_code = rust_code[:newline_after + 1] + banned_error_line + rust_code[newline_after + 1:]
        else:

            rust_code = rust_code.replace("#![no_main]\n", "#![no_main]\n" + banned_error_line, 1)
    with open(RUST_SRC_PATH, "w") as f:
        f.write(rust_code)

    audit_warnings = safety_audit(rust_code)
    if audit_warnings:
        print("[SAFETY AUDIT] Warnings (not blocking):")
        for w in audit_warnings:
            print(w)
    return True

def compile_rust():
    """Compile the Rust eBPF program. Returns (success, build_log)."""
    env, compile_as_user, cargo_bin, err = _resolve_build_context()
    if err:
        build_log = err
        with open(RUST_BUILD_LOG, "w") as f:
            f.write(build_log)
        return False, build_log

    compile_cmd = [
        cargo_bin,
        "+nightly",
        "build",
        f"--target={RUST_TARGET_JSON}",
        "-Zbuild-std=core",
        "--release",
        "-Zjson-target-spec",
    ]

    compile_cmd, wrap_err = _maybe_wrap_compile_user(compile_cmd, compile_as_user)
    if wrap_err:
        build_log = wrap_err
        with open(RUST_BUILD_LOG, "w") as f:
            f.write(build_log)
        return False, build_log

    try:
        proc = subprocess.run(
            compile_cmd,
            cwd=RUST_BUILD_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        build_log = f"[run_translation] failed to execute cargo: {exc}"
        with open(RUST_BUILD_LOG, "w") as f:
            f.write(build_log)
        return False, build_log

    build_log = (proc.stdout or "") + (proc.stderr or "")
    with open(RUST_BUILD_LOG, "w") as f:
        f.write(build_log)

    success = proc.returncode == 0
    if success and not os.path.exists(RUST_OBJ_SRC):
        success = False
        build_log = (
            build_log
            + "\n[run_translation] Build reported success but output object was not found: "
            + RUST_OBJ_SRC
        )

    return success, build_log

def copy_rust_binary():
    """Copy the compiled Rust eBPF binary to the working directory.

    Returns (ok, error_message).
    """
    if not os.path.exists(RUST_OBJ_SRC):
        return False, f"source object not found: {RUST_OBJ_SRC}"

    try:
        shutil.copy2(RUST_OBJ_SRC, RUST_OBJ_DST)
    except Exception as exc:
        return False, str(exc)

    return True, ""
