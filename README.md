# Heimdall: Formally Verified Automated Migration of Legacy eBPF Programs to Rust

This artifact accompanies the paper *"Heimdall: Formally Verified
Automated Migration of Legacy eBPF Programs to Rust"*.

## Repository layout

```
heimdall/
├── angr_ebpf_backend/      eBPF architecture, lifter, loader, SimOS for angr
│   └── angr_ebpf/          (installed as `import angr_ebpf`)
├── c2rust_translation/     Translation + verification pipeline
│   ├── agent_code_translate.sh        Driver: agentic translate + verify
│   ├── run_translation.py             Single-program translate + verify
│   ├── run_translation_commands.txt   102 ready-to-run invocations
│   ├── verify_equivalence.py          Z3 ITE-based equivalence checker
│   ├── verify_mixed_entries.py        Direct C↔Rust equivalence check
│   ├── verify_ebpf_kernel.py          In-kernel BPF verifier wrapper
│   ├── generate_formula.py            angr symbex → ProgramFormula
│   ├── safety_policy.py               Aya-side safety rules
│   ├── prompts.py / llm_client.py     LLM driver
│   ├── AGENTS.md                      Translation rules shown to the agent
│   ├── c_bpf_programs/                102 C eBPF programs (.c + .o)
│   └── verified_translations/         96 verified Aya Rust translations (.rs + .o)
├── environment.yml         conda env spec (Python 3.10 + angr stack + Z3 + LLM SDKs)
├── README.md               (this file)
└── LICENSE
```

## Installation

Both components run inside a single conda environment named `c2rust`. The
angr backend is installed *into* that environment as an editable package.

### 1. Create the conda environment

```bash
conda env create -f environment.yml
conda activate c2rust
```

This pins Python 3.10, the angr 9.2.176 stack, `z3-solver`, and the
`anthropic` / `openai` LLM client libraries.

### 2. Install the angr eBPF backend

```bash
pip install -e angr_ebpf_backend
```

Verify the install:

```bash
python -c "import angr_ebpf; print('eBPF backend OK')"
```

### 3. (Optional) LLM API keys

The translation pipeline calls Anthropic or OpenAI. Export the relevant
key(s) before running an agent:

```bash
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
```

If you only want to run the symbolic-equivalence checker against the
already-verified translations in `verified_translations/`, no LLM key is
needed.

## Quick start: re-verify one of the 96 translations

To confirm the symbolic equivalence checker works end-to-end without
needing an LLM key, pick any verified translation and run the equivalence
check directly:

```bash
cd c2rust_translation
python verify_mixed_entries.py \
    c_bpf_programs/libbpf-tools/biostacks.o \
    verified_translations/libbpf_tools__biostacks/libbpf_tools__biostacks.o \
    blk_account_io_done blk_account_io_done \
    rqinfos:hash hists:hash
```

A passing run prints `equivalent: True` for the entry symbol; the same
program has 5 entry points that can be checked one at a time.

## Translating a single program with the LLM pipeline

The full single-program pipeline (LLM translate → compile → kernel-verify
→ safety-check → symbex equivalence, with retry loops) is in
`run_translation.py`. The file `run_translation_commands.txt` contains a
ready-to-run command for each of the 102 C programs, using
`--all-entries` to verify every entry point in each binary.

Example (one program):

```bash
cd c2rust_translation
python run_translation.py \
    c_bpf_programs/libbpf-tools/biostacks.bpf.c \
    c_bpf_programs/libbpf-tools/biostacks.o \
    blk_account_io_done \
    --all-entries \
    rqinfos:hash hists:hash \
    --provider anthropic --model claude-opus-4-6
```

## Reproducing the paper: 102-program agentic sweep

`agent_code_translate.sh` is the driver that runs an LLM agent over the
full 102-program set, capturing per-program metadata (wall time, token
usage, attempts) and bucketing each result into
`agent_code_attempt/{verified,partially_verified,failed,skipped}/`.

```bash
cd c2rust_translation
sudo -E bash agent_code_translate.sh                                          # claude-opus-4-6 (default)
sudo -E bash agent_code_translate.sh --agent claude --model claude-sonnet-4-6 # claude sonnet 4.6
sudo -E bash agent_code_translate.sh --agent codex                            # OpenAI Codex
sudo -E bash agent_code_translate.sh --agent gemini --model gemini-2.5-pro    # Google Gemini
```

`sudo -E` is needed only for the in-kernel BPF verifier preflight; the
LLM call itself is unprivileged.

The script removes any prior result for each listed program before
re-running, so each invocation is a clean attempt. Use `--start N`
/ `--end N` to run a sub-range, or `--skip-verified` to skip programs
already in `verified/`.

## Static safety policy

`safety_policy.py` enforces a small set of structural rules on the
candidate Rust translation that the equivalence checker cannot see —
e.g. forbidding the use of raw generated helpers when a safe Aya wrapper
exists, requiring `Err(_) => return ...` on every `match` block
scrutinising a failable BPF helper, and rejecting `let _ = ...` discards
of helper Results. The driver script runs this check after the
in-kernel verifier and treats any blocking violation as a translation
failure.

## License

See [`LICENSE`](LICENSE).
