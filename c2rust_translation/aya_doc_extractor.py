"""Extract relevant Aya API documentation from cargo doc HTML output.

Analyzes a C eBPF source file to determine which Aya modules are needed,
then extracts the corresponding API docs from a local cargo doc build.
"""

import os
import re
from html.parser import HTMLParser

C_PATTERN_TO_AYA_DOCS = {

    r'BPF_MAP_TYPE_HASH': ('aya/maps/hash_map/struct.HashMap.html', 'HashMap'),
    r'BPF_MAP_TYPE_ARRAY': ('aya/maps/array/struct.Array.html', 'Array'),
    r'BPF_MAP_TYPE_PERCPU_ARRAY': ('aya/maps/array/struct.PerCpuArray.html', 'PerCpuArray'),
    r'BPF_MAP_TYPE_PERF_EVENT': ('aya/maps/perf/struct.PerfEventArray.html', 'PerfEventArray'),
    r'BPF_MAP_TYPE_RINGBUF': ('aya/maps/ring_buf/struct.RingBuf.html', 'RingBuf'),
    r'BPF_MAP_TYPE_STACK_TRACE': ('aya/maps/stack_trace/struct.StackTrace.html', 'StackTrace'),

    r'SEC\("tracepoint': ('aya_ebpf_macros/attr.tracepoint.html', 'tracepoint macro'),
    r'SEC\("kprobe': ('aya_ebpf_macros/attr.kprobe.html', 'kprobe macro'),
    r'SEC\("kretprobe': ('aya_ebpf_macros/attr.kretprobe.html', 'kretprobe macro'),
    r'SEC\("raw_tracepoint': ('aya_ebpf_macros/attr.raw_tracepoint.html', 'raw_tracepoint macro'),
    r'SEC\("lsm': ('aya_ebpf_macros/attr.lsm.html', 'lsm macro'),
}

RUST_PATTERN_TO_AYA_DOCS = {
    r'(?:aya_ebpf::maps::)?HashMap': ('aya/maps/hash_map/struct.HashMap.html', 'HashMap'),
    r'(?:aya_ebpf::maps::)?(?:Array\b|maps::array)': ('aya/maps/array/struct.Array.html', 'Array'),
    r'PerCpuArray': ('aya/maps/array/struct.PerCpuArray.html', 'PerCpuArray'),
    r'PerfEventArray': ('aya/maps/perf/struct.PerfEventArray.html', 'PerfEventArray'),
    r'RingBuf': ('aya/maps/ring_buf/struct.RingBuf.html', 'RingBuf'),
    r'StackTrace': ('aya/maps/stack_trace/struct.StackTrace.html', 'StackTrace'),
    r'#\[tracepoint': ('aya_ebpf_macros/attr.tracepoint.html', 'tracepoint macro'),
    r'#\[kprobe': ('aya_ebpf_macros/attr.kprobe.html', 'kprobe macro'),
    r'#\[kretprobe': ('aya_ebpf_macros/attr.kretprobe.html', 'kretprobe macro'),
    r'#\[raw_tracepoint': ('aya_ebpf_macros/attr.raw_tracepoint.html', 'raw_tracepoint macro'),
    r'#\[lsm': ('aya_ebpf_macros/attr.lsm.html', 'lsm macro'),
}

class _HTMLToText(HTMLParser):
    """Minimal HTML-to-text converter for cargo doc pages."""

    def __init__(self):
        super().__init__()
        self._pieces = []
        self._skip = False
        self._in_pre = False
        self._skip_tags = {'script', 'style', 'nav', 'head'}
        self._block_tags = {'p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                            'li', 'tr', 'br', 'pre', 'blockquote', 'dt', 'dd'}

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            self._skip = True
            return
        if tag == 'pre':
            self._in_pre = True
            self._pieces.append('\n```\n')
        elif tag in self._block_tags:
            self._pieces.append('\n')
        elif tag == 'code' and not self._in_pre:
            self._pieces.append('`')

    def handle_endtag(self, tag):
        if tag in self._skip_tags:
            self._skip = False
            return
        if tag == 'pre':
            self._in_pre = False
            self._pieces.append('\n```\n')
        elif tag == 'code' and not self._in_pre:
            self._pieces.append('`')
        elif tag in self._block_tags:
            self._pieces.append('\n')

    def handle_data(self, data):
        if self._skip:
            return
        self._pieces.append(data)

    def get_text(self):
        raw = ''.join(self._pieces)

        raw = re.sub(r'\n{3,}', '\n\n', raw)
        return raw.strip()

def _html_to_text(html_content):
    """Convert HTML to plain text / markdown."""
    parser = _HTMLToText()
    parser.feed(html_content)
    return parser.get_text()

def _extract_doc_section(html_content):
    """Extract the main documentation section from a cargo doc HTML page.

    Cargo doc pages have the main content inside a <main> tag (which may
    contain nested <section> tags).  We must match <main>...</main>
    without stopping at inner </section> tags.
    """

    main_match = re.search(
        r'<main[^>]*>(.*)</main>',
        html_content,
        re.DOTALL | re.IGNORECASE,
    )
    if main_match:
        return _html_to_text(main_match.group(1))

    section_match = re.search(
        r'<section\s+id="main-content"[^>]*>(.*)</section>',
        html_content,
        re.DOTALL | re.IGNORECASE,
    )
    if section_match:
        return _html_to_text(section_match.group(1))

    return _html_to_text(html_content)

def _find_doc_root(aya_docs_path):
    """Locate the cargo doc output root directory (target/doc/).

    The user may pass the repo root, the target/ dir, or target/doc/ directly.
    We verify the directory contains at least one of the expected crate doc
    directories (aya/, aya_ebpf_macros/).
    """
    candidates = [
        os.path.join(aya_docs_path, 'target', 'doc'),
        os.path.join(aya_docs_path, 'doc'),
        aya_docs_path,
    ]
    marker_dirs = ('aya', 'aya_ebpf_macros', 'aya_ebpf')
    for candidate in candidates:
        if os.path.isdir(candidate) and any(
            os.path.isdir(os.path.join(candidate, m)) for m in marker_dirs
        ):
            return candidate
    return None

_find_aya_ebpf_doc_root = _find_doc_root

def _fetch_doc_sections(doc_root, needed, max_chars):
    """Fetch and assemble doc sections for a list of (html_path, title) pairs.

    Returns a list of markdown section strings within the character budget.
    """
    sections = []
    total_chars = 0

    seen = set()
    deduped = []
    for html_path, title in needed:
        if html_path in seen:
            continue
        seen.add(html_path)
        deduped.append((html_path, title))

    for html_path, title in deduped:
        full_path = os.path.join(doc_root, html_path)
        if not os.path.isfile(full_path):
            continue

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except (OSError, UnicodeDecodeError):
            continue

        doc_text = _extract_doc_section(html_content)
        if not doc_text:
            continue

        for noise_heading in (
            'Auto Trait Implementations',
            'Blanket Implementations',
        ):
            idx = doc_text.find(noise_heading)
            if idx > 0:
                doc_text = doc_text[:idx].rstrip()

        section = f"### {title}\n\n{doc_text}"

        if total_chars + len(section) > max_chars:
            remaining = max_chars - total_chars
            if remaining > 200:
                section = section[:remaining] + "\n... (truncated)"
                sections.append(section)
            break

        sections.append(section)
        total_chars += len(section)

    return sections

def _format_doc_sections(sections):
    """Wrap a list of doc section strings with the standard header."""
    if not sections:
        return ""
    header = (
        "\n## Aya API Reference (from local cargo doc build)\n"
        "IMPORTANT: These docs are from the `aya` userspace crate. In your eBPF code,\n"
        "use the equivalent `aya_ebpf` kernel-space crate instead:\n"
        "  - `aya::maps::HashMap` → use `aya_ebpf::maps::HashMap`\n"
        "  - `aya::maps::Array` → use `aya_ebpf::maps::Array`\n"
        "  - The method signatures (get, get_ptr, get_ptr_mut, insert, etc.) are the same.\n"
        "Refer to these docs for API details (methods, type parameters), but always import from `aya_ebpf`.\n\n"
    )
    return header + "\n\n".join(sections) + "\n"

def extract_relevant_docs(c_source, aya_docs_path, max_chars=8000):
    """Analyze C source, extract relevant Aya API docs from cargo doc HTML.

    Args:
        c_source: The C eBPF source code to analyze.
        aya_docs_path: Path to the Aya repo or its cargo doc output directory.
        max_chars: Maximum characters for the assembled doc snippet.

    Returns:
        A markdown string suitable for prompt injection, or empty string
        if no docs could be extracted.
    """
    doc_root = _find_doc_root(aya_docs_path)
    if doc_root is None:
        print(f"[aya_doc_extractor] Warning: could not find Aya docs under {aya_docs_path}")
        return ""

    needed = []
    for pattern, (html_path, title) in C_PATTERN_TO_AYA_DOCS.items():
        if re.search(pattern, c_source):
            needed.append((html_path, title))

    if not needed:
        return ""

    return _format_doc_sections(_fetch_doc_sections(doc_root, needed, max_chars))

def extract_docs_for_error(rust_code, error_log, aya_docs_path, max_chars=4000):
    """Extract relevant Aya API docs based on Rust code and error messages.

    Scans the Rust source and compiler/verifier error output for Aya type
    and macro references, then returns the matching API documentation.
    Uses a smaller budget than the initial injection since this supplements
    error context rather than replacing it.

    Args:
        rust_code: The current Rust eBPF source code.
        error_log: Compiler or verifier error output.
        aya_docs_path: Path to the Aya repo or its cargo doc output directory.
        max_chars: Maximum characters for the assembled doc snippet.

    Returns:
        A markdown string with relevant docs, or empty string.
    """
    if not aya_docs_path:
        return ""

    doc_root = _find_doc_root(aya_docs_path)
    if doc_root is None:
        return ""

    combined = rust_code + "\n" + error_log
    needed = []
    for pattern, (html_path, title) in RUST_PATTERN_TO_AYA_DOCS.items():
        if re.search(pattern, combined):
            needed.append((html_path, title))

    if not needed:
        return ""

    return _format_doc_sections(_fetch_doc_sections(doc_root, needed, max_chars))
