#!/bin/bash
# Generic agentic translator: drives one of {claude, codex, gemini} over the
# 102 C eBPF programs, producing Aya Rust translations and verifying each
# one (compile, kernel-verify, safety-policy, symbex equivalence).
#
# Usage:
#   sudo -E bash agent_code_translate.sh \
#       [--agent claude|codex|gemini] [--model MODEL] \
#       [--start N] [--end N] [--skip-verified]
#
# Defaults: --agent claude --model claude-opus-4-6
# Examples:
#   sudo -E bash agent_code_translate.sh --agent claude  --model claude-sonnet-4-6
#   sudo -E bash agent_code_translate.sh --agent codex
#   sudo -E bash agent_code_translate.sh --agent gemini  --model gemini-2.5-pro
#
# Before running, this script removes any existing agent_code_attempt/
# bucket entry for each listed program so the agent starts fresh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RESULT_DIR="$SCRIPT_DIR/agent_code_attempt"
VERIFIED_DIR="$RESULT_DIR/verified"
FAILED_DIR="$RESULT_DIR/failed"
SKIPPED_DIR="$RESULT_DIR/skipped"
PARTIALLY_VERIFIED_DIR="$RESULT_DIR/partially_verified"
mkdir -p "$VERIFIED_DIR" "$FAILED_DIR" "$SKIPPED_DIR" "$PARTIALLY_VERIFIED_DIR"

# ── Step 1: Remove stale results for the listed programs ────────────────────
echo "=== Cleaning stale results for listed programs ==="
PROGRAM_NAMES=(
    "ebpf_se__crab_simple"
    "ebpf_se__dae_kern"
    "ebpf_se__fluvia_xdp"
    "ebpf_se__hercules_simple"
    "ebpf_se__xdp_csum_kern"
    "ebpf_se__xdp_fw_kern"
    "ebpf_se__xdp_map_access_kern"
    "ken_libbpf__accept-latency"
    "ken_libbpf__bashreadline"
    "ken_libbpf__biolatency"
    "ken_libbpf__bpf-jit"
    "ken_libbpf__cachestat"
    "ken_libbpf__cgroup"
    "ken_libbpf__execsnoop"
    "ken_libbpf__exitsnoop"
    "ken_libbpf__kfree_skb"
    "ken_libbpf__kprobe-link"
    "ken_libbpf__llcstat"
    "ken_libbpf__minimal"
    "ken_libbpf__oomkill"
    "ken_libbpf__opensnoop"
    "ken_libbpf__percpu-softirq"
    "ken_libbpf__raw-tracepoints"
    "ken_libbpf__shrinklat"
    "ken_libbpf__sigsnoop"
    "ken_libbpf__syscalls"
    "ken_libbpf__tcp-syn-backlog"
    "ken_libbpf__tcp-window-clamps"
    "ken_libbpf__timers"
    "ken_libbpf__udp-drops"
    "ken_libbpf__uprobe"
    "ken_libbpf__xdp"
    "libbpf_bootstrap__bootstrap"
    "libbpf_bootstrap__bootstrap_legacy"
    "libbpf_bootstrap__fentry"
    "libbpf_bootstrap__kprobe"
    "libbpf_bootstrap__ksyscall"
    "libbpf_bootstrap__lsm"
    "libbpf_bootstrap__minimal"
    "libbpf_bootstrap__minimal_legacy"
    "libbpf_bootstrap__minimal_ns"
    "libbpf_bootstrap__profile"
    "libbpf_bootstrap__sockfilter"
    "libbpf_bootstrap__tc"
    "libbpf_bootstrap__uprobe"
    "libbpf_tools__bashreadline"
    "libbpf_tools__biopattern"
    "libbpf_tools__biostacks"
    "libbpf_tools__biotop"
    "libbpf_tools__bitesize"
    "libbpf_tools__cachestat"
    "libbpf_tools__drsnoop"
    "libbpf_tools__filelife"
    "libbpf_tools__filetop"
    "libbpf_tools__fsdist"
    "libbpf_tools__fsslower"
    "libbpf_tools__futexctn"
    "libbpf_tools__gethostlatency"
    "libbpf_tools__javagc"
    "libbpf_tools__klockstat"
    "libbpf_tools__ksnoop"
    "libbpf_tools__llcstat"
    "libbpf_tools__mdflush"
    "libbpf_tools__memleak"
    "libbpf_tools__mountsnoop"
    "libbpf_tools__numamove"
    "libbpf_tools__offcputime"
    "libbpf_tools__oomkill"
    "libbpf_tools__opensnoop"
    "libbpf_tools__profile"
    "libbpf_tools__readahead"
    "libbpf_tools__runqlen"
    "libbpf_tools__runqslower"
    "libbpf_tools__sigsnoop"
    "libbpf_tools__slabratetop"
    "libbpf_tools__softirqs"
    "libbpf_tools__solisten"
    "libbpf_tools__statsnoop"
    "libbpf_tools__syncsnoop"
    "libbpf_tools__tcpconnect"
    "libbpf_tools__tcpconnlat"
    "libbpf_tools__tcpktlat"
    "libbpf_tools__tcplife"
    "libbpf_tools__tcprtt"
    "libbpf_tools__tcpstates"
    "libbpf_tools__tcpsynbl"
    "libbpf_tools__tcptracer"
    "libbpf_tools__vfsstat"
    "libbpf_tools__wakeuptime"
    "research__cache_ext_fifo"
    "research__cache_ext_get_scan"
    "research__cache_ext_mru"
    "research__cache_ext_s3fifo"
    "research__cache_ext_sampling"
    "suricata__bypass_filter"
    "suricata__filter"
    "suricata__vlan_filter"
    "suricata__xdp_filter"
    "research__bmc_kern"
    "research__cache_ext_lhd"
    "research__cache_ext_mglru"
    "suricata__xdp_lb"
)
for prog in "${PROGRAM_NAMES[@]}"; do
    for d in \
        "$VERIFIED_DIR/$prog" \
        "$FAILED_DIR/$prog" \
        "$PARTIALLY_VERIFIED_DIR/$prog" \
        "$SKIPPED_DIR/$prog" \
        "$RESULT_DIR/in_progress/$prog"
    do
        if [ -d "$d" ]; then
            echo "  rm -rf $d"
            rm -rf "$d"
        fi
    done
done
echo ""

START=${START:-1}
END=${END:-999}
SKIP_VERIFIED=${SKIP_VERIFIED:-0}
AGENT=${AGENT:-claude}             # claude | codex | gemini
MODEL=${MODEL:-}                   # default depends on AGENT, see below

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --start) START="$2"; shift 2 ;;
        --end) END="$2"; shift 2 ;;
        --skip-verified) SKIP_VERIFIED=1; shift ;;
        --agent) AGENT="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Default model per agent.  Override with --model.
case "$AGENT" in
    claude)  : "${MODEL:=claude-opus-4-6}" ;;
    codex)   : "${MODEL:=}" ;;                # codex picks its own default
    gemini)  : "${MODEL:=gemini-2.5-pro}" ;;
    *)       echo "Unknown --agent: $AGENT (must be claude|codex|gemini)"; exit 1 ;;
esac

# Sanity: the chosen agent CLI must be on PATH.
if ! command -v "$AGENT" >/dev/null 2>&1; then
    echo "ERROR: '$AGENT' CLI not found on PATH."
    case "$AGENT" in
        claude) echo "  Install: https://docs.anthropic.com/en/docs/claude-code/quickstart" ;;
        codex)  echo "  Install: https://github.com/openai/codex" ;;
        gemini) echo "  Install: https://github.com/google-gemini/gemini-cli" ;;
    esac
    exit 1
fi
echo "Agent: $AGENT  Model: ${MODEL:-<default>}"
echo ""

# ── Unified program list: c_dir|source|obj|dataset_prefix|maps ───────────────
# Full 102-program canonical set (matches paper_scripts/analyze_agent_sessions.py).
PROGRAMS=(
    "c_bpf_programs/ebpf-se/crab|crab_simple.c|crab_simple.o|ebpf_se__|targets_map:array macs_map:hash targets_count:array cpu_rr_idx:percpu_array"
    "c_bpf_programs/ebpf-se/dae|dae_kern.c|dae_kern.o|ebpf_se__|skb_addresses:hash events:ringbuf"
    "c_bpf_programs/ebpf-se/fluvia|fluvia_xdp.c|obj/fluvia_xdp.o|ebpf_se__|packet_probe_perf:perf_event_array"
    "c_bpf_programs/ebpf-se/hercules|hercules_simple.c|hercules_simple.o|ebpf_se__|xsks_map:xskmap num_xsks:array local_addr:array"
    "c_bpf_programs/ebpf-se/fw|xdp_csum_kern.c|xdp_csum_kern.o|ebpf_se__|rxcnt:percpu_array"
    "c_bpf_programs/ebpf-se/fw|xdp_fw_kern.c|xdp_fw_kern.o|ebpf_se__|tx_port:devmap flow_ctx_table:hash"
    "c_bpf_programs/ebpf-se/fw|xdp_map_access_kern.c|xdp_map_access_kern.o|ebpf_se__|rxcnt:percpu_hash"
    "c_bpf_programs/KEN/dataset/libbpf|accept-latency.bpf.c|accept-latency.bpf.o|ken_libbpf__|start:hash accept_latency_seconds:hash"
    "c_bpf_programs/KEN/dataset/libbpf|bashreadline.bpf.c|bashreadline.bpf.o|ken_libbpf__|"
    "c_bpf_programs/KEN/dataset/libbpf|biolatency.bpf.c|biolatency.bpf.o|ken_libbpf__|start:hash bio_latency_seconds:hash"
    "c_bpf_programs/KEN/dataset/libbpf|bpf-jit.bpf.c|bpf-jit.bpf.o|ken_libbpf__|bpf_jit_pages_currently_allocated:array"
    "c_bpf_programs/KEN/dataset/libbpf|cachestat.bpf.c|cachestat.bpf.o|ken_libbpf__|page_cache_ops_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|cgroup.bpf.c|cgroup.bpf.o|ken_libbpf__|cgroup_sched_migrations_total:lru_hash"
    "c_bpf_programs/KEN/dataset/libbpf|execsnoop.bpf.c|execsnoop.bpf.o|ken_libbpf__|events:perf_event_array"
    "c_bpf_programs/KEN/dataset/libbpf|exitsnoop.bpf.c|exitsnoop.bpf.o|ken_libbpf__|rb:ringbuf"
    "c_bpf_programs/KEN/dataset/libbpf|kfree_skb.bpf.c|kfree_skb.bpf.o|ken_libbpf__|kfree_skb_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|kprobe-link.bpf.c|kprobe-link.bpf.o|ken_libbpf__|"
    "c_bpf_programs/KEN/dataset/libbpf|llcstat.bpf.c|llcstat.bpf.o|ken_libbpf__|llc_references_total:hash llc_misses_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|minimal.bpf.c|minimal.bpf.o|ken_libbpf__|"
    "c_bpf_programs/KEN/dataset/libbpf|oomkill.bpf.c|oomkill.bpf.o|ken_libbpf__|oom_kills_total:perf_event_array"
    "c_bpf_programs/KEN/dataset/libbpf|opensnoop.bpf.c|opensnoop.bpf.o|ken_libbpf__|"
    "c_bpf_programs/KEN/dataset/libbpf|percpu-softirq.bpf.c|percpu-softirq.bpf.o|ken_libbpf__|softirqs_total:percpu_hash"
    "c_bpf_programs/KEN/dataset/libbpf|raw-tracepoints.bpf.c|raw-tracepoints.bpf.o|ken_libbpf__|raw_timer_starts_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|shrinklat.bpf.c|shrinklat.bpf.o|ken_libbpf__|start:hash shrink_node_latency_seconds:array"
    "c_bpf_programs/KEN/dataset/libbpf|sigsnoop.bpf.c|sigsnoop.bpf.o|ken_libbpf__|values:hash"
    "c_bpf_programs/KEN/dataset/libbpf|syscalls.bpf.c|syscalls.bpf.o|ken_libbpf__|syscalls_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|tcp-syn-backlog.bpf.c|tcp-syn-backlog.bpf.o|ken_libbpf__|tcp_syn_backlog:hash"
    "c_bpf_programs/KEN/dataset/libbpf|tcp-window-clamps.bpf.c|tcp-window-clamps.bpf.o|ken_libbpf__|tcp_window_clamps_total:array tcp_rmem_schedule_enters:lru_hash"
    "c_bpf_programs/KEN/dataset/libbpf|timers.bpf.c|timers.bpf.o|ken_libbpf__|timer_starts_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|udp-drops.bpf.c|udp-drops.bpf.o|ken_libbpf__|udp_fail_queue_rcv_skbs_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|uprobe.bpf.c|uprobe.bpf.o|ken_libbpf__|libc_malloc_calls_total:hash"
    "c_bpf_programs/KEN/dataset/libbpf|xdp.bpf.c|xdp.bpf.o|ken_libbpf__|xdp_incoming_packets_total:lru_hash"
    "c_bpf_programs/libbpf_bootstrap_standalone|bootstrap.bpf.c|bootstrap.bpf.o|libbpf_bootstrap__|exec_start:hash rb:ringbuf"
    "c_bpf_programs/libbpf_bootstrap_standalone|bootstrap_legacy.bpf.c|bootstrap_legacy.bpf.o|libbpf_bootstrap__|exec_start:hash perf_buffer:perf_event_array"
    "c_bpf_programs/libbpf_bootstrap_standalone|fentry.bpf.c|fentry.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|kprobe.bpf.c|kprobe.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|ksyscall.bpf.c|ksyscall.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|lsm.bpf.c|lsm.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|minimal.bpf.c|minimal.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|minimal_legacy.bpf.c|minimal_legacy.bpf.o|libbpf_bootstrap__|my_pid_map:array"
    "c_bpf_programs/libbpf_bootstrap_standalone|minimal_ns.bpf.c|minimal_ns.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|profile.bpf.c|profile.bpf.o|libbpf_bootstrap__|events:ringbuf"
    "c_bpf_programs/libbpf_bootstrap_standalone|sockfilter.bpf.c|sockfilter.bpf.o|libbpf_bootstrap__|rb:ringbuf"
    "c_bpf_programs/libbpf_bootstrap_standalone|tc.bpf.c|tc.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf_bootstrap_standalone|uprobe.bpf.c|uprobe.bpf.o|libbpf_bootstrap__|"
    "c_bpf_programs/libbpf-tools|bashreadline.bpf.c|bashreadline.o|libbpf_tools__|events:perf_event_array"
    "c_bpf_programs/libbpf-tools|biopattern.bpf.c|biopattern.o|libbpf_tools__|counters:hash"
    "c_bpf_programs/libbpf-tools|biostacks.bpf.c|biostacks.o|libbpf_tools__|rqinfos:hash hists:hash"
    "c_bpf_programs/libbpf-tools|biotop.bpf.c|biotop.o|libbpf_tools__|start:hash whobyreq:hash counts:hash"
    "c_bpf_programs/libbpf-tools|bitesize.bpf.c|bitesize.o|libbpf_tools__|hists:hash"
    "c_bpf_programs/libbpf-tools|cachestat.bpf.c|cachestat.o|libbpf_tools__|"
    "c_bpf_programs/libbpf-tools|drsnoop.bpf.c|drsnoop.o|libbpf_tools__|start:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|filelife.bpf.c|filelife.o|libbpf_tools__|heap:percpu_array events:ringbuf start:hash currevent:hash"
    "c_bpf_programs/libbpf-tools|filetop.bpf.c|filetop.o|libbpf_tools__|entries:hash"
    "c_bpf_programs/libbpf-tools|fsdist.bpf.c|fsdist.o|libbpf_tools__|starts:hash"
    "c_bpf_programs/libbpf-tools|fsslower.bpf.c|fsslower.o|libbpf_tools__|starts:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|futexctn.bpf.c|futexctn.o|libbpf_tools__|start:hash stackmap:stack_trace hists:hash"
    "c_bpf_programs/libbpf-tools|gethostlatency.bpf.c|gethostlatency.o|libbpf_tools__|starts:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|javagc.bpf.c|javagc.o|libbpf_tools__|__bpf_usdt_specs:array __bpf_usdt_ip_to_spec_id:hash data_map:hash perf_map:perf_event_array"
    "c_bpf_programs/libbpf-tools|klockstat.bpf.c|klockstat.o|libbpf_tools__|stack_map:stack_trace lockholder_map:hash stat_map:hash locks:hash task_states:hash"
    "c_bpf_programs/libbpf-tools|ksnoop.bpf.c|ksnoop.o|libbpf_tools__|ksnoop_func_stack:hash ksnoop_func_map:percpu_hash ksnoop_perf_map:perf_event_array"
    "c_bpf_programs/libbpf-tools|llcstat.bpf.c|llcstat.o|libbpf_tools__|infos:hash"
    "c_bpf_programs/libbpf-tools|mdflush.bpf.c|mdflush.o|libbpf_tools__|events:perf_event_array"
    "c_bpf_programs/libbpf-tools|memleak.bpf.c|memleak.o|libbpf_tools__|sizes:hash allocs:hash combined_allocs:hash memptrs:hash stack_traces:stack_trace"
    "c_bpf_programs/libbpf-tools|mountsnoop.bpf.c|mountsnoop.o|libbpf_tools__|heap:percpu_array events:ringbuf args:hash"
    "c_bpf_programs/libbpf-tools|numamove.bpf.c|numamove.o|libbpf_tools__|start:hash"
    "c_bpf_programs/libbpf-tools|offcputime.bpf.c|offcputime.o|libbpf_tools__|start:hash stackmap:stack_trace info:hash tgids:hash pids:hash"
    "c_bpf_programs/libbpf-tools|oomkill.bpf.c|oomkill.o|libbpf_tools__|heap:percpu_array events:ringbuf"
    "c_bpf_programs/libbpf-tools|opensnoop.bpf.c|opensnoop.o|libbpf_tools__|heap:percpu_array events:ringbuf start:hash"
    "c_bpf_programs/libbpf-tools|profile.bpf.c|profile.o|libbpf_tools__|stackmap:stack_trace counts:hash pids:hash tids:hash"
    "c_bpf_programs/libbpf-tools|readahead.bpf.c|readahead.o|libbpf_tools__|in_readahead:hash birth:hash"
    "c_bpf_programs/libbpf-tools|runqlen.bpf.c|runqlen.o|libbpf_tools__|"
    "c_bpf_programs/libbpf-tools|runqslower.bpf.c|runqslower.o|libbpf_tools__|start:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|sigsnoop.bpf.c|sigsnoop.o|libbpf_tools__|values:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|slabratetop.bpf.c|slabratetop.o|libbpf_tools__|slab_entries:hash"
    "c_bpf_programs/libbpf-tools|softirqs.bpf.c|softirqs.o|libbpf_tools__|start:percpu_array"
    "c_bpf_programs/libbpf-tools|solisten.bpf.c|solisten.o|libbpf_tools__|values:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|statsnoop.bpf.c|statsnoop.o|libbpf_tools__|values:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|syncsnoop.bpf.c|syncsnoop.o|libbpf_tools__|events:perf_event_array"
    "c_bpf_programs/libbpf-tools|tcpconnect.bpf.c|tcpconnect.o|libbpf_tools__|sockets:hash ipv4_count:hash ipv6_count:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|tcpconnlat.bpf.c|tcpconnlat.o|libbpf_tools__|start:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|tcpktlat.bpf.c|tcpktlat.o|libbpf_tools__|heap:percpu_array events:ringbuf start:hash"
    "c_bpf_programs/libbpf-tools|tcplife.bpf.c|tcplife.o|libbpf_tools__|birth:hash idents:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|tcprtt.bpf.c|tcprtt.o|libbpf_tools__|hists:hash"
    "c_bpf_programs/libbpf-tools|tcpstates.bpf.c|tcpstates.o|libbpf_tools__|sports:hash dports:hash timestamps:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|tcpsynbl.bpf.c|tcpsynbl.o|libbpf_tools__|hists:hash"
    "c_bpf_programs/libbpf-tools|tcptracer.bpf.c|tcptracer.o|libbpf_tools__|tuplepid:hash sockets:hash events:perf_event_array"
    "c_bpf_programs/libbpf-tools|vfsstat.bpf.c|vfsstat.o|libbpf_tools__|"
    "c_bpf_programs/libbpf-tools|wakeuptime.bpf.c|wakeuptime.o|libbpf_tools__|counts:hash start:hash stackmap:stack_trace"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_fifo.bpf.c|cache_ext_fifo.bpf.o|research__|inode_watchlist:hash"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_get_scan.bpf.c|cache_ext_get_scan.bpf.o|research__|scan_pids:hash folio_metadata_map:hash sampling_list_map:array stats:hash inode_watchlist:hash"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_mru.bpf.c|cache_ext_mru.bpf.o|research__|inode_watchlist:hash"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_s3fifo.bpf.c|cache_ext_s3fifo.bpf.o|research__|folio_metadata_map:hash ghost_map:lru_hash inode_watchlist:hash"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_sampling.bpf.c|cache_ext_sampling.bpf.o|research__|folio_metadata_map:hash stats:hash inode_watchlist:hash"
    "c_bpf_programs/suricata/ebpf|bypass_filter.c|bypass_filter.o|suricata__|flow_table_v4:percpu_hash flow_table_v6:percpu_hash"
    "c_bpf_programs/suricata/ebpf|filter.c|filter.o|suricata__|ipv4_drop:percpu_hash"
    "c_bpf_programs/suricata/ebpf|vlan_filter.c|vlan_filter.o|suricata__|"
    "c_bpf_programs/suricata/ebpf|xdp_filter.c|xdp_filter.o|suricata__|cpu_map:cpumap cpus_available:array cpus_count:array flow_table_v4:percpu_hash flow_table_v6:percpu_hash tx_peer:devmap tx_peer_int:array"
    "c_bpf_programs/research_papers/bmc-cache/bmc|bmc_kern.c|bmc_kern.o|research__|map_kcache:array map_keys:percpu_array map_parsing_context:percpu_array map_stats:percpu_array map_progs_xdp:prog_array map_progs_tc:prog_array"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_lhd.bpf.c|cache_ext_lhd.bpf.o|research__|folio_metadata_map:hash events:ringbuf inode_watchlist:hash"
    "c_bpf_programs/research_papers/cache_ext/policies|cache_ext_mglru.bpf.c|cache_ext_mglru.bpf.o|research__|folio_metadata_map:hash ghost_map:lru_hash mglru_global_metadata_map:array mglru_percpu_array:percpu_array"
    "c_bpf_programs/suricata/ebpf|xdp_lb.c|xdp_lb.o|suricata__|cpu_map:cpumap cpus_available:array cpus_count:array"
)

TOTAL=${#PROGRAMS[@]}
echo "=== Translating $TOTAL programs ==="
echo "Results: $RESULT_DIR"
echo "Range: $START to $END"
echo ""

OK=0
FAIL=0
SKIP=0
PARTIAL=0

for i in "${!PROGRAMS[@]}"; do
    IDX=$((i + 1))
    if [ "$IDX" -lt "$START" ] || [ "$IDX" -gt "$END" ]; then
        continue
    fi

    IFS='|' read -r C_DIR_REL C_SOURCE OBJ DATASET_PREFIX MAPS <<< "${PROGRAMS[$i]}"

    PROG_BASE="${C_SOURCE%.c}"
    PROG_BASE="${PROG_BASE%.bpf}"
    PROG_NAME="${DATASET_PREFIX}${PROG_BASE}"

    # Resolve C_DIR and OBJ path
    C_DIR="$C_DIR_REL"
    OBJ_PATH="$C_DIR_REL/$OBJ"

    # Skip if already done
    if [ "$SKIP_VERIFIED" = "1" ] && [ -d "$VERIFIED_DIR/$PROG_NAME" ]; then
        echo "[$IDX/$TOTAL] $PROG_NAME — SKIP (already verified)"
        SKIP=$((SKIP + 1))
        continue
    fi
    if [ -d "$VERIFIED_DIR/$PROG_NAME" ] || [ -d "$FAILED_DIR/$PROG_NAME" ] || [ -d "$PARTIALLY_VERIFIED_DIR/$PROG_NAME" ]; then
        echo "[$IDX/$TOTAL] $PROG_NAME — SKIP (already attempted)"
        SKIP=$((SKIP + 1))
        continue
    fi

    echo ""
    echo "======================================================================="
    echo "[$IDX/$TOTAL] $PROG_NAME (maps: $MAPS)"
    echo "======================================================================="

    # ── C kernel preflight ────────────────────────────────────────────────
    if [ -d "$SKIPPED_DIR/$PROG_NAME" ]; then
        echo "[$IDX/$TOTAL] $PROG_NAME — SKIP (C kernel verify failed previously)"
        SKIP=$(($SKIP + 1))
        continue
    fi

    echo "[$IDX/$TOTAL] Running C kernel preflight..."
    set +e; sudo env PATH="$PATH" python3 verify_ebpf_kernel.py "$OBJ_PATH" > /dev/null 2>&1; PREFLIGHT_EXIT=$?; set -e
    if [ $PREFLIGHT_EXIT -eq 2 ]; then
        echo "[$IDX/$TOTAL] $PROG_NAME — WARNING: unknown section type, skipping preflight"
    elif [ $PREFLIGHT_EXIT -ne 0 ]; then
        echo "[$IDX/$TOTAL] $PROG_NAME — SKIP (C binary rejected by kernel verifier)"
        mkdir -p "$SKIPPED_DIR/$PROG_NAME"
        echo "C kernel verify failed" > "$SKIPPED_DIR/$PROG_NAME/reason.txt"
        SKIP=$(($SKIP + 1))
        continue
    fi
    echo "[$IDX/$TOTAL] C preflight passed."

    PROG_DIR="$RESULT_DIR/in_progress/$PROG_NAME"
    mkdir -p "$PROG_DIR"

    # ── Extract ALL entry symbols from the C binary ────────────────────────
    C_ENTRIES=$(llvm-objdump -t "$OBJ_PATH" 2>/dev/null \
        | grep " g     F " | awk '{print $NF}' | sort | tr '\n' ' ')
    C_ENTRY_SECTIONS=$(llvm-objdump -t "$OBJ_PATH" 2>/dev/null \
        | grep " g     F " | awk '{print $4, $NF}' | sort -k2 | tr '\n' '; ')
    C_ENTRY_COUNT=$(echo $C_ENTRIES | wc -w)
    echo "[$IDX/$TOTAL] C entries ($C_ENTRY_COUNT): $C_ENTRIES"
    echo "[$IDX/$TOTAL] C sections: $C_ENTRY_SECTIONS"

    PROMPT="You are translating an eBPF program from C to Aya Rust. Follow AGENTS.md exactly.

CRITICAL: Your Rust code MUST include these lint guards right after #![no_main]:
  #![deny(clippy::multiple_unsafe_ops_per_block)]
  #![deny(clippy::undocumented_unsafe_blocks)]
  #![deny(unused_unsafe)]
  #![deny(unused_must_use)]
Each unsafe block must have exactly ONE unsafe op and a // SAFETY: comment above it.

CRITICAL: every BPF helper that returns a Result<T, E> MUST be properly
handled. Empty Err arms are NOT acceptable on failable helpers
(bpf_get_current_comm, bpf_probe_read_*, bpf_get_stackid, etc.). Required
shape:

    let v = match bpf_X(...) {
        Ok(c) => c,
        Err(_) => return Ok(0),   // early-exit drops the event on helper failure
    };
    // ... use v ...

Or use \`?\`-propagation if your function returns Result. Do NOT write
\`Err(_) => {}\` and let the surrounding code emit a partial-init record
into a map / ringbuf — the empty Err arm silently masks helper failures.

This early-return DOES NOT affect equivalence under our framework: the
default symbex constrains every helper to succeed
(helper_fail_mode = off), so the Err arm is dead code in the
equivalence check on both the C and Rust sides. The helper-success path
is what's compared, and that path is identical regardless of whether you
use \`Err(_) => return ...\` or \`Err(_) => {}\`. The early-return is
strictly safer and policy-compliant.

CRITICAL: when zero-initializing a stack struct or a HashMap/ringbuf
reservation larger than ~256 bytes, do NOT use \`__builtin_memset\`,
\`core::ptr::write_bytes\`, or struct assignment from a zero literal
(\`*p = MyStruct::default()\`). The BPF backend cannot inline memset for
buffers above its per-target store budget and falls back to a libcall
that BPF programs cannot resolve, producing a compile error
(\"A call to built-in function 'memset' is not supported\"). Use a manual
byte loop with \`volatile\` writes — the volatile defeats LLVM's
loop-idiom recognition that would otherwise re-lower the loop into the
broken memset path. Required shape (factored into a \`#[inline(always)]\`
or \`__noinline\` helper, or unrolled inline):

    let base = struct_ptr as *mut u64;
    let mut i: usize = 0;
    while i < (size_of::<MyStruct>() / 8) {
        // SAFETY: writing zero to qword i within bounds of the struct
        unsafe { core::ptr::write_volatile(base.add(i), 0u64) };
        i += 1;
    }

This pattern produces the same observable state as a working memset and
DOES NOT affect equivalence (the symbex sees the same per-byte zero
stores). It is purely a workaround for the BPF backend's inline-store
budget.

## Program
- C source: $C_DIR/$C_SOURCE
- C binary: $OBJ_PATH
- Maps: $MAPS

## REQUIRED entry points (--all-entries)
The C binary contains $C_ENTRY_COUNT entry symbols. Your Rust translation MUST include ALL of them:
  $C_ENTRIES
Section mapping from C binary:
  $C_ENTRY_SECTIONS
After compilation, verify ALL $C_ENTRY_COUNT symbols appear in the Rust .o by running:
  llvm-objdump -t \$PROG_DIR/\${PROG_NAME}.o | grep ' g     F '
If any entry is missing, fix the Rust source before proceeding to equivalence checks.

## Output directory
Save all artifacts to: $PROG_DIR/
- Save your final Rust source as: $PROG_DIR/${PROG_NAME}.rs
- Save the compiled Rust .o as: $PROG_DIR/${PROG_NAME}.o
- Save a result.txt with one of:
    'EQUIVALENT'                                                    — ALL entry points verified equivalent
    'PARTIALLY_VERIFIED: verified=<list> unverified=<list>'         — some verified, rest timed out or errored (NOT for mismatches)
    'FAILED: <reason>'                                              — compile failed, no entry points verified, or any mismatch

## Structured logging
After each compile attempt, append a line to $PROG_DIR/attempts.log:
  COMPILE <attempt_num> <success|fail> <one-line error summary if fail>
After each kernel verify attempt, append a line to $PROG_DIR/attempts.log:
  KERNEL_VERIFY <attempt_num> <pass|fail> <one-line summary>
After each safety check, append a line to $PROG_DIR/attempts.log:
  SAFETY_CHECK <attempt_num> <pass|fail> <one-line summary>
After each equivalence check, append a line to $PROG_DIR/attempts.log:
  EQUIV <attempt_num> <equivalent|mismatch> <entry_name>
This is MANDATORY — do not skip logging.

## Steps
1. Read the C source file
2. Translate to Aya Rust (write to aya-ebpf-agent/src/main.rs)
3. Compile: cd aya-ebpf-agent && RUSTFLAGS=\"-C debuginfo=2 -C link-arg=--btf -C target-cpu=v3\" cargo +nightly build --target=bpfel-unknown-none-atomic.json -Zbuild-std=core --release -Zjson-target-spec
4. If compile fails, fix and retry (up to 20 attempts). Log each attempt.
5. Copy compiled .o from aya-ebpf-agent/target/bpfel-unknown-none-atomic/release/aya-ebpf-translated to \$PROG_DIR/\${PROG_NAME}.o
5b. Verify ALL required entries exist in the Rust .o:
   llvm-objdump -t \$PROG_DIR/\${PROG_NAME}.o | grep ' g     F '
   Every one of these must appear: $C_ENTRIES
   If any are missing, fix the Rust source (add the missing function), recompile, and re-check.
6. Run kernel verifier: sudo env PATH=\"\$PATH\" python3 verify_ebpf_kernel.py $PROG_DIR/${PROG_NAME}.o --verbose
   If it rejects, fix the Rust, recompile, re-verify (shares the 20-attempt budget). Log each attempt.
7. Run safety check: python3 safety_check.py aya-ebpf-agent/src/main.rs
   IMPORTANT: This translator uses the strengthened safety policy (safety_policy.py, the 11-rule strict policy promoted to default on 2026-04-30).
   It flags 'match unsafe { helper(...) } { _ => {} }' as a Result-discard violation,
   in addition to all checks from the standard policy.
   To clear it, branch explicitly on Ok/Err — e.g.,
       match unsafe { bpf_probe_read_kernel_str_bytes(...) } {
           Ok(_) => {},
           Err(_) => {},
       };
   If it fails, read the suggested safe-helper replacement, fix the Rust, recompile, re-copy the .o, and re-run kernel verify. Log each safety check.
8. Run equivalence check for EVERY entry symbol listed above:
   python3 verify_mixed_entries.py $OBJ_PATH \$PROG_DIR/\${PROG_NAME}.o <entry> <entry> $MAPS
   Run this once per entry: $C_ENTRIES
   IMPORTANT: Do NOT wrap this in a timeout command. Let it run as long as it needs.
   You MUST check ALL $C_ENTRY_COUNT entries — do not skip any. Log each check.
9. If not equivalent, read the counter-example, fix the Rust, recompile, re-copy the .o, re-verify kernel, re-run the safety check, and re-check (up to 10 attempts)
10. Write result.txt:
   - 'EQUIVALENT' if ALL entry points verified equivalent
   - 'PARTIALLY_VERIFIED: verified=<e1,e2> unverified=<e3>' if some passed and some timed out or errored
     (do NOT use PARTIALLY_VERIFIED for mismatches — a mismatch means the translation is wrong, use FAILED)
   - 'FAILED: <reason>' if compile failed, no entry points verified, or any entry has a mismatch
11. Copy final Rust source to $PROG_DIR/${PROG_NAME}.rs

Do NOT modify any files outside of aya-ebpf-agent/src/main.rs and $PROG_DIR/.
Do NOT skip steps. Iterate until verified or exhausted."

    # Run the selected agent CLI.  Output files use generic agent_* names;
    # codex emits JSONL events, claude/gemini emit a single JSON object.
    START_TIME=$(date +%s)
    case "$AGENT" in
        claude)
            if claude --model "$MODEL" --print --dangerously-skip-permissions --output-format json \
                -p "$PROMPT" > "$PROG_DIR/agent_output.json" 2>"$PROG_DIR/agent_stderr.txt"; then
                AGENT_EXIT=0
            else
                AGENT_EXIT=$?
            fi
            ;;
        codex)
            if codex exec --dangerously-bypass-approvals-and-sandbox --json \
                -o "$PROG_DIR/agent_last_message.txt" \
                "$PROMPT" > "$PROG_DIR/agent_output.jsonl" 2>"$PROG_DIR/agent_stderr.txt"; then
                AGENT_EXIT=0
            else
                AGENT_EXIT=$?
            fi
            ;;
        gemini)
            if gemini --model "$MODEL" --prompt "$PROMPT" --yolo --output-format json \
                > "$PROG_DIR/agent_output.json" 2>"$PROG_DIR/agent_stderr.txt"; then
                AGENT_EXIT=0
            else
                AGENT_EXIT=$?
            fi
            ;;
    esac
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))

    # Agent-aware metadata extraction.  Always write metadata.json with a
    # common base shape (agent, exit code, wall time) plus agent-specific
    # token / event counters when available.
    python3 -u - "$AGENT" "$C_SOURCE" "${DATASET_PREFIX%__}" "$MAPS" "$AGENT_EXIT" "$ELAPSED" "$MODEL" "$PROG_DIR" <<'PYEOF_META'
import json, os, sys

agent, c_src, dataset, maps, exit_code, elapsed, model, prog_dir = sys.argv[1:9]
exit_code = int(exit_code); elapsed = int(elapsed)
meta = {
    'program': c_src, 'dataset': dataset, 'maps': maps,
    'agent': agent, 'model': model,
    'agent_exit_code': exit_code, 'wall_time_s': elapsed,
}

if agent in ('claude', 'gemini'):
    out_path = os.path.join(prog_dir, 'agent_output.json')
    try:
        data = json.load(open(out_path))
        meta.update({
            'duration_ms':     data.get('duration_ms', 0),
            'duration_api_ms': data.get('duration_api_ms', 0),
            'num_turns':       data.get('num_turns', 0),
            'total_cost_usd':  data.get('total_cost_usd', 0),
            'stop_reason':     data.get('stop_reason', ''),
            'session_id':      data.get('session_id', ''),
            'is_error':        data.get('is_error', False),
            'usage':           data.get('usage', {}),
            'model_usage':     data.get('modelUsage', {}),
        })
        with open(os.path.join(prog_dir, 'agent_log.txt'), 'w') as f:
            f.write(data.get('result', '') or '')
    except Exception as e:
        meta['error'] = f'json_parse_failed: {e}'
        try: os.system(f'cp {out_path} {prog_dir}/agent_log.txt 2>/dev/null')
        except Exception: pass

elif agent == 'codex':
    out_path = os.path.join(prog_dir, 'agent_output.jsonl')
    events = []
    try:
        for line in open(out_path):
            line = line.strip()
            if not line: continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError: pass
    except FileNotFoundError:
        pass
    in_tok = out_tok = 0
    types = {}
    for e in events:
        usage = e.get('usage') or {}
        in_tok  += usage.get('input_tokens', 0)  or usage.get('prompt_tokens', 0)     or 0
        out_tok += usage.get('output_tokens', 0) or usage.get('completion_tokens', 0) or 0
        t = e.get('type', 'unknown'); types[t] = types.get(t, 0) + 1
    sid = next((e['session_id'] for e in events if e.get('session_id')), '')
    mdl = next((e['model']      for e in events if e.get('model')),      '')
    log_lines = []
    for e in events:
        if e.get('type') == 'message' and e.get('content'):
            c = e['content']
            if isinstance(c, str): log_lines.append(c)
            elif isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and part.get('text'): log_lines.append(part['text'])
                    elif isinstance(part, str): log_lines.append(part)
    with open(os.path.join(prog_dir, 'agent_log.txt'), 'w') as f:
        f.write('\n'.join(log_lines))
    meta.update({
        'session_id': sid, 'model': mdl or model,
        'total_input_tokens': in_tok, 'total_output_tokens': out_tok,
        'total_events': len(events), 'event_types': types,
    })

with open(os.path.join(prog_dir, 'metadata.json'), 'w') as f:
    json.dump(meta, f, indent=2)
PYEOF_META

    # Backstop safety policy check — should be redundant if the in-loop safety step ran
    RS_FILE="$PROG_DIR/${PROG_NAME}.rs"
    if [ -f "$RS_FILE" ] && [ -f "$PROG_DIR/result.txt" ]; then
        RESULT_LINE=$(head -1 "$PROG_DIR/result.txt" 2>/dev/null || echo "")
        if [[ "$RESULT_LINE" == EQUIVALENT* ]] || [[ "$RESULT_LINE" == PARTIALLY_VERIFIED* ]] || [[ "$RESULT_LINE" == COMPILED* ]]; then
            if ! python3 safety_check.py "$RS_FILE" 2>&1 | tee -a "$PROG_DIR/safety_check.log"; then
                echo "FAILED: safety policy violation (banned pattern in source)" > "$PROG_DIR/result.txt"
                echo "[$IDX/$TOTAL] $PROG_NAME — DOWNGRADED to FAILED by safety_check.py"
            fi
        fi
    fi

    # Check result
    if [ -f "$PROG_DIR/result.txt" ] && grep -qE "^EQUIVALENT" "$PROG_DIR/result.txt"; then
        mv "$PROG_DIR" "$VERIFIED_DIR/$PROG_NAME"
        echo "[$IDX/$TOTAL] $PROG_NAME — EQUIVALENT (${ELAPSED}s)"
        OK=$((OK + 1))
    elif [ -f "$PROG_DIR/result.txt" ] && grep -qE "^PARTIALLY_VERIFIED" "$PROG_DIR/result.txt"; then
        mv "$PROG_DIR" "$PARTIALLY_VERIFIED_DIR/$PROG_NAME"
        REASON=$(cat "$PARTIALLY_VERIFIED_DIR/$PROG_NAME/result.txt")
        echo "[$IDX/$TOTAL] $PROG_NAME — PARTIALLY_VERIFIED: $REASON (${ELAPSED}s)"
        PARTIAL=$((PARTIAL + 1))
    else
        mv "$PROG_DIR" "$FAILED_DIR/$PROG_NAME"
        REASON=$(cat "$FAILED_DIR/$PROG_NAME/result.txt" 2>/dev/null || echo "unknown")
        echo "[$IDX/$TOTAL] $PROG_NAME — FAILED: $REASON (${ELAPSED}s)"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "======================================================================="
echo "COMPLETE: OK=$OK  Partial=$PARTIAL  Failed=$FAIL  Skipped=$SKIP"
echo "Results in: $RESULT_DIR"
echo "======================================================================="
