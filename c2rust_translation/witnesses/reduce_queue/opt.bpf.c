// Optimized program: same per-RX-queue packet counter, but the queue id is
// narrowed to 16 bits and the hash-map key type is u16 (half the key storage).
//
// This is only sound when the RX queue index never exceeds 65535 — which is
// exactly what the witness states as an assumption, and what the
// map_correspondence (optimized_key = truncate(k, 16)) encodes.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u64);
} queue_packets SEC(".maps");

SEC("xdp")
int count_by_queue(struct xdp_md *ctx)
{
	__u16 queue_id = (__u16)ctx->rx_queue_index;

	__u64 *cnt = bpf_map_lookup_elem(&queue_packets, &queue_id);
	if (cnt) {
		*cnt += 1;
	} else {
		__u64 init = 1;
		bpf_map_update_elem(&queue_packets, &queue_id, &init, BPF_ANY);
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
