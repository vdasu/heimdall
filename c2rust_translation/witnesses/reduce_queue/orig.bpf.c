// Original program: count XDP packets per RX queue.
//
// The RX queue index is a 32-bit value and is used directly as the hash-map
// key (key type u32).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} queue_packets SEC(".maps");

SEC("xdp")
int count_by_queue(struct xdp_md *ctx)
{
	__u32 queue_id = ctx->rx_queue_index;

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
