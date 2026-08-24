// SPDX-License-Identifier: GPL-2.0
// Standalone version of hercules XDP redirect program.
// Independent of packet.h and hercules.h — SCION structs inlined.
// Uses standard kernel types from vmlinux.h (struct iphdr, struct udphdr, struct ethhdr).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_NUM_SOCKETS 256

#define SCION_ENDHOST_PORT 30041
#define SCION_HEADER_LINELEN 4
#define SCION_HEADER_HBH 200
#define SCION_HEADER_E2E 201

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

// SCION common header (packed, from packet.h)
struct scionhdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned int version: 4;
	unsigned int qos: 8;
	unsigned int flow_id: 20;
#else
	unsigned int flow_id: 20;
	unsigned int qos: 8;
	unsigned int version: 4;
#endif
	__u8 next_header;
	__u8 header_len;
	__u16 payload_len;
	__u8 path_type;
	unsigned int dst_type: 2;
	unsigned int src_type: 2;
	unsigned int dst_len: 2;
	unsigned int src_len: 2;
	__u16 reserved;
} __attribute__((packed));

// SCION IPv4 address header (packed, from packet.h)
struct scionaddrhdr_ipv4 {
	__u64 dst_ia;
	__u64 src_ia;
	__u32 dst_ip;
	__u32 src_ip;
} __attribute__((packed));

// Connection information (from hercules.h)
struct hercules_app_addr {
	__u64 ia;
	__u32 ip;
	__u16 port;
};

// ---------- Maps ----------

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, MAX_NUM_SOCKETS);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} num_xsks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct hercules_app_addr));
	__uint(max_entries, 1);
} local_addr SEC(".maps");

// ---------- Globals ----------

static int redirect_count = 0;
static __u32 zero = 0;

// ---------- XDP program ----------

SEC("xdp")
int xdp_prog_redirect_userspace(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 min_len = sizeof(struct ethhdr) +
	                sizeof(struct iphdr) +
	                sizeof(struct udphdr) +
	                sizeof(struct scionhdr) +
	                sizeof(struct scionaddrhdr_ipv4) +
	                sizeof(struct udphdr);
	if (data + min_len > data_end) {
		return XDP_PASS; // too short
	}
	const struct ethhdr *eh = (const struct ethhdr *)data;
	if (eh->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS; // not IP
	}
	const struct iphdr *iph = (const struct iphdr *)(eh + 1);
	if (iph->protocol != IPPROTO_UDP) {
		return XDP_PASS; // not UDP
	}

	// get listening address
	struct hercules_app_addr *addr = bpf_map_lookup_elem(&local_addr, &zero);
	if (addr == NULL) {
		return XDP_PASS; // not listening
	}

	// check if IP address matches
	if (iph->daddr != addr->ip) {
		return XDP_PASS; // not addressed to us (IP address)
	}

	// check if UDP port matches
	const struct udphdr *udph = (const struct udphdr *)(iph + 1);
	if (udph->dest != bpf_htons(SCION_ENDHOST_PORT)) {
		return XDP_PASS; // not addressed to us (UDP port)
	}

	// parse SCION header
	const struct scionhdr *scionh = (const struct scionhdr *)(udph + 1);
	if (scionh->version != 0u) {
		return XDP_PASS; // unsupported SCION version
	}
	if (scionh->dst_type != 0u) {
		return XDP_PASS; // unsupported destination address type
	}
	if (scionh->src_type != 0u) {
		return XDP_PASS; // unsupported source address type
	}
	__u8 next_header = scionh->next_header;
	__u64 next_offset = sizeof(struct ethhdr) +
	                     sizeof(struct iphdr) +
	                     sizeof(struct udphdr) +
	                     scionh->header_len * SCION_HEADER_LINELEN;
	if (next_header == SCION_HEADER_HBH) {
		if (data + next_offset + 2 > data_end) {
			return XDP_PASS;
		}
		next_header = *((__u8 *)data + next_offset);
		next_offset += (*((__u8 *)data + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if (next_header == SCION_HEADER_E2E) {
		if (data + next_offset + 2 > data_end) {
			return XDP_PASS;
		}
		next_header = *((__u8 *)data + next_offset);
		next_offset += (*((__u8 *)data + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if (next_header != IPPROTO_UDP) {
		return XDP_PASS;
	}

	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *)(scionh + 1);
	if (scionaddrh->dst_ia != addr->ia) {
		return XDP_PASS; // not addressed to us (IA)
	}
	if (scionaddrh->dst_ip != addr->ip) {
		return XDP_PASS; // not addressed to us (IP in SCION hdr)
	}

	__u64 offset = next_offset;

	// Finally parse the L4-UDP header
	const struct udphdr *l4udph = (struct udphdr *)(data + offset);
	if ((void *)(l4udph + 1) > data_end) {
		return XDP_PASS; // too short after all
	}
	if (l4udph->dest != addr->port) {
		return XDP_PASS;
	}
	offset += sizeof(struct udphdr);

	// write the payload offset to the first word
	*(__u32 *)data = offset;

	__u32 *_num_xsks = bpf_map_lookup_elem(&num_xsks, &zero);
	if (_num_xsks == NULL) {
		return XDP_PASS;
	}
	__sync_fetch_and_add(&redirect_count, 1);

	return bpf_redirect_map(&xsks_map, (redirect_count) % (*_num_xsks), 0);
}

char _license[] SEC("license") = "GPL";
