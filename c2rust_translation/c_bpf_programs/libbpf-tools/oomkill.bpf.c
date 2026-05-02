// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Krisztian Fekete
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

#define MAX_EVENT_SIZE		10240
#define RINGBUF_SIZE		(1024 * 256)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_EVENT_SIZE);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

static __always_inline void *reserve_buf(__u64 size)
{
	static const int zero = 0;

	if (bpf_core_type_exists(struct bpf_ringbuf))
		return bpf_ringbuf_reserve(&events, size, 0);

	return bpf_map_lookup_elem(&heap, &zero);
}

static __always_inline long submit_buf(void *ctx, void *buf, __u64 size)
{
	if (bpf_core_type_exists(struct bpf_ringbuf)) {
		bpf_ringbuf_submit(buf, 0);
		return 0;
	}

	return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, size);
}

struct data_t {
	__u32 fpid;
	__u32 tpid;
	__u64 pages;
	char fcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
};


SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct data_t *data;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return 0;

	data->fpid = bpf_get_current_pid_tgid() >> 32;
	data->tpid = BPF_CORE_READ(oc, chosen, tgid);
	data->pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm));
	bpf_probe_read_kernel(&data->tcomm, sizeof(data->tcomm), BPF_CORE_READ(oc, chosen, comm));
	submit_buf(ctx, data, sizeof(*data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";