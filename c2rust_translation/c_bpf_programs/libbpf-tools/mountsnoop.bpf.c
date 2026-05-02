/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

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


#define MAX_ENTRIES 10240
#define TASK_COMM_LEN	16
#define FS_NAME_LEN	8
#define DATA_LEN	512
#define PATH_MAX	4096

enum op {
	OP_MIN, /* skip 0 */
	MOUNT,
	UMOUNT,
	FSOPEN,
	FSCONFIG,
	FSMOUNT,
	MOVE_MOUNT,
};

union sys_arg {
	/* op=MOUNT */
	struct {
		__u64 flags;
		const char *src;
		const char *dest;
		const char *fs;
		const char *data;
	} mount;
	/* op=UMOUNT */
	struct {
		__u64 flags;
		const char *dest;
	} umount;
	/* op=FSOPEN */
	struct {
		const char *fs;
		__u32 flags;
	} fsopen;
	/* op=FSCONFIG */
	struct {
		int fd;
		unsigned int cmd;
		const char *key;
		const char *value;
		int aux;
	} fsconfig;
	/* op=FSMOUNT */
	struct {
		int fs_fd;
		__u32 flags;
		__u32 attr_flags;
	} fsmount;
	/* op=MOVE_MOUNT */
	struct {
		int from_dfd;
		const char *from_pathname;
		int to_dfd;
		const char *to_pathname;
		__u32 flags;
	} move_mount;
};

struct arg {
	__u64 ts;
	enum op op;
	union sys_arg sys;
};

struct event {
	__u64 delta;
	__u32 pid;
	__u32 tid;
	unsigned int mnt_ns;
	int ret;
	enum op op;
	char comm[TASK_COMM_LEN];
	union {
		/* op=MOUNT */
		struct {
			__u64 flags;
			char fs[FS_NAME_LEN];
			char src[PATH_MAX];
			char dest[PATH_MAX];
			char data[DATA_LEN];
		} mount;
		/* op=UMOUNT */
		struct {
			__u64 flags;
			char dest[PATH_MAX];
		} umount;
		/* op=FSOPEN */
		struct {
			char fs[FS_NAME_LEN];
			__u32 flags;
		} fsopen;
		/* op=FSCONFIG */
		struct {
			int fd;
			unsigned int cmd;
			char key[DATA_LEN];
			char value[DATA_LEN];
			int aux;
		} fsconfig;
		/* op=FSMOUNT */
		struct {
			int fs_fd;
			__u32 flags;
			__u32 attr_flags;
		} fsmount;
		/* op=MOVE_MOUNT */
		struct {
			int from_dfd;
			char from_pathname[PATH_MAX];
			int to_dfd;
			char to_pathname[PATH_MAX];
			__u32 flags;
		} move_mount;
	};
};

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

static int probe_entry(union sys_arg *sys_arg, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};

	if (target_pid && target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.op = op;

	switch (op) {
	case MOUNT:
	case UMOUNT:
	case FSOPEN:
	case FSCONFIG:
	case FSMOUNT:
	case MOVE_MOUNT:
		__builtin_memcpy(&arg.sys, sys_arg, sizeof(*sys_arg));
		break;
	default:
		goto skip;
	}

	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);
skip:
	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct task_struct *task;
	struct event *eventp;
	struct arg *argp;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	task = (struct task_struct *)bpf_get_current_task();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->op = argp->op;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	eventp->ret = ret;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));

	switch (argp->op) {
	case MOUNT:
		eventp->mount.flags = argp->sys.mount.flags;
		bpf_probe_read_user_str(eventp->mount.src,
					sizeof(eventp->mount.src),
					argp->sys.mount.src);
		bpf_probe_read_user_str(eventp->mount.dest,
					sizeof(eventp->mount.dest),
					argp->sys.mount.dest);
		bpf_probe_read_user_str(eventp->mount.fs,
					sizeof(eventp->mount.fs),
					argp->sys.mount.fs);
		bpf_probe_read_user_str(eventp->mount.data,
					sizeof(eventp->mount.data),
					argp->sys.mount.data);
		break;
	case UMOUNT:
		eventp->umount.flags = argp->sys.umount.flags;
		bpf_probe_read_user_str(eventp->umount.dest,
					sizeof(eventp->umount.dest),
					argp->sys.umount.dest);
		break;
	case FSOPEN:
		eventp->fsopen.flags = argp->sys.fsopen.flags;
		bpf_probe_read_user_str(eventp->fsopen.fs,
					sizeof(eventp->fsopen.fs),
					argp->sys.fsopen.fs);
		break;
	case FSCONFIG:
		eventp->fsconfig.fd = argp->sys.fsconfig.fd;
		eventp->fsconfig.cmd = argp->sys.fsconfig.cmd;
		bpf_probe_read_user_str(eventp->fsconfig.key,
					sizeof(eventp->fsconfig.key),
					argp->sys.fsconfig.key);
		bpf_probe_read_user_str(eventp->fsconfig.value,
					sizeof(eventp->fsconfig.value),
					argp->sys.fsconfig.value);
		eventp->fsconfig.aux = argp->sys.fsconfig.aux;
		break;
	case FSMOUNT:
		eventp->fsmount.fs_fd = argp->sys.fsmount.fs_fd;
		eventp->fsmount.flags = argp->sys.fsmount.flags;
		eventp->fsmount.attr_flags = argp->sys.fsmount.attr_flags;
		break;
	case MOVE_MOUNT:
		eventp->move_mount.from_dfd = argp->sys.move_mount.from_dfd;
		bpf_probe_read_user_str(eventp->move_mount.from_pathname,
					sizeof(eventp->move_mount.from_pathname),
					argp->sys.move_mount.from_pathname);
		eventp->move_mount.to_dfd = argp->sys.move_mount.to_dfd;
		bpf_probe_read_user_str(eventp->move_mount.to_pathname,
					sizeof(eventp->move_mount.to_pathname),
					argp->sys.move_mount.to_pathname);
		break;
	}

	submit_buf(ctx, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_entry(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.mount.src = (const char *)ctx->args[0];
	arg.mount.dest = (const char *)ctx->args[1];
	arg.mount.fs = (const char *)ctx->args[2];
	arg.mount.flags = (__u64)ctx->args[3];
	arg.mount.data = (const char *)ctx->args[4];

	return probe_entry(&arg, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int mount_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_entry(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.umount.dest = (const char *)ctx->args[0];
	arg.umount.flags = (__u64)ctx->args[1];

	return probe_entry(&arg, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int umount_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int fsopen_entry(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.fsopen.fs = (const char *)ctx->args[0];
	arg.fsopen.flags = (__u32)ctx->args[1];

	return probe_entry(&arg, FSOPEN);
}

SEC("tracepoint/syscalls/sys_exit_fsopen")
int fsopen_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int fsconfig_entry(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.fsconfig.fd = (int)ctx->args[0];
	arg.fsconfig.cmd = (int)ctx->args[1];
	arg.fsconfig.key = (const char *)ctx->args[2];
	arg.fsconfig.value = (const char *)ctx->args[3];
	arg.fsconfig.aux = (int)ctx->args[4];

	return probe_entry(&arg, FSCONFIG);
}

SEC("tracepoint/syscalls/sys_exit_fsconfig")
int fsconfig_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int fsmount_entry(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.fsmount.fs_fd = (__u32)ctx->args[0];
	arg.fsmount.flags = (__u32)ctx->args[1];
	arg.fsmount.attr_flags = (__u32)ctx->args[2];

	return probe_entry(&arg, FSMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_fsmount")
int fsmount_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int move_mount_entry(struct syscall_trace_enter *ctx)
{
	union sys_arg arg = {};

	arg.move_mount.from_dfd = (int)ctx->args[0];
	arg.move_mount.from_pathname = (const char *)ctx->args[1];
	arg.move_mount.to_dfd = (int)ctx->args[2];
	arg.move_mount.to_pathname = (const char *)ctx->args[3];

	return probe_entry(&arg, MOVE_MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_move_mount")
int move_mount_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";