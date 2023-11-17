// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "uprobe.h"

// under v5.2 linux kernel, 4096 insts, can't find vma at all
// after v5.2, 1000,000 insts, can iterate vma linklist to find vma, can still fail
// after v5.17, can use bpf_find_vma, definitely can find vma
// if we can find vma in uprobe program, we can just get vma info in userspace by parsing /proc/<pid>/maps
// but some times, program with <pid> exit before we parse it
// so we need to setup a dummy long-live rdma program to activate tracing at the beginning of the system
SEC("uprobe")
int BPF_KPROBE(uprobe_ibv_create_qp,struct ibv_pd* pd,struct ibv_qp_init_attr* qp_init_attr){
	struct ibv_context* context;
	bpf_probe_read(&context,sizeof(struct ibv_context*),&pd->context);
	struct callback_event event = {};
	event.pid_tgid = bpf_get_current_pid_tgid();
	u64 post_send,post_recv;
	bpf_probe_read(&post_send,sizeof(post_send),&context->ops.post_send);
	event.type = IBV_POST_SEND;
	event.callback_vaddr = post_send;
	bpf_perf_event_output(ctx, &callback_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	bpf_probe_read(&post_recv,sizeof(post_recv),&context->ops.post_recv);
	event.type = IBV_POST_RECV;
	event.callback_vaddr = post_recv;
	bpf_perf_event_output(ctx, &callback_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ibv_post_send,struct ibv_qp *qp, struct ibv_send_wr *wr,
				struct ibv_send_wr **bad_wr){
	struct event e = {};
	e.pid_tgid = bpf_get_current_pid_tgid();
	e.timestamp = bpf_ktime_get_ns();
	e.type = IBV_POST_SEND_ENTER;
	bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ibv_post_send,int ret){
	struct event e = {};
	e.pid_tgid = bpf_get_current_pid_tgid();
	e.timestamp = bpf_ktime_get_ns();
	e.type = IBV_POST_SEND_EXIT;
	bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ibv_post_recv,struct ibv_qp *qp, struct ibv_recv_wr *wr,
				struct ibv_recv_wr **bad_wr){
	struct event e = {};
	e.pid_tgid = bpf_get_current_pid_tgid();
	e.timestamp = bpf_ktime_get_ns();
	e.type = IBV_POST_RECV_ENTER;
	bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ibv_post_recv,int ret){
	struct event e = {};
	e.pid_tgid = bpf_get_current_pid_tgid();
	e.timestamp = bpf_ktime_get_ns();
	e.type = IBV_POST_RECV_EXIT;
	bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}



