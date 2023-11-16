// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "uprobe.h"
#include "header.h"
#include <infiniband/verbs.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef unsigned long long u64;
typedef unsigned int u32;

struct { // TODO: use ringbuffer
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 12);
	__uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} callback_events SEC(".maps");
//nm -D /usr/lib64/libibverbs.so.1 | grep ibv_create_qp
//0000000000017cb0 T ibv_create_qp@@IBVERBS_1.1
//0000000000010ec0 T ibv_create_qp@IBVERBS_1.0


// under v5.2 linux kernel, 4096 insts, can't find vma at all
// after v5.2, 1000,000 insts, can iterate vma linklist to find vma, can still fail
// after v5.17, can use bpf_find_vma, definitely can find vma
// if we can find vma in uprobe program, we can just get vma info in userspace by parsing /proc/<pid>/maps
// but some times, program with <pid> exit before we parse it
// so we need to setup a dummy long-live rdma program to activate tracing at the beginning of the system
SEC("uprobe")
int BPF_KPROBE(uprobe_ibv_create_qp,struct ibv_pd* pd,struct ibv_qp_init_attr* qp_init_attr){
	bpf_printk("ibv_create_qp -- enter -- pd addr 0x%llx\n",(u64)pd);
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

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ibv_create_qp,struct ibv_qp* qp){
	bpf_printk("ibv_create_qp -- exit -- qp addr 0x%llx\n",(u64)qp);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ibv_post_send,struct ibv_qp *qp, struct ibv_send_wr *wr,
				struct ibv_send_wr **bad_wr){
	bpf_printk("ibv_post_send -- enter -- qp 0x%llx -- wr 0x%llx -- bad_wr 0x%llx\n",(u64)qp,(u64)wr,(u64)bad_wr);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ibv_post_send,int ret){
	bpf_printk("ibv_post_send -- exit -- ret %d\n",ret);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ibv_post_recv,struct ibv_qp *qp, struct ibv_recv_wr *wr,
				struct ibv_recv_wr **bad_wr){
	bpf_printk("ibv_post_recv -- enter -- qp 0x%llx -- wr 0x%llx -- bad_wr 0x%llx\n",(u64)qp,(u64)wr,(u64)bad_wr);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ibv_post_recv,int ret){
	bpf_printk("ibv_post_recv -- exit -- ret %d\n",ret);
	return 0;
}



