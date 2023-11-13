// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include "uprobe.h"
#include "header.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct { // TODO: use ringbuffer
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 12);
	__uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} callback_events SEC(".maps");

struct pid_tgid_key {
	u64 pid_tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 12);
	__type(key, struct pid_tgid_key);
	__type(value, struct test_struct*);
} param_map SEC(".maps");

enum callback_stats {
	CALLBACK_RECORDED,
	CALLBACK_ATTACHED,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 12);
	__type(key, void*);
	__type(value, enum callback_stats);
} callback_func_record SEC(".maps");

SEC("uprobe/libtest.so:create_test_struct") // TODO: Add filter
int BPF_KPROBE(uprobe_create_test_struct,struct test_struct *t)
{
	struct pid_tgid_key key = {};
	key.pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&param_map, &key, &t, BPF_ANY);	
	return 0;
}

SEC("uretprobe/libtest.so:create_test_struct")
int BPF_KRETPROBE(uretprobe_create_test_struct)
{
	struct pid_tgid_key key = {};
	key.pid_tgid = bpf_get_current_pid_tgid();
	struct test_struct **tt = bpf_map_lookup_elem(&param_map, &key);
	if(!tt){
		return 0;
	}
	struct test_struct* t = *tt;
	struct callback_event event = {};
	u64 send,recv;
	bpf_probe_read(&send,sizeof(send),&t->send);
	bpf_probe_read(&recv,sizeof(recv),&t->recv);
	event.pid_tgid = bpf_get_current_pid_tgid();
	event.callback_vaddr = send;
	event.type = SEND;
	bpf_perf_event_output(ctx, &callback_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	event.callback_vaddr = recv;
	event.type = RECV;
	bpf_perf_event_output(ctx, &callback_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;

	__sync_and_fetch
}

SEC("uprobe")
int BPF_KPROBE(uprobe_send,int a)
{
    bpf_printk("uprobe_send %d\n",a);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_send)
{
	bpf_printk("uretprobe_send\n");
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_recv,int a)
{
	bpf_printk("uprobe_recv %d\n",a);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_recv)
{
	bpf_printk("uretprobe_recv\n");
	return 0;
}

