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

struct { 
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 12);
	__uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} callback_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 20);
	__uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} trace_events SEC(".maps");