// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "uprobe.h"
#include "vmlinux.h"

struct request_structure_content{
	u64 request_ptr;
	u64 content[32];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 12);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct request_structure_content));
} tid_request_map SEC(".maps");


SEC("uprobe")
int BPF_KPROBE(upstream_index_search_enter,u64 request_ptr){
	bpf_printk("upstream_index_search_enter : \trequest_ptr %lx",request_ptr);
	struct request_structure_content request_content = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	request_content.request_ptr = request_ptr;
	bpf_probe_read(&request_content.content, sizeof(request_content.content), (void*)request_ptr);
	int ret = bpf_map_update_elem(&tid_request_map, &pid_tgid, &request_content, BPF_ANY);
	if(ret){
		bpf_printk("uprobe map update failed");
	}
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(upstream_index_search_exit){
	bpf_printk("upstream_index_search_exit");
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct request_structure_content *content_ptr = bpf_map_lookup_elem(&tid_request_map, &pid_tgid);
	if(!content_ptr){
		return 0;
	}

	u64 request_ptr = content_ptr->request_ptr;
	u64 content[32]={0};
	bpf_probe_read(&content, sizeof(content), (void*)request_ptr);

	// compare the content 
	int index=0;
	while(index < 32){
		if(content[index] != content_ptr->content[index]){
			bpf_printk("content[%d] : %lx",index,content[index]);
			break;
		}
		index++;
	}

	bpf_map_delete_elem(&tid_request_map, &pid_tgid);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(ngx_output_chain_uprobe,u64 output_ctx_ptr){
	bpf_printk("ngx_output_chain_uprobe : \toutput_ctx_ptr %lx",output_ctx_ptr);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(create_request_http_uretprobe,u64 request_ptr){
	bpf_printk("create_request_http_uprobe exit: \trequest_ptr %lu",request_ptr);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(ngx_http_free_request_uprobe,u64 r){
	bpf_printk("ngx_http_free_request : \tr %lx",r);
	return 0;
}

// // int BPF_PROG(tcp_sendmsg_enter, struct sock *sk, struct msghdr *msg, size_t size){
// SEC("fentry/tcp_sendmsg")
// int BPF_PROG(tcp_sendmsg_enter, struct sock *sk){
// 	if(!sk) return 0;
// 	bpf_printk("<tcp sendmsg> enter : \tsock addr %lu",sk);
//     return 0;
// }


// // int BPF_PROG(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size){
// SEC("fexit/tcp_sendmsg")
// int BPF_PROG(tcp_sendmsg_exit){
//     int ret = (int)ctx[3];
//     if(ret <= 0){
//         return 0;
//     }
//     struct sock* sk = (struct sock*)ctx[0];
//     if(!sk) return 0;
//     bpf_printk("<tcp sendmsg> exit  : \tsock addr %lu",sk);
//     return 0;
// }

// SEC("fentry/tcp_recvmsg")
// int BPF_PROG(tcp_recvmsg_enter){
//     struct sock* sk = (struct sock*)ctx[0];
//     if(!sk) return 0;
// 	bpf_printk("<tcp recvmsg> enter : \tsock addr %lu",sk);
//     return 0;
// }


// SEC("fexit/tcp_recvmsg") 
// int BPF_PROG(tcp_recvmsg_exit){
//     struct sock* sk = (struct sock*)ctx[0];
//     if(!sk) return 0;
// 	bpf_printk("<tcp recvmsg> exit  : \tsock addr %lu",sk);
//     return 0;
// }
