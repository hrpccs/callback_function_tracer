// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "header.h"
#include "helpers.h"
#include "time.h"
#include "uprobe.skel.h"
#include <bpf/libbpf.h>
#include <cstdio>
#include <ctime>
#include <errno.h>
#include <set>
#include <signal.h>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>

#define PATH_MAX 512

typedef unsigned long long attach_info_t;
attach_info_t make_attach_info(unsigned int inode, unsigned int offset) {
    return (attach_info_t)inode << 32 | offset;
}

std::set<attach_info_t> attach_info_set;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

void handle_static_callback_uprobe_attach(void* ctx,
                                          int cpu,
                                          void* data,
                                          __u32 data_sz) {
}

int attach_init_uprobe(struct uprobe_bpf* skel) {
    //pgrep -f "nginx: worker"
    std::string cmd = "pgrep -fax \"nginx: worker process\"";

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        printf("popen failed\n");
        return -1;
    }

    char buf[PATH_MAX];
    // get multiple lines
    bool attach_uretprobe = false;
    // while (fgets(buf, PATH_MAX, fp)) {
        fgets(buf, PATH_MAX, fp);
        // add additional string validation
        printf("buf: %s", buf);
        // int pid = atoi(buf);
        int pid = 799921;
        printf("pid: %d\n", pid);
        std::string path = "/proc/" + std::to_string(pid) + "/root" + "/usr/sbin/nginx";
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
        uprobe_opts.retprobe = false;
        uprobe_opts.func_name = "ngx_http_upstream_create";
        skel->links.upstream_index_search_enter =
                bpf_program__attach_uprobe_opts(skel->progs.upstream_index_search_enter,
                                            //pid,
                                           -1,
                                           path.c_str(),
                                        // NULL,
                                           0,
                                           &uprobe_opts);
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts1);
            uprobe_opts1.retprobe = true;
            uprobe_opts1.func_name = "ngx_http_upstream_create";
            skel->links.upstream_index_search_exit =
                    bpf_program__attach_uprobe_opts(skel->progs.upstream_index_search_exit,
                                            //pid,
                                            -1,
                                            path.c_str(),
                                            // NULL,
                                            0,
                                            &uprobe_opts1);
            attach_uretprobe = true;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts2);
        uprobe_opts2.retprobe = false;
        uprobe_opts2.func_name = "ngx_output_chain";
        skel->links.ngx_output_chain_uprobe =
                bpf_program__attach_uprobe_opts(skel->progs.ngx_output_chain_uprobe,
                                   //pid,
                                            -1,
                                            path.c_str(),
                                            // NULL,
                                           0,
                                           &uprobe_opts2);
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts3);
        uprobe_opts3.retprobe = false;
        uprobe_opts3.func_name = "ngx_http_free_request";
        skel->links.ngx_http_free_request_uprobe =
                bpf_program__attach_uprobe_opts(skel->progs.ngx_http_free_request_uprobe,
                                    //pid,
                                            -1,
                                            path.c_str(),
                                            // NULL,
                                           0,
                                           &uprobe_opts3);
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts4);
        uprobe_opts4.retprobe = true;
        uprobe_opts4.func_name = "ngx_http_create_request";
        skel->links.create_request_http_uretprobe =
                bpf_program__attach_uprobe_opts(skel->progs.create_request_http_uretprobe,
                                    //pid,
                                            -1,
                                            path.c_str(),
                                            // NULL,
                                           0,
                                           &uprobe_opts4);
        if(libbpf_get_error(skel->links.upstream_index_search_enter) ||
           libbpf_get_error(skel->links.upstream_index_search_exit) ||
           libbpf_get_error(skel->links.ngx_output_chain_uprobe)) {
            printf("err %ld\n", libbpf_get_error(skel->links.upstream_index_search_enter));
            printf("err %ld\n", libbpf_get_error(skel->links.upstream_index_search_exit));
            printf("err %ld\n", libbpf_get_error(skel->links.ngx_output_chain_uprobe));
            fprintf(stderr, "Failed to attach uprobe\n");
            return -1;
        }
    // }
    return 0;
}

void handle_trace_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    struct event* event = (struct event*)data;
    unsigned int pid = event->pid_tgid >> 32;
    unsigned int tgid = event->pid_tgid & 0xffffffff;
    switch (event->type) {
        case IBV_POST_SEND_ENTER:
            printf("ibv_post_send -- enter -- pid %u tgid %u ts %llu\n",pid,tgid,event->timestamp);
            break;
        case IBV_POST_SEND_EXIT:
            printf("ibv_post_send -- exit -- pid %u tgid %u ts %llu\n",pid,tgid,event->timestamp);
            break;
        case IBV_POST_RECV_ENTER:
            printf("ibv_post_recv -- enter -- pid %u tgid %u ts %llu\n",pid,tgid,event->timestamp);
            break;
        case IBV_POST_RECV_EXIT:
            printf("ibv_post_recv -- exit -- pid %u tgid %u ts %llu\n",pid,tgid,event->timestamp);
            break;
        default:
            printf("unknown type\n");
            break;
    }
}

void trace_event_poller(struct uprobe_bpf* skel) {
    printf("trace event poller started\n");
    struct perf_buffer* trace_pb = NULL;
    int err;
    LIBBPF_OPTS(perf_buffer_opts, pb_opts);
    trace_pb = perf_buffer__new(bpf_map__fd(skel->maps.trace_events),
                                8,
                                handle_trace_event,
                                nullptr,
                                skel,
                                &pb_opts);
    if(libbpf_get_error(trace_pb)) {
        fprintf(stderr, "Failed to open perf buffer\n");
        err = -libbpf_get_error(trace_pb);
        return;
    }
    while (1) {
        int err = perf_buffer__poll(trace_pb, 100);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            return;
        }
    }
}

int main(int argc, char** argv) {
    /* Cleaner handling of Ctrl-C */
    struct uprobe_bpf* skel;
    int err;
    struct perf_buffer* cb_pb = NULL;
    LIBBPF_OPTS(perf_buffer_opts, pb_opts);

    libbpf_set_print(libbpf_print_fn);

    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    std::thread trace_event_poller_thread(trace_event_poller, skel);
    trace_event_poller_thread.detach();
    attach_init_uprobe(skel);
    err = uprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    cb_pb = perf_buffer__new(bpf_map__fd(skel->maps.callback_events),
                             8,
                             handle_static_callback_uprobe_attach,
                             nullptr,
                             skel,
                             &pb_opts);
    if (libbpf_get_error(cb_pb)) {
        fprintf(stderr, "Failed to open perf buffer\n");
        err = -libbpf_get_error(cb_pb);
        goto cleanup;
    }


    while (1) {
        err = perf_buffer__poll(cb_pb, 100);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    uprobe_bpf__destroy(skel);
    return -err;
}