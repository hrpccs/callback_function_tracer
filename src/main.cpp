// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "mmap_helper.h"
#include "time.h"
#include "uprobe.h"
#include "uprobe.skel.h"
#include <bpf/libbpf.h>
#include <cstdio>
#include <ctime>
#include <errno.h>
#include <set>
#include <signal.h>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>

typedef unsigned long long attach_info_t;
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
    struct callback_event* event = (struct callback_event*)data;
    unsigned long long vaddr = event->callback_vaddr;
    unsigned int pid = event->pid_tgid >> 32;
    unsigned int tgid = event->pid_tgid & 0xffffffff;
    // find the file offset

    struct vma_info info;
    if (find_vma(&info, pid, vaddr)) {
        printf("find vma failed\n");
        return;
    }

    unsigned int file_offset = vaddr - info.start + info.offset;
    attach_info_t key = (attach_info_t)info.inode << 32 | file_offset;

    if (attach_info_set.find(key) != attach_info_set.end()) {
        return;
    }

    printf("path: %s\n", info.path.c_str());
    printf("inode: %u\n", info.inode);
    printf("offset: %u\n", info.offset);
    printf("file_offset: %u\n", file_offset);

    // attach the uprobe
    struct uprobe_bpf* skel = (struct uprobe_bpf*)ctx;
    switch (event->type) {
        case SEND:
            printf("attach send %s file_offset %d\n",
                   info.path.c_str(),
                   file_offset);
            skel->links.uprobe_send =
                    bpf_program__attach_uprobe(skel->progs.uprobe_send,
                                               false,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            skel->links.uretprobe_send =
                    bpf_program__attach_uprobe(skel->progs.uretprobe_send,
                                               true,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            if (!skel->links.uprobe_send || !skel->links.uretprobe_send)
                printf("attach send failed\n");
            break;
        case RECV:
            printf("attach recv %s file_offset %d\n",
                   info.path.c_str(),
                   file_offset);
            skel->links.uprobe_recv =
                    bpf_program__attach_uprobe(skel->progs.uprobe_recv,
                                               false,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            skel->links.uretprobe_recv =
                    bpf_program__attach_uprobe(skel->progs.uretprobe_recv,
                                               true,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            break;
        default:
            printf("unknown type\n");
            break;
    }
    attach_info_set.insert(key);
}

int main(int argc, char** argv) {
    /* Cleaner handling of Ctrl-C */
    struct uprobe_bpf* skel;
    int err;
    struct perf_buffer* pb = NULL;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
    LIBBPF_OPTS(perf_buffer_opts, pb_opts);

    libbpf_set_print(libbpf_print_fn);

    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = uprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.callback_events),
                          8,
                          handle_static_callback_uprobe_attach,
                          nullptr,
                          skel,
                          &pb_opts);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Failed to open perf buffer\n");
        err = -libbpf_get_error(pb);
        goto cleanup;
    }

    while (1) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    uprobe_bpf__destroy(skel);
    return -err;
}