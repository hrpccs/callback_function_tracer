// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "helpers.h"
#include "time.h"
#include "uprobe.h"
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
        case IBV_POST_SEND:
            printf("attach ibv_post_send %s file_offset %d\n",
                   info.path.c_str(),
                   file_offset);
            skel->links.uprobe_ibv_post_send =
                    bpf_program__attach_uprobe(skel->progs.uprobe_ibv_post_send,
                                               false,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            skel->links.uretprobe_ibv_post_send =
                    bpf_program__attach_uprobe(skel->progs.uretprobe_ibv_post_send,
                                               true,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            break;
        case IBV_POST_RECV:
            printf("attach ibv_post_recv %s file_offset %d\n",
                   info.path.c_str(),
                   file_offset);
            skel->links.uprobe_ibv_post_recv =
                    bpf_program__attach_uprobe(skel->progs.uprobe_ibv_post_recv,
                                               false,
                                               -1,
                                               info.path.c_str(),
                                               file_offset);
            skel->links.uretprobe_ibv_post_recv =
                    bpf_program__attach_uprobe(skel->progs.uretprobe_ibv_post_recv,
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

int attach_init_uprobe_libibverbs(struct uprobe_bpf* skel){
   std::string lib_path = "libibverbs.so.1";
   std::string lib_path_full;
   unsigned int inode = 0;
   unsigned int offset = 0;
    if (resolve_full_path(lib_path, lib_path_full)) {
         printf("resolve full path failed\n");
         return -1;
    }
    inode = get_file_inode(lib_path_full.c_str()); 
    printf("lib_path_full: %s inode: %d\n", lib_path_full.c_str(),inode);
    char function_name[] = "ibv_create_qp";

    // nm -D <full path> | grep <func name>
    // nm -D /usr/lib64/libibverbs.so.1 | grep ibv_create_qp
    // 0000000000017cb0 T ibv_create_qp@@IBVERBS_1.1
    // 0000000000010ec0 T ibv_create_qp@IBVERBS_1.0
    
    // char cmd[PATH_MAX];
    // sprintf(cmd, "nm -D %s | grep %s", lib_path_full.c_str(), function_name);
    std::string cmd = "nm -D " + lib_path_full + " | grep " + function_name;

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        printf("popen failed\n");
        return -1;
    }

    char buf[PATH_MAX];
    // get multiple lines
    while (fgets(buf, PATH_MAX, fp)) {
        // add additional string validation
        printf("buf: %s", buf);
        char* p = strchr(buf, ' ');
        if (!p) {
            printf("strchr failed\n");
            return -1;
        }
        *p = '\0';
        offset = strtoul(buf, NULL, 16);
        printf("offset: 0x%x\n", offset);
        attach_info_t key = make_attach_info(inode, offset);
        if(attach_info_set.find(key) != attach_info_set.end()){
            continue;
        }
        skel->links.uprobe_ibv_create_qp = bpf_program__attach_uprobe(
                skel->progs.uprobe_ibv_create_qp,
                false,
                -1,
                lib_path_full.c_str(),
                offset);
        skel->links.uretprobe_ibv_create_qp = bpf_program__attach_uprobe(
                skel->progs.uretprobe_ibv_create_qp,
                true,
                -1,
                lib_path_full.c_str(),
                offset);
    }
    return 0;
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

    attach_init_uprobe_libibverbs(skel);
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