#pragma once
#include <string>

struct vma_info {
    std::string path;
    unsigned long long start;
    unsigned long long end;
    unsigned int inode;
    unsigned int offset;
};

int find_vma(struct vma_info* vma, int pid, unsigned long long vaddr);