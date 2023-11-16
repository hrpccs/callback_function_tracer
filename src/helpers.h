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
int resolve_full_path(std::string& file, std::string& result);
unsigned int get_file_inode(const char* path);