#include <fstream>
#include <sstream>
#include <string>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <cassert>
#include "mmap_helper.h"

int find_vma(struct vma_info* vma,int pid, unsigned long long vaddr) {
    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    std::string line;

    while (std::getline(maps_file, line)) {
        std::istringstream iss(line);
        std::string range;
        iss >> range;

        size_t dash = range.find('-');
        unsigned long start = std::stoul(range.substr(0, dash), nullptr, 16);
        unsigned long end = std::stoul(range.substr(dash + 1), nullptr, 16);

        if (start <= vaddr && vaddr < end) {
            line = line.substr(line.find_first_of(' ') + 6);
            unsigned int offset = std::stoul(line, nullptr, 16);
            line = line.substr(16);
            unsigned int inode = std::stoul(line, nullptr, 16);
            std::string path = line.substr(line.find_last_of(' ') + 1);
            if (path.find("libtest.so") == std::string::npos) {
                assert(false);
            }
            vma->start = start;
            vma->end = end;
            vma->offset = offset;
            vma->inode = inode;
            vma->path = path;
            return 0;
        }
    }
    return -1;
}

