#include <fstream>
#include <sstream>
#include <string>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <cassert>
#include "helpers.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <libgen.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <libelf.h>
#include <gelf.h>
#include <zlib.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// can be replace by bpf_find_vma after v5.17 linux kernel 
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


// comes from libbpf repo src/libbpf.c
static const char *arch_specific_lib_paths(void)
{
	/*
	 * Based on https://packages.debian.org/sid/libc6.
	 *
	 * Assume that the traced program is built for the same architecture
	 * as libbpf, which should cover the vast majority of cases.
	 */
#if defined(__x86_64__)
	return "/lib/x86_64-linux-gnu";
#elif defined(__i386__)
	return "/lib/i386-linux-gnu";
#elif defined(__s390x__)
	return "/lib/s390x-linux-gnu";
#elif defined(__s390__)
	return "/lib/s390-linux-gnu";
#elif defined(__arm__) && defined(__SOFTFP__)
	return "/lib/arm-linux-gnueabi";
#elif defined(__arm__) && !defined(__SOFTFP__)
	return "/lib/arm-linux-gnueabihf";
#elif defined(__aarch64__)
	return "/lib/aarch64-linux-gnu";
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SZLONG == 64
	return "/lib/mips64el-linux-gnuabi64";
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SZLONG == 32
	return "/lib/mipsel-linux-gnu";
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return "/lib/powerpc64le-linux-gnu";
#elif defined(__sparc__) && defined(__arch64__)
	return "/lib/sparc64-linux-gnu";
#elif defined(__riscv) && __riscv_xlen == 64
	return "/lib/riscv64-linux-gnu";
#else
	return NULL;
#endif
}

/* suffix check */
static inline bool str_has_sfx(const std::string& str, const std::string& sfx)
{
	size_t str_len = str.size();
	size_t sfx_len = sfx.size();

	if (sfx_len > str_len)
		return false;
	return strcmp(str.c_str() + str_len - sfx_len, sfx.c_str()) == 0;
}

/* Get full path to program/shared library. */
int resolve_full_path(std::string& file, std::string& result)
{
	const char *search_paths[3] = {};
	int i, perm;

	if (str_has_sfx(file, ".so") || strstr(file.c_str(), ".so.")) {
		search_paths[0] = getenv("LD_LIBRARY_PATH");
		search_paths[1] = "/usr/lib64:/usr/lib";
		search_paths[2] = arch_specific_lib_paths();
		perm = R_OK;
	} else {
		search_paths[0] = getenv("PATH");
		search_paths[1] = "/usr/bin:/usr/sbin";
		perm = R_OK | X_OK;
	}

	for (i = 0; i < 3; i++) {
		const char *s;

		if (!search_paths[i])
			continue;
		for (s = search_paths[i]; s != NULL; s = strchr(s, ':')) {
			const char *next_path;
			int seg_len;

			if (s[0] == ':')
				s++;
			next_path = strchr(s, ':');
			seg_len = next_path ? next_path - s : strlen(s);
			if (!seg_len)
				continue;
			result = std::string(s, seg_len) + "/" + file;
			/* ensure it has required permissions */
			if (faccessat(AT_FDCWD, result.c_str(), perm, AT_EACCESS) < 0)
				continue;
			return 0;
		}
	}
	return -ENOENT;
}

unsigned int get_file_inode(const char* path){
  struct stat buf;
  if (stat(path, &buf) < 0) {
    return 0;
  }
  return buf.st_ino;
}