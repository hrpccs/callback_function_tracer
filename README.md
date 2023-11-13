# Dependencies: libbpf with CO-RE 

To use BTF and CO-RE, `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y` need to be enabled. If you don't want to rebuild the kernel, the following distos have enabled those options by default:

- Ubuntu 20.10+
- Fedora 31+
- RHEL 8.2+
- Debian 11+

And to build bpf applications, the following development tools should also be installed:

```
# Ubuntu
sudo apt-get install -y cmake make clang llvm libelf-dev linux-tools-$(uname -r)

# RHEL
sudo yum install -y cmake make clang llvm elfutils-libelf-devel bpftool

# WSL2 
# bpftool which shall be compiled and installed from kernel souce code provided by Microsoft
# source code
https://github.com/microsoft/WSL2-Linux-Kernel 
# can reffer to link below for instruction
https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f
```

# Build and Run

build sample first 
```bash
cd sample
./compile_and_install.sh
./main
```

then build and run tracer

```bash
mkdir build 
cd build 
cmake ..
make -j4
sudo mount -t debugfs none /sys/kernel/debug 
sudo ./src/rdma_tracer
sudo cat /sys/kernel/debug/tracing/trace_pipe
```