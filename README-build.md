# 编译环境要求

gcc>=7 
clang,llvm >= 10
cmake >= 3.0

建议编译环境的内核版本高一点，比如 5.15 ，方便利用 eBPF 的特性，如果后续要引入 kprobe，也方便开发。

```
# Ubuntu 建议 20.10+
sudo apt-get install -y git cmake make clang llvm libelf-dev 

# openEuler 建议 22.03+
sudo yum install -y git cmake make clang llvm elfutils-libelf-devel libstdc++-static
```

# Build and Run
```bash
mkdir build 
cd build 
cmake ..
make -j4
sudo mount -t debugfs none /sys/kernel/debug 
sudo ./src/rdma_tracer
```