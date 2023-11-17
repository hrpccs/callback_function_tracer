# 前置要求
已经在高版本内核的机器上完成本工具的编译，得到了静态链接可执行文件。编译方法参见[README-build.md](README-build.md)。
# 测试环境
OS: centos 7.6 linux kernel 3.10.0-957.12.2.el7.x86_64
# 声明
本工具目前只利用了 ebpf + uprobe 的功能，所以不依赖内核数据结构，因此不需要增加对不同内核版本的兼容性。
如果后续增加了 kprobe 功能，在把工具分发到不同内核版本的机器上时，需要额外携带 BTF 文件。[BTFGen: 让 eBPF 程序可移植发布更近一步](https://www.cnblogs.com/davad/p/16120225.html)
# 测试过程
把编译好的可执行文件通过 scp 等方式拷贝到测试机器上，然后执行。
```bash
sudo ./rdma_tracer
```
观察输出，如果看到如下信息，说明运行正常，并且找到了当前系统中的 libibverbs.so.1 库，且挂载了相关的 uprobe：
```bash
# sudo ./rdma_tracer
libbpf: loading object 'uprobe_bpf' from buffer
libbpf: elf: section(3) uprobe, size 672, link 0, flags 6, type=1
 ......
lib_path_full: /usr/lib64/libibverbs.so.1 inode: 346
trace event poller started
buf: 000000000000cf70 T ibv_create_qp
offset: 0xcf70
buf: 0000000000012b00 T ibv_create_qp
offset: 0x12b00
```
此时，我在该机器上部署了 Soft-RoCE，见[README-Soft-RoCE]，然后运行了 ib_send_bw 测试工具，观察输出：
```bash
ib_send_bw -d rxe0 -n 5 -s 1000000
ib_send_bw -d rxe0 -n 5 -s 1000000 172.16.2.75
```
此时 rdma_tracer 输出日志，可以看到捕捉到了 ibv_post_send 和 ibv_post_recv 的调用各 5 次，和 ib_send_bw 中设置的 -n 5 参数一致：
```bash
path: /usr/lib64/libibverbs/librxe-rdmav22.so
inode: 4408626
offset: 0
file_offset: 9200
attach ibv_post_send /usr/lib64/libibverbs/librxe-rdmav22.so file_offset 9200
path: /usr/lib64/libibverbs/librxe-rdmav22.so
inode: 4408626
offset: 0
file_offset: 10912
attach ibv_post_recv /usr/lib64/libibverbs/librxe-rdmav22.so file_offset 10912
ibv_post_recv -- enter -- pid 4894 tgid 4894 ts 4342233538943
ibv_post_recv -- exit -- pid 4894 tgid 4894 ts 4342233572690
ibv_post_recv -- enter -- pid 4894 tgid 4894 ts 4342233579699
ibv_post_recv -- exit -- pid 4894 tgid 4894 ts 4342233590459
ibv_post_recv -- enter -- pid 4894 tgid 4894 ts 4342233595674
ibv_post_recv -- exit -- pid 4894 tgid 4894 ts 4342233606078
ibv_post_recv -- enter -- pid 4894 tgid 4894 ts 4342233611101
ibv_post_recv -- exit -- pid 4894 tgid 4894 ts 4342233621351
ibv_post_recv -- enter -- pid 4894 tgid 4894 ts 4342233626340
ibv_post_recv -- exit -- pid 4894 tgid 4894 ts 4342233636774
ibv_post_recv -- enter -- pid 4894 tgid 4894 ts 4342233641822
ibv_post_recv -- exit -- pid 4894 tgid 4894 ts 4342233663415
ibv_post_send -- enter -- pid 4898 tgid 4898 ts 4342248048352
ibv_post_send -- exit -- pid 4898 tgid 4898 ts 4342253123381
ibv_post_send -- enter -- pid 4898 tgid 4898 ts 4342253134321
ibv_post_send -- exit -- pid 4898 tgid 4898 ts 4342257935213
ibv_post_send -- enter -- pid 4898 tgid 4898 ts 4342257946351
ibv_post_send -- exit -- pid 4898 tgid 4898 ts 4342281747456
ibv_post_send -- enter -- pid 4898 tgid 4898 ts 4342281766444
ibv_post_send -- exit -- pid 4898 tgid 4898 ts 4342286816464
ibv_post_send -- enter -- pid 4898 tgid 4898 ts 4342286829391
ibv_post_send -- exit -- pid 4898 tgid 4898 ts 4342290593991
```