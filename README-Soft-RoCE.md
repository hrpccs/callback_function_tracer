# Soft-RoCE 的配置
参考 https://zhuanlan.zhihu.com/p/361740115
```bash
cat /boot/config-$(uname -r) | grep RXE # 查看是否支持软件 RDMA
sudo modprobe rdma_rxe # 加载软件 RDMA 模块
sudo yum install perftest libibverbs-utils 
```

```bash 

[root]# rxe_cfg start
  Name  Link  Driver      Speed  NMTU  IPv4_addr    RDEV  RMTU
  eth0  yes   virtio_net         1450  172.16.2.75

[root]# ibv_devices
    device                 node GUID
    ------              ----------------
[root]# ibv_devices
    device                 node GUID
    ------              ----------------
[root]# rxe_cfg add eth0
[root]# ibv_devices
    device                 node GUID
    ------              ----------------
    rxe0                f8163efffe1d794b

[root]# ib_send_bw -d rxe0 -n 5 -s 1000000

[root]# ib_send_bw -d rxe0 -n 5 -s 1000000 172.16.2.75
```