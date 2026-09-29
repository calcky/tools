# netcap

在指定内核函数或 tracepoint 处捕获 skb 报文，查看协议栈某个位置实际经过的数据包。

## 安装

从[下载页面](https://github.com/calcky/tools/releases/tag/netcap-release)选择 ARMv7、ARM64 或 x86_64 静态程序。以 x86_64 为例：

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netcap-release/netcap-linux-x86_64
chmod +x netcap-linux-x86_64
./netcap-linux-x86_64 version
```

静态程序内含 BCC/LLVM，目标机不必安装 Clang 或动态库；运行时仍会编译 BPF 探针。

## 常用命令

```sh
# 在 ICMP 接收函数处抓取 10 个报文，写入 pcap
sudo ./netcap-linux-x86_64 skb -f icmp_rcv@1 -e 'icmp' -i eth0 -w icmp.pcap -c 10

# 多个内核位置共用一条过滤规则
sudo ./netcap-linux-x86_64 skb -f 'ip_local_deliver@1,icmp_rcv@1' \
  -e 'host 192.0.2.10' -i eth0 -w path.pcap -c 20

# 只查看生成的 BPF C 代码，不加载探针
./netcap-linux-x86_64 skb -f icmp_rcv@1 -e 'icmp' -i eth0 --dry-run
```

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `skb` | 跟踪 Linux skb；另有面向 AF_XDP/DPDK 进程的 `raw`、`mbuf` 模式 |
| `-f FUNCTION@N` | 跟踪函数及 skb 参数序号；多个位置用逗号分隔 |
| `-e EXPR` | tcpdump 风格的报文过滤表达式 |
| `-i IFACE` | 限定网口 |
| `-w FILE` | 写入 pcap 文件 |
| `-c COUNT` | 抓到指定数量后退出 |
| `--dry-run` | 仅显示生成的 BPF C 代码 |

## 注意事项

- `skb` 抓包需要 root 或相应跟踪权限、debugfs，以及与运行内核匹配的已准备头文件。自定义内核可设置 `BCC_KERNEL_SOURCE`。
- 不使用 `-w` 时，文本输出会调用外部 `bash` 和 `tcpdump`；静态链接不包含这两个程序。
- x86_64 已实测回环抓包；ARM64、ARMv7 仅验证了构建与命令启动，尚未在对应硬件上验证抓包。
- `raw` 和 `mbuf` 需要匹配的 AF_XDP/DPDK 目标进程，本次未做运行验证。

[下载静态程序](https://github.com/calcky/tools/releases/tag/netcap-release) · [构建与限制](https://github.com/calcky/tools/blob/master/netcap/README.md) · [上游用法](https://github.com/bytedance/netcap)
