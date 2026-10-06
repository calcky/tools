# Linux tools

**中文** | [English](README.en.md)

Linux 调试、监控与测试工具集，各工具独立运行。

## 工具

| 工具 | 用途 | 安装来源 |
| --- | --- | --- |
| [bpfmap](bpfmap/README.md) | 只读查看 BPF map 元数据、BTF 键值预览与周期差值 | [Release](https://github.com/calcky/tools/releases/tag/bpfmap-release) |
| [bpftop](bpftop/README.md) | 实时查看 eBPF 程序运行时间、事件速率和 CPU 估计值 | [Release](https://github.com/calcky/tools/releases/tag/bpftop-release) |
| [bpftrace](bpftrace/README.md) | Linux 内核动态跟踪的三架构静态程序 | [Release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| [cachetop](cachetop/README.md) | 用硬件 PMU 查看 LLC 读未命中、MPKI、IPC 与线程落核 | [Release](https://github.com/calcky/tools/releases/tag/cachetop-release) |
| [cttop](cttop/README.md) | conntrack 实时监控、聚合下钻和离线分析 | [Release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| [droptop](droptop/README.md) | 按内核 skb 丢包原因、网卡与位置聚合速率，并查看热点调用栈 | [Release](https://github.com/calcky/tools/releases/tag/droptop-release) |
| [fdtop](fdtop/README.md) | eBPF 进程/FD I/O 监控，默认轻量计数，按需分析耗时，支持文件、网络、管道、设备与 POSIX MQ | [Release](https://github.com/calcky/tools/releases/tag/fdtop-release) |
| [flowgen](flowgen/README.md) | 多会话 TCP/UDP 负载测试，RTT 统计与离线 HTML 报告 | [Release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| [gomemtop](gomemtop/README.md) | 从 Go pprof 服务采样，实时分析堆占用与增长调用栈 | [Release](https://github.com/calcky/tools/releases/tag/gomemtop-release) |
| [irqtop / irqstat](irqtop/README.md) | 查看硬中断、软中断和 softnet；支持实时窗口与文本输出 | [Release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| [napitop](napitop/README.md) | 查看 NAPI poll 工作量、budget 压力、耗时与 CPU 热点 | [Release](https://github.com/calcky/tools/releases/tag/napitop-release) |
| [netcap](netcap/README.md) | 在指定内核函数处抓取 skb 报文，支持 pcap 输出 | [Release](https://github.com/calcky/tools/releases/tag/netcap-release) |
| [netlens](netlens/README.md) | 分层查看网口、socket、qdisc、路由及网络栈计数 | [Release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| [netping](netping/README.md) | ICMP、UDP、TCP 延迟与丢失检测，MTU/MSS 探测 | [Release](https://github.com/calcky/tools/releases/tag/netping-release) |
| [nettrace](nettrace/README.md) | 内核 skb 路径跟踪、丢包诊断与处理延迟分析 | [Release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| [skbtop](skbtop/README.md) | 按接口与有向接口对查看 IPv4/IPv6 INPUT、OUTPUT、路由/NAT 与桥转发的 skb 栈处理、出口排队和总时延 | 尚未发布预编译程序 |
| [systop](systop/README.md) | eBPF 实时统计系统调用、进程与线程调用速率 | [Release](https://github.com/calcky/tools/releases/tag/systop-release) |
| [xpcap](xpcap/README.md) | 同时抓取 AF_XDP 与常规网口流量，支持 XDP 阶段和 PCAPNG | [Release](https://github.com/calcky/tools/releases/tag/xpcap-release) |
| [xsktop](xsktop/README.md) | 实时查看 AF_XDP socket 的队列流量、错误和进程归属 | [Release](https://github.com/calcky/tools/releases/tag/xsktop-release) |

另有 `irq-affinity.sh` 脚本，用于修改 IRQ/RPS 配置。

## 文档

[使用概览](docs/zh/index.md) · [快速开始](docs/zh/getting-started.md)

文档站默认中文，顶部可切换英文。各工具的完整手册见上表。

## 安装

从 [GitHub Releases](https://github.com/calcky/tools/releases) 选择工具和架构：
`linux-x86_64`、`linux-arm64` 或 `linux-arm`（netlens 为 `linux-armv7`）。

以 x86_64 的 netping 为例：

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netping-release/netping-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
netping -h
```

确保 `$HOME/.local/bin` 已加入 `PATH`。Release 附件是静态 Linux 程序，无需 Rust 运行环境。

也可以从源码安装单个工具（需要 Rust 和 C 编译工具链）：

```sh
git clone https://github.com/calcky/tools.git
cd tools
make netping
make install-netping PREFIX="$HOME/.local"
```
