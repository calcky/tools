# Linux tools

**中文** | [English](README.en.md)

Linux 调试、监控与测试工具集，各工具独立运行。

## 工具

| 工具 | 用途 |
| --- | --- |
| [irqtop / irqstat](irqtop/README.md) | 查看硬中断、软中断和 softnet；支持实时窗口与文本输出 |
| [netping](netping/README.md) | ICMP、UDP、TCP 延迟与丢失检测，MTU/MSS 探测 |
| [flowgen](flowgen/README.md) | 多会话 TCP/UDP 负载测试，RTT 统计与离线 HTML 报告 |
| [cttop](cttop/README.md) | conntrack 实时监控、聚合下钻和离线分析 |
| [netlens](netlens/README.md) | 分层查看网口、socket、qdisc、路由及网络栈计数 |
| [bpftrace](bpftrace/README.md) | Linux 内核动态跟踪的三架构静态程序 |
| [nettrace](nettrace/README.md) | 内核 skb 路径跟踪、丢包诊断与处理延迟分析 |
| [netcap](netcap/README.md) | 在指定内核函数处抓取 skb 报文，支持 pcap 输出 |
| [xsktop](xsktop/README.md) | 实时查看 AF_XDP socket 的队列流量、错误和进程归属 |
| [gomemtop](gomemtop/README.md) | 从 Go pprof 服务采样，实时分析堆占用与增长调用栈 |

另有 `irq-affinity.sh` 脚本，用于修改 IRQ/RPS 配置。

## 文档

[使用概览](docs/zh/index.md) · [快速开始](docs/zh/getting-started.md)

文档站默认中文，顶部可切换英文。各工具的完整手册见上表。

## 下载与安装

从 [GitHub Releases](https://github.com/calcky/tools/releases) 选择工具和架构：
`linux-x86_64`、`linux-arm64` 或 `linux-arm`（netlens 为 `linux-armv7`）。

以 x86_64 的 netping 为例：

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netping-release/netping-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
netping -h
```

确保 `$HOME/.local/bin` 已加入 `PATH`。下载的是静态 Linux 程序，无需 Rust 运行环境。

也可以从源码安装单个工具（需要 Rust 和 C 编译工具链）：

```sh
git clone https://github.com/calcky/tools.git
cd tools
make netping
make install-netping PREFIX="$HOME/.local"
```
