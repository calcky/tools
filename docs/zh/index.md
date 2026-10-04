# Linux tools

Linux 调试、监控与测试工具集，各工具独立运行。

## 选择工具

| 工具 | 用途 | 安装来源 |
| --- | --- | --- |
| [bpfmap](bpfmap/README.md) | 只读查看 BPF map 元数据、键值预览和采样差值 | [Release](https://github.com/calcky/tools/releases/tag/bpfmap-release) |
| [bpftop](bpftop/README.md) | 实时查看 eBPF 程序运行时间、事件速率和 CPU 估计值 | [Release](https://github.com/calcky/tools/releases/tag/bpftop-release) |
| [bpftrace](bpftrace/README.md) | 内核动态跟踪，提供三架构静态程序 | [Release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| [cachetop](cachetop/README.md) | 查看 LLC 读未命中、MPKI、IPC 与线程落核 | [Release](https://github.com/calcky/tools/releases/tag/cachetop-release) |
| [cttop](cttop/README.md) | conntrack 实时监控、聚合下钻和离线分析 | [Release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| [droptop](droptop/README.md) | 按丢包原因、网卡与调用位置聚合 skb 丢包，查看样本与内核调用栈 | [Release](https://github.com/calcky/tools/releases/tag/droptop-release) |
| [fdtop](fdtop/README.md) | 按进程与 FD 查看应用 I/O、完整 FD 清单和打开关闭事件 | [Release](https://github.com/calcky/tools/releases/tag/fdtop-release) |
| [flowgen](flowgen/README.md) | 多会话负载测试，分析 RTT 和 HTML 时序报告 | [Release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| [gomemtop](gomemtop/README.md) | 分析 Go pprof 堆增长和本机进程 RSS 来源 | [Release](https://github.com/calcky/tools/releases/tag/gomemtop-release) |
| [irqtop / irqstat](irqtop/README.md) | 查看中断速率、CPU 分布和 softnet | [Release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| [napitop](napitop/README.md) | 查看 NAPI poll 工作量、budget 压力、耗时与 CPU 热点 | [Release](https://github.com/calcky/tools/releases/tag/napitop-release) |
| [netcap](netcap/README.md) | 在指定内核函数处抓取 skb 报文，支持 pcap 输出 | [Release](https://github.com/calcky/tools/releases/tag/netcap-release) |
| [netlens](netlens/README.md) | 分层查看网口、socket、qdisc、路由及网络栈状态 | [Release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| [netping](netping/README.md) | 测量 ICMP、UDP、TCP 延迟，探测 MTU/MSS | [Release](https://github.com/calcky/tools/releases/tag/netping-release) |
| [nettrace](nettrace/README.md) | 跟踪内核 skb 路径，定位丢包与处理延迟 | [Release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| [xpcap](xpcap/README.md) | 同屏抓取 AF_XDP 与常规网口流量，可观察 XDP 阶段 | [Release](https://github.com/calcky/tools/releases/tag/xpcap-release) |
| [xsktop](xsktop/README.md) | 查看 AF_XDP socket 的队列流量、错误和所属进程 | [Release](https://github.com/calcky/tools/releases/tag/xsktop-release) |

从[安装与使用](getting-started.md)开始。

## 其他脚本

- `irq-affinity.sh`：设置 IRQ 亲和性及 RPS，会修改系统配置。
