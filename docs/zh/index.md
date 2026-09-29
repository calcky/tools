# Linux tools

Linux 调试、监控与测试工具集，各工具独立运行。

## 选择工具

| 工具 | 用途 |
| --- | --- |
| [irqtop / irqstat](irqtop/README.md) | 查看中断速率、CPU 分布和 softnet |
| [netping](netping/README.md) | 测量 ICMP、UDP、TCP 延迟，探测 MTU/MSS |
| [flowgen](flowgen/README.md) | 多会话负载测试，分析 RTT 和 HTML 时序报告 |
| [cttop](cttop/README.md) | conntrack 实时监控、聚合下钻和离线分析 |
| [netlens](netlens/README.md) | 分层查看网口、socket、qdisc、路由及网络栈状态 |
| [bpftrace](bpftrace/README.md) | 内核动态跟踪，提供三架构静态程序 |
| [nettrace](nettrace/README.md) | 跟踪内核 skb 路径，定位丢包与处理延迟 |
| [netcap](netcap/README.md) | 在指定内核函数处抓取 skb 报文，支持 pcap 输出 |

从[安装与使用](getting-started.md)开始。

## 下载

| 工具 | 静态程序 |
| --- | --- |
| irqtop / irqstat | [irqtop-release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| netping | [netping-release](https://github.com/calcky/tools/releases/tag/netping-release) |
| flowgen | [flowgen-release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| cttop | [cttop-release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| netlens | [netlens-release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| bpftrace | [bpftrace-release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| nettrace | [nettrace-release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| netcap | [netcap-release](https://github.com/calcky/tools/releases/tag/netcap-release) |

## 其他脚本

- `irq-affinity.sh`：设置 IRQ 亲和性及 RPS，会修改系统配置。
