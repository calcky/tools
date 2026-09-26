# Linux tools

面向 Linux 网络调试、监控和测试的小工具集。各工具独立运行，Rust 工具支持静态编译，生成的程序统一放在 `bin/`。

## 选择工具

| 需要查看或测试什么 | 工具 | 主要能力 |
| --- | --- | --- |
| 中断速率、CPU 分布、softnet | [irqtop / irqstat](irqtop/README.md) | 实时窗口与周期文本输出，硬中断、软中断及网卡筛选 |
| 延迟、丢包、MTU、MSS | [netping](netping/README.md) | ICMP、UDP/TCP 回显、TCP 建连、三协议窗口 |
| 多会话发包和连接更替 | [flowgen](flowgen/README.md) | TCP/UDP、会话预热、并发与新建速率、记录及离线分析 |
| conntrack 连接和流量 | [cttop](cttop/README.md) | IP、端口、协议、Mark 聚合，下钻、NAT 和静态文件 |
| 网络栈整体状态 | [netlens](netlens/README.md) | 网口、qdisc、中断、socket、conntrack、路由等分层监控 |

从[安装与构建](getting-started.md)开始，或直接查看[常见任务](tasks.md)。完整选项、交互按键和指标定义在各工具手册中。

## 程序与文档版本

各工具独立发布，使用 `工具名-v版本` 标签。下载见 [GitHub Releases](https://github.com/calcky/tools/releases)。
开发分支文档可能包含尚未发布的改动，使用时应核对程序版本和发布说明。

`cttop` 原名 `ctop`。已有 `ctop-v0.1.0` 发布及其附件仍保留旧名称；当前源码、构建入口和后续发布流程使用 `cttop`。

## 指标与权限

实时采集与离线数据的能力不同。例如 cttop 单份静态快照可以显示已有包数和字节数，但无法计算带宽与新建速率，相关字段显示 `N/A`。部分工具需要目标网络命名空间内的权限，具体要求见工具手册。

仓库还保留 `irq-affinity.sh` 和 UDP 测试脚本；其中 `irq-affinity.sh` 会修改 IRQ/RPS 配置，与只读监控工具的用途不同。
