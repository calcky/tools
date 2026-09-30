# nettrace

使用 eBPF 跟踪报文在 Linux 内核中的 skb 路径，定位丢包和协议栈处理延迟。

## 安装

以 x86_64 为例；其他架构见 [nettrace-release](https://github.com/calcky/tools/releases/tag/nettrace-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/nettrace-release/nettrace-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 nettrace-linux-x86_64 "$HOME/.local/bin/nettrace"
```

程序内嵌 BPF 对象，无需在目标机器安装 clang、bpftool 或动态库。
运行仍需要 root 或相应权限、内核 BTF 和 BPF trampoline/fentry/fexit 支持。

## 常用命令

```sh
# 跟踪指定目标的 ICMP，显示设备、CPU、进程等上下文
nettrace -p icmp --daddr 192.0.2.10 --detail

# 诊断指定 TCP 服务，只输出发现的异常
nettrace -p tcp --dport 443 --diag --diag-quiet

# 查看指定目标的 skb 释放/丢弃事件
nettrace --drop --daddr 192.0.2.10

# 显示处理耗时超过 1ms 的 ICMP 路径及各环节延迟
nettrace -p icmp --daddr 192.0.2.10 \
  --min-latency 1000 --latency-show
```

将示例地址替换为实际目标；按 Ctrl+C 停止跟踪。排查容器时可加 `--netns-current` 限定当前网络命名空间。

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-p PROTO` | 按协议过滤，如 `tcp`、`udp`、`icmp` |
| `--saddr` / `--daddr` / `--addr` | 按源、目的或任一地址过滤 |
| `--sport` / `--dport` / `-P PORT` | 按源、目的或任一 TCP/UDP 端口过滤 |
| `--detail` | 显示 CPU、网口、PID/进程名等上下文 |
| `--basic` | 逐事件显示，不组合 skb 生命周期 |
| `--diag` / `--diag-quiet` | 诊断模式 / 只输出异常 |
| `--drop` / `--drop-stack` | 释放/丢弃事件 / 同时显示调用栈 |
| `--min-latency US` / `--latency-show` | 最低处理耗时（微秒） / 显示各环节延迟 |
| `-t LIST` | 选择跟踪函数或分组，多个名称用逗号分隔 |
| `--netns-current` | 仅跟踪当前网络命名空间 |
| `-h` / `-V` | 帮助 / 版本；`-v` 是日志，不是版本 |

## 注意事项

- 当前静态版本来自上游 `btf` 分支；必须存在 `/sys/kernel/btf/vmlinux`，仅有 BTF 还不足以保证可用。
- 如果提示 debugfs 未挂载，需要在主机上挂载到 `/sys/kernel/debug`；容器还可能受到能力或挂载限制。
- **ARMv7 为实验产物**：普通上游 32 位 ARM 内核缺少所需 trampoline 实现；能启动不等于能跟踪报文。ARM64 尚未完成真实内核跟踪验证。
- `--drop` 观察 skb 的释放/丢弃，不应把每个释放事件都解释为网络丢包。
- 进程名是事件发生时的执行上下文，不一定是所属 socket 的应用。
- native XDP 在创建 skb 前处理报文，可能不出现在此工具的路径中；没有事件不等于报文没有经过该逻辑层。
- 先缩小协议、地址或端口范围，再开启详细输出或调用栈，避免大量事件影响被测系统。

[完整说明](https://github.com/calcky/tools/blob/master/nettrace/README.md) · [上游用法](https://github.com/OpenCloudOS/nettrace/blob/d455f001315322db4d606a8bdf8c659ba36b269c/README.md)
