# droptop

持续聚合 Linux 内核 `skb:kfree_skb` 丢包事件，按原因、网卡或调用位置查看速率；选中热点后，可查看近期 skb 样本和内核调用栈。

## 安装

以 x86_64 为例，从 [droptop-release](https://github.com/calcky/tools/releases/tag/droptop-release) 安装。该 Release 也提供 ARMv7 和 ARM64 程序。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/droptop-release/droptop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 droptop-linux-x86_64 "$HOME/.local/bin/droptop"
```

运行时需要 root 或等效的 BPF、tracing 权限；命令示例假设权限已具备。

## 常用命令

```sh
droptop                 # 按丢包原因和网卡聚合，打开实时窗口
droptop -i eth0         # 只看丢包点关联 eth0 的事件
droptop -g reason       # 跨网卡按原因聚合
droptop -g site -c 5   # 按调用位置输出 5 次纯文本采样
droptop -d 0.5 -c 10   # 每 0.5 秒采样，可重定向输出
```

| 选项 | 作用 |
| --- | --- |
| `-i IFACE` | 按丢包点的 `skb->dev` 限定当前网络命名空间内的网卡；不等同于原始入接口，未关联网卡的事件会被排除。 |
| `-d SEC` | 采样间隔，0.1-60 秒，默认 1 秒。 |
| `-c N` | 输出 N 次文本采样，不打开终端窗口。 |
| `-g pair\|reason\|device\|site` | 初始聚合维度；默认 `pair`（原因 + 网卡）。 |
| `-h` / `-V` | 帮助 / 版本。 |

## 窗口与指标

顶部表格按 `drop/s` 排列聚合组；中部时间线显示选中组近期的 skb 样本；底部显示选中样本的报文信息和该**组**的热点调用栈。调用栈不是对单个样本的归因。终端宽度至少 105 列时，底部两块并排，否则上下排列。

`j/k` 或方向键选择聚合组，`[` / `]` 浏览样本，左右键切换热点调用路径，PageUp/PageDown 滚动栈帧，`g` 切换聚合方式，`q` 退出。切换组后，需要等待该组出现新的丢包才能填充样本和调用栈。`-c` 文本模式仅输出每次采样的前 30 个组，不采集样本与调用栈。

- `drop/s`：两次采样间计数增量除以实际间隔；`TOTAL`：探针挂载以来的累计事件数。
- 样本时间线：观察时间、协议、长度、五元组；宽终端还显示丢包原因与调用位置。
- 样本详情：`skb_iif` 是接收 ifindex，`skb->dev` 是丢包点关联的设备。两者都不能保证指出原始物理入接口；地址和端口也可能已经过 NAT。
- `map`、`stack`：聚合 map 写入失败、栈采集或聚合失败。样本头部的 `limit`、`ring`、`user` 表示样本损失，不影响独立的全量丢包计数；`limit` 和 `ring` 是区间增量，`user` 是启动以来累计。

## 适用范围

只计数到达 `skb:kfree_skb` 的事件，不覆盖网卡硬件丢包、早期 XDP DROP、AF_XDP ring 失败或应用层丢失；不要将它与其他层的丢包计数直接相加。`NOT_SPECIFIED` 等原因单独出现时，也不能据此判定网络故障。

原因名称从运行内核的 BTF `skb_drop_reason` 枚举读取。无法读取的报文头、非首片 IPv4 分片和 IPv6 扩展头会明确标为不完整；不猜测端口。调用位置是内核代码位置，不代表责任进程；`/proc/kallsyms` 不公开符号时会显示十六进制地址。

需要 Linux 6.6+、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_EVENTS`、`CONFIG_DEBUG_INFO_BTF`、`/sys/kernel/btf/vmlinux` 和 `skb:kfree_skb` tracepoint。更完整的语义见[项目手册](https://github.com/calcky/tools/blob/master/droptop/README.md)。
