# irqtop / irqstat

查看 Linux 硬中断、软中断及 softnet 的变化速率和 CPU 分布。irqtop 是实时窗口，irqstat 是周期文本输出。

[![irqtop 的中断与 softnet 窗口](../assets/screenshots/irqtop-window.png)](../assets/screenshots/irqtop-window.png)

`irqtop -a -m 100 -b` 实际窗口：中断总计、每 CPU 速率与 softnet 同屏。

## 安装

以 x86_64 为例；其他架构见 [irqtop-release](https://github.com/calcky/tools/releases/tag/irqtop-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/irqtop-release/irqtop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 irqtop-linux-x86_64 "$HOME/.local/bin/irqtop"
ln -sfn irqtop "$HOME/.local/bin/irqstat"
```

## 常用命令

```sh
# 全部硬中断和软中断
irqtop

# 网络中断，附加 softnet
irqtop -n -b

# 指定网口，支持多个网口
irqtop -i eth0,eth1

# 指定 VF 标签
irqtop -i xnic0/vf1

# 每个 CPU 的速率超过 500/s 才显示
irqtop -n -m 500

# 每秒输出一次，共五次；默认仅硬中断
irqstat -n 1 5

# 加上网络软中断，或记录未过滤的输出
irqstat -i eth0 -s 1 5
irqstat -m 0 1 60 > irq.log
```

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-a` | 全部硬中断；启用软中断时包含全部 softirq |
| `-n` | 网络硬中断；启用软中断时包含 NET_RX/NET_TX |
| `-i NIC[,NIC]` | 指定网口或 `PF/vfN` 标签，隐含 `-n` |
| `-s` | irqstat 加上软中断；irqtop 默认已启用 |
| `-b` | 加上 softnet 的处理、丢弃、预算耗尽等计数 |
| `-m RATE` | 只显示速率严格大于阈值的 CPU，默认 200/s；`0` 不过滤 |
| `-z` | 显示所有非零中断源 |
| `-d` | 显示采样间隔内的计数，而非每秒速率 |
| `interval [count]` | 采样间隔（秒）及输出次数 |
| `-h` / `-v` | 帮助 / 版本 |

## 读取结果

- `CPU=all` 表示该中断的总计，包含被阈值隐藏的 CPU。
- 若所有 CPU 的速率都不超过阈值，即使总计较大，也隐藏该中断。
- 窗口中的最高 CPU 值加粗高亮；`rate/s` 为采样期间的平均速率。
- softnet 的 `dropped/s` 是接收 backlog 丢弃；`squeeze/s` 是处理预算耗尽，不是丢包数。

## 窗口按键

| 按键 | 操作 |
| --- | --- |
| `a` / `n` | 全部 / 网络中断 |
| `z` | 切换默认阈值与非零显示 |
| `b` / `Tab` | 显示 softnet / 切换滚动区域 |
| `s` | 切换排序 |
| 方向键、`j/k` | 移动；PgUp/PgDn 翻页 |
| `q` / Ctrl+C | 退出 |

## 注意事项

IRQ/s 不是 PPS，也不是 CPU 占用率。NET_RX/NET_TX 和 softnet 均为本机统计，不能用 `-i` 归属到某个网口。
VF 标签显示主机可见的中断，不代表虚拟机内的中断或 CPU 分布；选择 PF 不会自动选中其 VF。
工具只读，不修改 IRQ 亲和性或系统配置。

[完整手册](https://github.com/calcky/tools/blob/master/irqtop/README.md)
