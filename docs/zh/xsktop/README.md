# xsktop

实时查看当前网络命名空间中的 AF_XDP socket，按网口和队列显示 RX/TX 速率、错误和所属进程。

## 安装

以 x86_64 为例；其他架构见 [xsktop-release](https://github.com/calcky/tools/releases/tag/xsktop-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/xsktop-release/xsktop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 xsktop-linux-x86_64 "$HOME/.local/bin/xsktop"
```

## 常用命令

```sh
xsktop                   # 实时窗口
xsktop -i eth0           # 仅看指定网口
xsktop -d 0.5            # 每 0.5 秒刷新
xsktop -c 5 -d 1 > log   # 采样 5 次，输出纯文本
```

窗口中用方向键或 `j/k` 选择 socket；点击 Q、速率或错误率表头排序，再点一次反转；`s` 切换排序列，`q` 退出。指标排序先按网口汇总速率排，再排网口内的队列。

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-i IFACE` | 限定网口 |
| `-d SEC` | 采样间隔，最小 0.1 秒 |
| `-c N` | 输出 N 次文本采样，不需要终端 |

## 错误与事件

详情区的计数来自内核 AF_XDP socket 诊断接口，不是网卡硬件错误：

| 指标 | 含义 |
| --- | --- |
| `RX dropped` | 其他原因导致报文未进入 XSK，例如无可用 UMEM 帧、报文超过配置的帧大小；RX ring 满单独统计。 |
| `RX invalid` | 内核报告的无效 RX ring 描述符；不等于无效 fill ring 条目数。 |
| `RX ring full` | XSK RX ring 没有空位，报文无法入队；可检查应用是否及时消费。 |
| `TX invalid` | 无效 TX 描述符，例如 UMEM 地址或长度不合法。 |
| `UMEM fill empty` | 内核获取 RX 缓冲区时找不到可用 fill ring 条目；是检查事件，不能将每次增加都当作一个丢包。共享 UMEM 的 socket 共用该计数。 |
| `TX empty` | 内核检查 TX ring 时没有可用描述符；不是发送错误或丢包数。 |

`rate/s` 是上次采样以来的增量除以实际间隔，`total` 是该 socket（或共享 UMEM 池）的内核累计值；`rate/s` 为 `-` 表示还没有可用的前次采样，不是 0。主表 `RX err/s` 是前三项 RX 错误之和，`TX err/s` 仅计 `TX invalid`；两个 empty 事件不计入错误率。这些数值反映 XSK 侧情况，不能直接当作网卡错误或链路丢包。

## 注意事项

- 需要 Linux 6.6+、`CONFIG_XDP_SOCKETS_DIAG`、内核 BTF 和 fentry/fexit BPF 支持；通常需要 root 或相应能力。
- RX 表示进入 XSK，TX 表示内核取走描述符，不等于应用已消费或报文已上网线。ring 显示的是容量，不是实时占用。
- `UMEM fill empty`、`TX empty` 是事件，不计入 RX/TX 错误。共用 UMEM 的 socket 可能共享 fill-ring 事件。同一网口/队列有多个 XSK 时，速率显示为 `-`；其中一个关闭后的首个采样区间仍可能包含其流量。
- 已验证 veth 上的 generic/copy 与 native/copy；真实网卡 zero-copy 和多缓冲报文尚未验证。

[完整手册](https://github.com/calcky/tools/blob/master/xsktop/README.md)
