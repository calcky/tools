# 网卡、队列与中断

## 从网口下钻

```sh
netlens -i eth0,eth1 interface
netlens qdisc
netlens hardirq
netlens softirq
```

Interface 同时显示流量与配置，选择网口按 Enter 进入该设备的分层详情。
`s/r` 切换排序与方向，也可点击流量表头；配置表不可排序。
`-i` 只筛选网口相关行，softirq 等主机级统计不会因此变成该网口的统计。

## 流量和驱动计数

先看 RX/TX 的带宽与 PPS，再看丢弃、错误，以及驱动提供的分类计数。

| 指标 | 口径 |
| --- | --- |
| PACKETS / TRAFFIC | 网口累计包数 / 字节 |
| PPS / BANDWIDTH | 实际采样间隔中的变化，带宽为 bit/s |
| DROPS / ERRORS | 当前 netdevice 的丢弃 / 错误，不是端到端丢包率 |
| CRC / frame / missed 等 | 驱动和硬件支持的错误分类，不保证可以相加 |
| 驱动私有计数 | 来源原值；名称不足以证明单位或 XDP 动作语义 |

PF 和 VF 都按实际 netdevice 展示，包括 DOWN 的设备。当前命名空间没有 netdevice 的 VF 不会被虚构出来。
软件网口的 RX/TX 不等于物理线上流量；同一业务包可能经过多个虚拟网口。

## 配置怎么看

配置包括链路速度、双工、驱动、MTU、RX/TX 队列与 ring、pause、offload 及 root qdisc。
这些是只读信息，不能仅凭一个配置值判断异常。

- MTU 是链路上的 IP 包大小上限，不等于 TCP MSS。
- RX/TX ring、`tx_queue_len` 与 BQL 属于不同缓冲或限制，不可互换。
- 队列数包含驱动报告的 combined channels；sysfs 回退会保留来源标识。
- `fixed` 表示来源明确不支持配置，不是因为当前值等于最大值。
- GRO/GSO/TSO 会改变不同统计点的包数，详见[数据包路径](packet-path.md)。

缺失配置显示 `n/a`，驱动不支持或权限失败的原因在 Providers 中查看。

## 看 qdisc 排队和丢弃

```sh
netlens qdisc
```

| 指标 | 含义 |
| --- | --- |
| backlog | 当前排队量，不是历史丢弃 |
| drop/s | 队列丢弃速率 |
| requeue/s | 重新入队，不是丢包或 TCP 重传 |
| overlimit | 超出调度限制，不一定发生丢弃 |
| packets / bytes | 该 qdisc 统计点的累计流量 |

根与子 qdisc 分别展示，不能相加。Overview 仅突出有新 drop 或 requeue 的根出口 qdisc。
目前不采集 class/filter/action。TC ingress 与 XDP redirect 不能按普通出口 qdisc 解释。

## 对照硬中断与 softnet

HardIRQ 显示已确认属于网卡的 IRQ，不是全部系统中断。
每行是一个 IRQ 的全 CPU 总计，CPU 列显示当前活跃 CPU；`+N` 仅表示更多 CPU 未放入列中，总计仍包含它们。

| 页面 / 指标 | 反映什么 |
| --- | --- |
| HardIRQ `COUNT` / `intr/s` | 累计中断 / 每秒中断处理次数 |
| SoftIRQ NET_RX / NET_TX | softirq 调用次数，不是包数 |
| softnet processed | 接收处理计数，不是线上 PPS |
| softnet dropped | 接收 backlog 入队丢弃 |
| time squeeze | 接收处理耗尽预算，不是丢包数 |
| flow limit | RPS flow-limit 丢弃，不与总 dropped 再次相加 |

中断合并与 NAPI 批处理让一个中断可以对应多个包，持续轮询也不需要每批都有新 IRQ。
softnet 与 softirq 按 CPU 统计，不能直接归属到一个网口。
XDP_DROP/TX/REDIRECT 可能不进入后续统计点，不能用 IRQ、softnet、网口包数的差值断言丢包。
