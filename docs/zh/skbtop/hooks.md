# 观测钩子

本页说明 `skbtop` 实际挂载的 eBPF 观测点。`fentry/函数` 在函数入口观察，`fexit/函数` 在返回时取得结果，`tp_btf/事件` 使用内核 BTF 类型监听 tracepoint；它们不是配置在网卡上的 XDP/TC 程序，也不是一组 netfilter 规则。指标含义与操作见[使用说明](README.md)。

## INPUT：接口到本机

```text
tp_btf/netif_receive_skb                    t0：保存起点时间和 skb->len
  位于 __netif_receive_skb_core 内
        |
        | IP 接收、路由到本机
        v
IPv4: fentry/ip_protocol_deliver_rcu        t1：本机协议分发入口
IPv6: fentry/ip6_protocol_deliver_rcu

Stack = Total = t1 - t0；没有 Queue
```

终点位于 TCP/UDP/ICMP 等后续协议处理、socket 和应用之前；IPv6 还可能在扩展头处理之前。NIC 接收、NAPI/GRO 以及发生在 RX core 入口之前的 RPS 工作不包含在内。这里不统计非 IP 的本机交付时延。

## OUTPUT：本机到接口

```text
IPv4: fentry/__ip_local_out                 t0：本机 IP 输出起点
IPv6: fentry/__ip6_local_out
        |
        | IP 输出、netfilter、邻居及出口处理
        v
tp_btf/net_dev_queue                       tq：出口队列观察点
        |
        | 出口调度、qdisc、可能的驱动 BUSY 重试
        v
tp_btf/net_dev_start_xmit                  tx：驱动发送尝试入口
        |
tp_btf/net_dev_xmit                        结果：NETDEV_TX_OK 才确认完成

Stack = tq - t0；Queue = tx - tq；Total = tx - t0
```

`__ip_local_out` / `__ip6_local_out` 是实际探针名，包含开头的双下划线。应用的 write/send、TCP 等传输层在这个起点之前的工作不计入时延。

## FORWARD：入接口到出接口

```text
tp_btf/netif_receive_skb                    t0：入接口 RX core
        |
        +-- IP 路由 / NAT -- ip_forward / ip6_forward
        |
        +-- Linux bridge -- br_* 分类及分支观察
        |
        v
tp_btf/net_dev_queue                       tq：实际出接口已确定
        |
tp_btf/net_dev_start_xmit                  tx：驱动发送尝试入口
        |
tp_btf/net_dev_xmit                        结果：NETDEV_TX_OK 才确认完成

Stack = tq - t0；Queue = tx - tq；Total = tx - t0
```

转发按实际入、出接口形成有向路径；桥接泛洪的各出口分支独立统计，同接口 hairpin 也保留。NAT 不额外挂载一个计时钩子，不提供独立的 NAT 耗时。

| 分类 | 实际函数入口探针 | 用途 |
| --- | --- | --- |
| 路由 | `fentry/ip_forward`、`fentry/ip6_forward` | 标记 IPv4/IPv6 路由转发。 |
| 桥接接收与分支 | `fentry/br_handle_frame_finish`、`fentry/br_forward`、`fentry/br_flood` | 标记桥接、单播分支和泛洪路径。 |
| 桥接出口 | `fentry/br_forward_finish`、`fentry/br_dev_queue_push_xmit`、`fentry/br_dev_xmit` | 保留出口或本机经桥发出的桥接分类。 |

这些分类探针不各自生成时延分段。队列观察还会验证 skb 控制缓冲区中的桥设备身份，补充被内联等优化影响的分类。路径统计中的 `route` / `bridge` / `combo` 分别表示仅路由、仅桥接和两种标记都出现的成功完成次数；最后一种常见于桥接与 IP 路径组合。

## IN / OUT 的入账时机

| 路径 | IN 计数 | OUT 计数 |
| --- | --- | --- |
| INPUT | 在协议分发入口入账，使用 RX core 起点保存的长度。 | 在同一入口入账，使用此时的 skb 长度。 |
| OUTPUT | 首次进入已识别出口的 `net_dev_queue` 时入账，使用本机 IP 输出起点保存的长度。 | `net_dev_xmit` 确认成功时入账，使用该次 `net_dev_start_xmit` 保存的长度。 |
| FORWARD | 首次进入已识别出口的 `net_dev_queue` 时，按出口分支入账，使用接收起点保存的长度。 | 与 OUTPUT 相同，按实际成功的发送分支入账。 |

IN 是已识别路径的起点观察，并非接口全部收包。尚未交付或进入出口队列的 skb 可能只有全局起点计数，没有路径行。OUT 计数与时延样本计入完成区间，入口排队可能在更早的区间；Total 仍使用原始起点时间。区间按统计入账时的单调时钟划分，时延仍按钩子入口时间计算；恰好跨越刷新边界的样本可能计入下一区间。

RX core 通常不含以太网头，驱动发送通常已包含以太网头，INPUT 分发入口可能已移除 IP 头。克隆、泛洪、GSO 分段也可能改变完成次数或长度，尤其是排队后分段的一个入口对应多个完成样本。因此 IN/OUT 字节数或 PPS 不等，不等于丢包。

BUSY 尝试不计为 OUT，不生成成功时延样本；等待后续成功尝试，Queue/Total 包含期间的等待，终点仍取成功尝试的入口时间。`net_dev_xmit` 的返回时间只用于确认和入账，不加入已测时延。成功表示驱动接受，不表示 NIC 已完成发送或对端已收到。

## 关联与生命周期钩子

| 作用 | 实际探针 |
| --- | --- |
| 克隆、复制与身份继承 | `fexit/skb_clone`、`fexit/skb_copy`、`fexit/skb_copy_expand`、`fexit/__pskb_copy_fclone`、`fexit/skb_morph` |
| 软件分段的子 skb 继承 | `fexit/skb_segment`、`fexit/skb_segment_list` |
| 释放和清理关联 | `fentry/skb_release_head_state`、`tp_btf/consume_skb`、`tp_btf/kfree_skb` |
| 设备注销 | `fentry/unregister_netdevice_queue` |
| 分片与重组覆盖诊断 | `fentry/ip_do_fragment`、`fentry/ip6_fragment`、`fentry/ip_defrag`、`fentry/ipv6_frag_rcv` |

`__kfree_skb` 会经过 `skb_release_head_state`，因此不再单独挂载探针。
Consume/drop tracepoint 仍覆盖无状态消费等其他释放路径；头部状态释放也负责在
`skb_morph` 前清理旧身份。GSO 使用最多 128 段的有界回调复用父关联，
每个子 skb 仍有独立身份并占用跟踪容量。

分片与重组目前不能完整关联，受影响的已跟踪 skb 不生成正常时延样本，流量计数与时延样本数可能不同。独立健康计数报告缺口。超时关联另外由用户态每秒触发 BPF 清理程序，不注入报文。设备新建、改名、删除的发现使用 rtnetlink。

当前采集器要求所有挂载探针可用，缺少某个必需探针会报错，即使当时未出现该类流量。`tp_btf` 需要对应 tracepoint 的 BTF 类型，`fentry/fexit` 需要相应 BTF 函数目标；桥模块必须可用。全部时间是观测点之间的经过时间，Total 分位数独立计算；不能相加 Stack/Queue 分位数。XDP、AF_XDP 和硬件卸载绕过这些钩子的流量不在范围内。
