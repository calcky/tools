# 观测钩子

本页说明 `skbtop` 实际挂载的 eBPF 观测点。`fentry/函数` 在函数入口观察，`fexit/函数` 在返回时取得结果，`tp_btf/事件` 使用内核 BTF 类型监听 tracepoint；它们不是配置在网卡上的 XDP/TC 程序，也不是一组 netfilter 规则。指标含义与操作见[使用说明](README.md)。

## 计时函数对应表

内核函数触发观测，BPF 处理函数记录时间或确认结果；两者不是同一个函数。下表与[采集源码](https://github.com/calcky/tools/blob/master/skbtop/bpf/observe.bpf.c)对应。

| 观测点 | 内核函数 / 触发位置 | 实际探针 | BPF 处理函数 |
| --- | --- | --- | --- |
| INPUT / FORWARD 起点 | `__netif_receive_skb_core()` 内的 `trace_netif_receive_skb(skb)` | `tp_btf/netif_receive_skb` | `on_receive()` → `receive_event()` → `begin()` |
| IPv4 OUTPUT 起点 | `__ip_local_out()` 入口 | `fentry/__ip_local_out` | `on_output4()` → `begin()` |
| IPv6 OUTPUT 起点 | `__ip6_local_out()` 入口 | `fentry/__ip6_local_out` | `on_output6()` → `begin()` |
| IPv4 INPUT 终点 | `ip_protocol_deliver_rcu()` 入口 | `fentry/ip_protocol_deliver_rcu` | `on_input4()` → `deliver()` |
| IPv6 INPUT 终点 | `ip6_protocol_deliver_rcu()` 入口 | `fentry/ip6_protocol_deliver_rcu` | `on_input6()` → `deliver()` |
| **Stack 终点 / Queue 起点** | **`__dev_queue_xmit()` 内的 `trace_net_dev_queue(skb)`** | **`tp_btf/net_dev_queue`** | **`on_queue()` → `enqueue()`** |
| Queue / Total 终点候选 | `xmit_one()` 内的 `trace_net_dev_start_xmit(skb, dev)`，在调用驱动之前 | `tp_btf/net_dev_start_xmit` | `on_attempt()` → `attempt_event()` |
| 确认发送结果 | `xmit_one()` 内的 `trace_net_dev_xmit(skb, rc, dev, len)`，在驱动返回之后 | `tp_btf/net_dev_xmit` | `on_result()` → `result_event()` |

在 Linux 6.6 的 `__dev_queue_xmit()` 中，`net_dev_queue` 位于出口 netfilter/TC 处理与 TX 队列选择之后、`__dev_xmit_skb()` 及 qdisc enqueue/bypass 之前。它不是 `qdisc_enqueue()` 的入口探针；无 qdisc 的路径也会触发。因此 Queue 还可能包含锁等待、调度与 BUSY 重试，不能解读为纯 qdisc 排队时间。

## INPUT：接口到本机

```text
tp_btf/netif_receive_skb                    t0：保存起点时间和 skb->len
  位于 __netif_receive_skb_core 内
        |
        | IP 接收、路由到本机
        v
IPv4: fentry/ip_protocol_deliver_rcu        t1：本机协议分发入口
IPv6: fentry/ip6_protocol_deliver_rcu

Stack = t1 - t0；仅采集 S，没有 Queue / Total
```

终点位于 TCP/UDP/ICMP 等后续协议处理、socket 和应用之前；IPv6 还可能在扩展头处理之前。NIC 接收、NAPI/GRO 以及发生在 RX core 入口之前的 RPS 工作不包含在内。这里不统计非 IP 的本机交付时延。

## OUTPUT：本机到接口

```text
IPv4: fentry/__ip_local_out                 t0：本机 IP 输出起点
IPv6: fentry/__ip6_local_out
        |
        | IP 输出、netfilter、邻居及出口处理
        v
__dev_queue_xmit(): trace_net_dev_queue(skb)
  tp_btf/net_dev_queue -> on_queue()       tq：Stack 终点 / Queue 起点
        |
        | 出口调度、qdisc、可能的驱动 BUSY 重试
        v
xmit_one(): trace_net_dev_start_xmit(skb, dev)
  tp_btf/net_dev_start_xmit -> on_attempt() tx：驱动发送尝试入口
        |
xmit_one(): trace_net_dev_xmit(skb, rc, dev, len)
  tp_btf/net_dev_xmit -> on_result()       结果：NETDEV_TX_OK 才确认完成

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
__dev_queue_xmit(): trace_net_dev_queue(skb)
  tp_btf/net_dev_queue -> on_queue()       tq：实际出接口已确定
        |
tp_btf/net_dev_start_xmit                  tx：驱动发送尝试入口
        |
tp_btf/net_dev_xmit                        结果：NETDEV_TX_OK 才确认完成

Stack = tq - t0；Queue = tx - tq；Total = tx - t0
```

转发按实际入、出接口形成有向路径；桥接泛洪的各出口分支独立统计，同接口 hairpin 也保留。NAT 不额外挂载一个计时钩子，不提供独立的 NAT 耗时。

| 实际函数入口探针 | BPF 处理函数 | 用途 |
| --- | --- | --- |
| `fentry/ip_forward` | `on_route4()` → `mark()` | IPv4 路由转发。 |
| `fentry/ip6_forward` | `on_route6()` → `mark()` | IPv6 路由转发。 |
| `fentry/br_handle_frame_finish` | `on_bridge_receive()` → `mark()` | 桥接接收。 |
| `fentry/br_forward` | `on_bridge_branch()` → `mark()` | 桥接出口分支。 |
| `fentry/br_flood` | `on_bridge_flood()` → `mark()` | 桥接泛洪。 |
| `fentry/br_forward_finish` | `on_bridge()` → `mark()` | 桥接转发出口。 |
| `fentry/br_dev_queue_push_xmit` | `on_bridge_transmit()` → `mark()` | 桥接发送出口。 |
| `fentry/br_dev_xmit` | `on_bridge_output()` → `mark()` | 本机经桥发出。 |

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

| 实际探针 | BPF 处理函数 | 作用 |
| --- | --- | --- |
| `fexit/skb_clone` | `on_clone()` → `inherit()` | 克隆身份继承。 |
| `fexit/skb_copy` | `on_copy()` → `inherit()` | 复制身份继承。 |
| `fexit/skb_copy_expand` | `on_expand()` → `inherit()` | 扩容复制继承。 |
| `fexit/__pskb_copy_fclone` | `on_pskb()` → `inherit()` | 部分复制继承。 |
| `fexit/skb_morph` | `on_morph()` → `inherit()` | 替换 skb 内容后的身份继承。 |
| `fexit/skb_segment` | `on_segment()` → `segments()` | GSO 子 skb 继承。 |
| `fexit/skb_segment_list` | `on_segment_list()` → `segments()` | GSO 列表继承。 |
| `fentry/skb_release_head_state` | `on_release()` → `forget()` | 清理头部状态关联。 |
| `tp_btf/consume_skb` | `on_consume()` → `consume_event()` → `forget()` | 消费路径清理。 |
| `tp_btf/kfree_skb` | `on_drop()` → `drop_event()` → `forget()` | 释放路径清理。 |
| `fentry/unregister_netdevice_queue` | `on_unregister()` | 停用接口身份。 |
| `fentry/ip_do_fragment` | `on_fragment4()` → `conversion()` | IPv4 分片覆盖缺口。 |
| `fentry/ip6_fragment` | `on_fragment6()` → `conversion()` | IPv6 分片覆盖缺口。 |
| `fentry/ip_defrag` | `on_reassembly4()` → `conversion()` | IPv4 重组覆盖缺口。 |
| `fentry/ipv6_frag_rcv` | `on_reassembly6()` → `conversion()` | IPv6 重组覆盖缺口。 |

`SEC("socket")` 的 `cleanup()` 由用户态通过 BPF test-run 每秒调用，执行 `origin_expire()` / `tx_expire()`，不挂载业务 socket。测试代码中的 `raw_tp/*` 和 `on_free()` 仅供原生状态机测试，不是正式采集器额外挂载的钩子。

`__kfree_skb` 会经过 `skb_release_head_state`，因此不再单独挂载探针。
Consume/drop tracepoint 仍覆盖无状态消费等其他释放路径；头部状态释放也负责在
`skb_morph` 前清理旧身份。GSO 使用最多 128 段的有界回调复用父关联，
每个子 skb 仍有独立身份并占用跟踪容量。

分片与重组目前不能完整关联，受影响的已跟踪 skb 不生成正常时延样本，流量计数与时延样本数可能不同。独立健康计数报告缺口。超时关联另外由用户态每秒触发 BPF 清理程序，不注入报文。设备新建、改名、删除的发现使用 rtnetlink。

当前采集器要求所有挂载探针可用，缺少某个必需探针会报错，即使当时未出现该类流量。`tp_btf` 需要对应 tracepoint 的 BTF 类型，`fentry/fexit` 需要相应 BTF 函数目标；桥模块必须可用。全部时间是观测点之间的经过时间，Total 分位数独立计算；不能相加 Stack/Queue 分位数。XDP、AF_XDP 和硬件卸载绕过这些钩子的流量不在范围内。
