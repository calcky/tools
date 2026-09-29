# 数据包路径

同一个包可能走普通协议栈，也可能被 XDP、TC、桥接或硬件卸载提前处理。
本页用常见路径解释**在哪里处理、哪些层能看到、为什么计数不同**，不是 netlens 的逐包追踪结果。
示意以 Linux 6.6 常见路径为参考，具体 hook、驱动和设备行为仍取决于运行环境。

## 普通接收路径

```text
wire -> NIC RX queue / DMA
                  |
             IRQ -> NAPI poll
                  |
            native XDP (if attached)
                  | PASS
                  v
             skb / GRO
                  |
            receive processing
                  |
            generic XDP (if attached)
                  | PASS
                  v
             TC ingress
                  |
        IP / routing / netfilter
                  |
            local delivery
                  |
             TCP / UDP
                  |
           socket -> application
```

native 和 generic 是不同运行模式的位置，不表示同一个普通接收包必然运行两次 XDP。
图省略 VLAN、packet taps、netfilter ingress、桥接等分支，不能当作所有 hook 的严格排序。

NIC 将帧放入接收缓冲，驱动通过 NAPI 按批处理；一个中断可能触发多个包的处理。
持续轮询、busy polling 等情况下，也不需要每批都有新硬中断。
GRO 可以合并报文，backlog/RPS 路径并非每个包都会经过。

| 观察点 | netlens 中优先看 |
| --- | --- |
| NIC、驱动、接收资源 | Interface 的标准与驱动计数 |
| 中断与接收处理压力 | HardIRQ、SoftIRQ、softnet |
| IP 错误、分片与重组 | Network |
| TCP/UDP 协议错误 | Transport |
| 应用未读取、TCP 窗口与 RTT | Socket 详情 |

## XDP {#xdp}

XDP 在接收路径运行 BPF 程序，对报文做快速决策。它不是额外的一层 TCP 服务，也不保证进入 IP 栈。
普通网口程序通常面对链路层报文；解析边界、修改头部和重定向目标由程序负责。

### 三种运行模式

| 模式 | 大致位置 | 重要区别 |
| --- | --- | --- |
| native / driver | 驱动接收处理，通常在创建 skb 之前 | 依赖驱动支持，可提前绕过后续协议栈 |
| generic / skb | 已创建 skb 的软件接收路径 | 兼容性较广，已付出部分 skb/接收处理开销 |
| hardware offload | 支持的 NIC 上执行 | 能力受硬件限制，部分流量可能不进入主机接收路径 |

**native 不等于 AF_XDP zero-copy。** XDP 的执行模式与 AF_XDP 的 copy/zero-copy 数据传递模式是不同选择。
不能仅根据模式名字判断速度、CPU 开销或所有可用功能。

### 程序返回动作之后

```text
                     XDP program
                          |
    +---------+-----------+-----------+-------------+
    |         |           |           |             |
   PASS      DROP        TX       REDIRECT        ABORTED
    |         |           |           |             |
 normal    discard    same-device    target      exception
 receive              transmit       |
                              +------+------+
                              |      |      |
                           DEVMAP CPUMAP XSKMAP
                              |      |      |
                           netdev   CPU   AF_XDP
```

| 动作 | 后续行为 | 对统计的影响 |
| --- | --- | --- |
| XDP_PASS | 继续当前接收路径 | 可以进入后续统计点，但仍可能在后面丢弃 |
| XDP_DROP | 在 XDP 处丢弃 | 不进入后续 IP/TCP/应用计数；不保证计入标准 RX dropped |
| XDP_TX | 从接收设备发出报文 | 不等于普通应用发送，一般不经过常规出口 qdisc |
| XDP_REDIRECT | 交给指定设备、CPU 或 AF_XDP socket 等目标 | 不意味着经过路由/NAT；返回动作不保证后续交付成功 |
| XDP_ABORTED | 异常动作，丢弃并产生异常追踪信号 | 不等于普通 DROP；netlens 不采集该追踪信号 |

DEVMAP 常用于设备间转发，不自动替程序完成普通 IP 路由、TTL、邻居解析或 NAT。
CPUMAP 将处理搬到另一 CPU，后续可再运行程序或进入协议栈，不是“换 CPU 就直接上网”。
重定向仍可能因目标、队列、缓冲或驱动错误失败；动作次数与成功发出的包数不是同一个指标。
普通应用的网口 TX 不会自动经过接收侧 XDP；例如进入对端 veth 的接收路径时，才可能在那里遇到 XDP。

### netlens 能看到多少

netlens **不采集通用的 XDP 程序挂载清单、BPF map 或 PASS/DROP/REDIRECT 动作统计**。
驱动可能提供 `xdp_*` 私有字段，若来源可用会保留，但名称、单位和是否重叠依赖驱动。

native XDP_DROP 的包通常不会到达同一设备下游的普通 tcpdump/AF_PACKET 抓包点。
硬件计数可能增加，IP、TCP 或 softnet 的对应计数却不增加；generic 和 native 的可见性又不同。
不能把这些差值直接解释成驱动丢包，也不能从 IP 计数为零断言没有流量。
需要验证动作分布，应另查程序自己的 map、驱动说明或专门追踪工具。

## AF_XDP：到用户态的另一条路 {#af-xdp}

AF_XDP 是 socket 家族，不是 XDP 的另一个名称。接收通常由 XDP_REDIRECT 通过 XSKMAP 交给匹配设备/队列的 socket。

```text
NIC RX -> XDP -> XSKMAP -> AF_XDP RX ring
                                     |
                              user application
                                     |
                              AF_XDP TX ring
                                     |
                              driver -> wire

FILL: application supplies receive buffers
COMPLETION: transmitted buffers can be reused
UMEM: shared packet-buffer memory
```

RX/TX ring 放描述符，数据位于 UMEM。FILL 提供接收缓冲，COMPLETION 归还已完成发送的缓冲。
缺少 FILL 缓冲或 RX ring 没空间都可能使接收失败；COMPLETION 不代表对端已收到。
AF_XDP 不提供 TCP 可靠性、重传或 RTT，应用需要自行解析与处理协议。

copy 模式复制数据到 UMEM；zero-copy 在驱动支持时直接利用 UMEM 缓冲，不能仅凭 native 模式认定启用了 zero-copy。
其收发绕过普通 TCP/UDP socket 交付及常规出口 qdisc；这不代表没有队列或背压。

在 netlens Socket 页按 `/` 输入 `xdp`，可查看当前可见 socket 的队列 ID、UMEM、ring 配置和可用错误计数。
ring 配置容量不是当前占用，错误计数也不等于全局 XDP_DROP 数。

## TC：与 XDP 的区别

TC ingress/egress 通常处理 skb，可分类、丢弃、修改或重定向。
native XDP 在更早的驱动接收路径运行，XDP_DROP 的包不会继续到该设备后续 TC ingress。
两者都能运行 BPF，但程序类型、上下文、helper 和处理成本不同，不能直接互换。

TC ingress 不是普通出口排队；egress qdisc 可以调度和缓存待发送流量。
native XDP_TX、常见 DEVMAP redirect、AF_XDP TX 通常绕过常规出口 qdisc，不能用其 qdisc 流量推算所有 TX。
netlens 当前显示 qdisc 对象统计，不采集 class/filter/action 或每条 TC-BPF 动作计数。

## 普通发送路径

```text
application -> socket / TCP / UDP
                         |
                  IP / route lookup
                         |
                  netfilter output
                         |
                  netfilter postrouting
                         |
                  TC egress / qdisc
                         |
                  driver / TX ring
                         |
                        wire
```

TCP 重传属于传输层；qdisc requeue 是重新入队，不是 TCP 重传。
`acked-app` 是对端 TCP 已确认的应用字节，不表示对端应用已经读取或处理。
TX 计数增加只反映本地统计点，不能单独证明送达。

## 普通 IP 转发与旁路

```text
ingress -> receive -> IP routing
                          |
                  netfilter forward
                          |
                  netfilter postrouting
                          |
                  qdisc -> egress
```

conntrack 在相应 netfilter hook 跟踪连接，NAT 在配置的 hook 进行转换；并非每个包都创建新连接或重新决定 NAT 映射。
普通转发通常不经过本机应用 socket，Socket 页为空不代表没有转发。
XDP redirect 不等同于此路径；桥接、隧道、veth 和硬件 offload 也可能改变路径及可见性。
Conntrack TX/RX 是原始/回复方向，不是入口/出口网卡方向。

## 为什么各层包数对不上

| 原因 | 常见影响 |
| --- | --- |
| GRO / LRO | 接收报文被合并，后续软件包数不等于线上帧数 |
| GSO / TSO | 较大的软件包被拆分发送，线上包数可能更多 |
| IRQ coalescing / NAPI | 一个中断或一次轮询处理多个包 |
| XDP / TC | 丢弃、重定向或旁路使后续统计点看不到包 |
| veth / bridge / tunnel | 同一业务流量可能在多个 netdevice 计数 |
| flow / hardware offload | 部分流量绕过软件跟踪和规则计数 |
| 重传与不同字节定义 | TCP 段数、应用字节、链路字节不是同一个口径 |

比较前先确认时间窗口、统计范围、单位以及 Providers 的数据状态。
某层丢弃计数增加可以缩小排查范围，但相邻层总计之差不能证明某个包在哪一层丢失。

## 进一步阅读

- [Linux AF_XDP](https://docs.kernel.org/6.6/networking/af_xdp.html)：UMEM、rings 与 copy/zero-copy。
- [Linux XDP redirect](https://docs.kernel.org/6.6/bpf/redirect.html)：重定向流程、失败与追踪。
- [DEVMAP](https://docs.kernel.org/6.6/bpf/map_devmap.html) / [CPUMAP](https://docs.kernel.org/6.6/bpf/map_cpumap.html)：设备与 CPU 重定向。
