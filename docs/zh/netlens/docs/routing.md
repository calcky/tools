# 路由与连接跟踪

## 查看连接与双向流量

```sh
sudo netlens conntrack
```

每个连接一行，显示协议、状态、原始端点、mark，以及双向字节、包数、PPS 和带宽。
Enter 打开原始/回复五元组、NAT 关系及可用计数；`s/r` 排序或反向。

按 `/` 输入条件，Ctrl+U 清空：

```text
tcp and dst port 443
src net 192.168.0.0/24
udp and portrange 10000-20000
```

这些表达式匹配原始五元组，`src/dst` 不使用转换后的 NAT 地址。
过滤只改变展示，不重置累计值，也不改变采集范围。

## 区分方向与累计值

| 字段 | 含义 |
| --- | --- |
| TX | 原始发起方向，不一定是本机网口的发送 |
| RX | 回复方向，不一定是本机网口的接收 |
| PACKETS / traffic byte | 连接生命周期中的累计包数 / 字节 |
| PPS / BANDWIDTH | 连续有效采样差值；带宽为 bit/s |
| avg pkt byte | 该方向累计字节 / 累计包数 |
| CT mark | conntrack 标记，不等于 socket 或包的其他标记 |

包数为零或没有 accounting 时，平均包长显示 `n/a`，不是零字节包。
硬件转发和 flow offload 可能绕过 conntrack 计数，统计不完整不代表流量停止。

容量、占用、插入失败、drop、early drop 等反映跟踪资源压力，但不是应用请求成功率。
规则计数在 Netfilter 入口查看；按 `:` 输入 `:netfilter` 可进入相关视图。
无计数器规则显示 `NO COUNTER`。原生 nftables 与 iptables-nft 不要相加。

## 查看路由和邻居

```sh
sudo netlens route
```

Routes、Policy Rules 和 Neighbours 按当前命名空间展示。
选择行按 Enter 查看完整匹配条件、nexthop、MTU、策略选择器或 ARP/NDISC 状态。
邻居 `FAILED` 是当前 NUD 状态，不是失败速率。

路由增删与邻居变化来自完整快照之间的净变化，不是实时事件日志。
在两次采样之间出现又消失的条目可能看不到；失败或不完整采样不会推进完整基线。

## 查询内核选择的路由

进入 Route Lookup，输入字面 IP 地址：

```text
192.168.0.1 from 192.168.0.2 oif eth0 mark 0x1
```

语法为：

```text
DEST [from SOURCE] [iif IFACE] [oif IFACE] [mark N] [uid N] [tos N]
```

源与目标必须属于同一地址族，数值支持十进制或 `0x` 前缀。不进行 DNS 查询。
结果是内核返回的最终路由、表和 nexthop，不展示所有策略规则的遍历过程。

## 判断转发问题的边界

转发流量通常没有本机应用 socket，要结合 Network、Conntrack、Qdisc 与 Interface 查看。
Network 将 IPv4/IPv6、ICMP、分片与重组分开，不能把所有错误字段加成总丢包数。
XDP redirect、桥接、隧道或硬件卸载可能绕过普通 IP 转发链，详见[数据包路径](packet-path.md)。
