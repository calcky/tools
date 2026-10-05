# xpcap

同时观察 AF_XDP (XSK) 与常规网口 (PCAP) 的收发报文；按需开启 XDP 程序入口、出口和 redirect 阶段。默认抓 XSK 与 PCAP，不会替换网卡上已有的 XDP 程序。

## 安装

以 x86_64 为例；其他架构见 [xpcap-release](https://github.com/calcky/tools/releases/tag/xpcap-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/xpcap-release/xpcap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 xpcap-linux-x86_64 "$HOME/.local/bin/xpcap"
```

## 常用用法

```sh
xpcap -i eth0
xpcap -i any -c 20 tcp and port 443
xpcap -i eth0 -S xdp-entry,xdp-exit,redirect -q 3 -T 10
xpcap -i eth0 -S pcap -ev -c 10 tcp
xpcap -i eth0 -w trace.pcapng udp and port 9000
xpcap -i eth0 -w trace.pcapng --print udp and port 9000
```

`-i` 必填，可重复指定网口；`-i any` 抓所有网口，不能与其他 `-i` 同用。`-w` 写 PCAPNG，默认不逐包打印；加 `--print` 可同时打印。不带 `-w` 时照常逐包打印。简单过滤表达式可直接写在命令末尾；含括号时需用 shell 引号包住。

## 常用选项

| 选项 | 用途 |
| --- | --- |
| `-S LIST` | 选择阶段，逗号分隔；支持 `xsk`、`pcap`、`xdp-entry`、`xdp-exit`、`redirect`，以及 `xsk-in/out`、`pcap-in/out` |
| `-Q in\|out\|inout` | 收发方向，默认双向；`-Q out` 不包含 XDP 入口、出口与 redirect 阶段 |
| `-q QUEUE` | XDP/XSK 队列过滤；PCAP 不提供队列号 |
| `-c EVENTS` / `-T SECONDS` | 全局抓包数量 / 抓包时长上限 |
| `--print` | 与 `-w` 同用，同时逐包打印；启动状态和结束汇总始终显示 |
| `-s BYTES` | 每包保存字节数，默认 2048，最大 9216 |
| `-m N` | 每个阶段约保留 N 个匹配包中的 1 个 |
| `-B PAGES` | 每 CPU 的 perf buffer 页数，默认 256 |
| `-v` | 显示 IP 头细节，如 TTL、ID、分片标志和校验和字段 |
| `-e` | 显示链路头；Ethernet 包可看 MAC/VLAN，`any` 的 PCAP 包显示 SLL 可用字段 |

终端的 `PCAP`、`XSK`、`IN/OUT` 和队列分列显示；XDP 行显示 `XDP-ENTRY` 或 `XDP-EXIT`，不再附加 `IN`。`xdp-exit` 表示程序返回点，不是网卡发包。协议摘要包含 TCP flags、seq/ack、窗口与选项。`-v/-e` 只影响终端文本，不改变保存的报文；`-e` 在 `-i any` 下无法凭 SLL 头还原完整的源/目的 MAC。

`-w` 始终写 PCAPNG；把后缀改成 `.pcap` 不会生成传统 PCAP 文件。

## 过滤表达式

命令末尾的参数按 tcpdump 风格拼接成一个过滤表达式。当前使用 `pktbaffle` 的 cBPF 子集，常用语法如下：

```text
# 地址和网段
host 192.0.2.1
src host 192.0.2.1
net 192.0.2.0/24
dst net 2001:db8::/32

# 端口和范围
port 443
tcp dst port 22
udp src port 53
portrange 1024-65535
tcp src portrange 32768-60999

# 协议
tcp  udp  icmp  icmp6  arp  rarp  igmp  sctp
ah  esp  pim  vrrp  ip  ip6  proto 47

# 链路层、VLAN、MPLS、PPPoE
ether host aa:bb:cc:dd:ee:ff
ether src aa:bb:cc:dd:ee:ff
ether proto 0x0806
vlan 100
mpls 1000
pppoed
pppoes

# 广播、组播、长度
ip broadcast
ip multicast
ip6 multicast
ether broadcast
len > 1400
less 64
greater 1400

# 原始字段和 TCP/ICMP 常量
ip[9] = 6
tcp[tcpflags] & tcp-syn != 0
tcp[13] & tcp-syn != 0
icmp[icmptype] = icmp-echo
icmp6[icmp6type] = 128
```

逻辑运算支持 `and`/`&&`、`or`/`||`、`not`/`!`，优先级为 `not`、`and`、
`or`；复杂条件请使用括号。`src`/`dst` 可修饰 `host`、`net`、`port`、
`portrange`。例如：

```sh
xpcap -i eth0 'tcp and (dst port 80 or dst port 443)'
xpcap -i eth0 'src net 192.0.2.0/24 and dst portrange 8000-9000'
xpcap -i eth0 'vlan 100 and tcp[tcpflags] & tcp-syn != 0'
```

`tcp-fin`、`tcp-syn`、`tcp-rst`、`tcp-push`、`tcp-ack`、`tcp-urg`、`tcp-ece`、`tcp-cwr` 可用于 TCP flags；`tcpflags` 是 flags 字段偏移。`icmptype`、`icmpcode`、`icmp6type`、`icmp6code` 可用于 ICMP 原始字段。

这不是完整的 libpcap 语法：`inbound`、`outbound` 和复杂 IPv6 扩展头遍历
不可用，`ether multicast` 也不可靠，应使用 `ip multicast` 或
`ip6 multicast`。命名网口上的 PCAP 过滤在内核执行，`-i any` 的 PCAP
过滤在用户态执行；XDP/XSK 过滤必须能压缩到 128 条 classic BPF 指令，
否则启动时会报错。

## 边界

- XDP/XSK 阶段需要 Linux 6.6+、BTF 和 BPF 跟踪权限；单独 `-S pcap` 仅需 `AF_PACKET` 和 `CAP_NET_RAW`。
- XSK RX 表示 RX ring 已接收，XSK TX 表示驱动取走描述符或发起通用发送尝试，不等于应用读取或物理发出。多个阶段看到同一个包时不会自动去重。
- `-i any` 的 PCAP 使用 Linux cooked (SLL) 格式，XSK/XDP 保持 Ethernet。混合链路类型的 PCAPNG 建议用 Wireshark/tshark 查看；部分 tcpdump 版本不能读取。
- `-i any` 的 PCAP 内容过滤在用户态进行，高速流量建议指定网口；XDP/XSK 过滤仍在内核探针中完成。

[完整手册](https://github.com/calcky/tools/blob/master/xpcap/README.md)
