# xpcap

同时观察 AF_XDP (XSK) 与常规网口 (PCAP) 的收发报文；按需开启 XDP 程序入口、出口和 redirect 阶段。默认抓 XSK 与 PCAP，不会替换网卡上已有的 XDP 程序。

## 构建与运行

```sh
make xpcap
sudo bin/xpcap -i eth0
sudo bin/xpcap -i any -c 20 tcp and port 443
sudo bin/xpcap -i eth0 -S xdp-in,xdp-out,redirect -q 3 -T 10
sudo bin/xpcap -i eth0 -S pcap -ev -c 10 tcp
sudo bin/xpcap -i eth0 -w trace.pcapng udp and port 9000
```

`-i` 必填，可重复指定网口；`-i any` 抓所有网口，不能与其他 `-i` 同用。`-w` 在终端输出之外写 PCAPNG。简单过滤表达式可直接写在命令末尾；含括号时需用 shell 引号包住。

## 常用选项

| 选项 | 用途 |
| --- | --- |
| `-S LIST` | 选择阶段，逗号分隔；支持 `xsk`、`pcap`、`xdp-in`、`xdp-out`、`redirect`，以及 `xsk-in/out`、`pcap-in/out` |
| `-Q in\|out\|inout` | 收发方向，默认双向；`xdp-out` 表示程序出口，不代表网口发包 |
| `-q QUEUE` | XDP/XSK 队列过滤；PCAP 不提供队列号 |
| `-c EVENTS` / `-T SECONDS` | 全局抓包数量 / 抓包时长上限 |
| `-s BYTES` | 每包保存字节数，默认 2048，最大 9216 |
| `-m N` | 每个阶段约保留 N 个匹配包中的 1 个 |
| `-B PAGES` | 每 CPU 的 perf buffer 页数，默认 256 |
| `-v` | 显示 IP 头细节，如 TTL、ID、分片标志和校验和字段 |
| `-e` | 显示链路头；Ethernet 包可看 MAC/VLAN，`any` 的 PCAP 包显示 SLL 可用字段 |

终端的 `PCAP`、`XSK`、`IN/OUT` 和队列分列显示，协议摘要包含 TCP flags、seq/ack、窗口与选项。`-v/-e` 只影响终端文本，不改变保存的报文；`-e` 在 `-i any` 下无法凭 SLL 头还原完整的源/目的 MAC。

## 边界

- XDP/XSK 阶段需要 Linux 6.6+、BTF 和 BPF 跟踪权限；单独 `-S pcap` 仅需 `AF_PACKET` 和 `CAP_NET_RAW`。
- XSK RX 表示 RX ring 已接收，XSK TX 表示驱动取走描述符或发起通用发送尝试，不等于应用读取或物理发出。多个阶段看到同一个包时不会自动去重。
- `-i any` 的 PCAP 使用 Linux cooked (SLL) 格式，XSK/XDP 保持 Ethernet。混合链路类型的 PCAPNG 建议用 Wireshark/tshark 查看；部分 tcpdump 版本不能读取。
- `-i any` 的 PCAP 内容过滤在用户态进行，高速流量建议指定网口；XDP/XSK 过滤仍在内核探针中完成。

[完整手册与构建依赖](https://github.com/calcky/tools/blob/master/xpcap/README.md)
