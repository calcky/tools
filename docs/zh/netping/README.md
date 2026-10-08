# netping

测量 ICMP、UDP/TCP 回显及 TCP 建连延迟，支持三协议实时窗口和 MTU/MSS 探测。

[![netping 三协议实时统计与详情](../assets/screenshots/netping-window.png)](../assets/screenshots/netping-window.png)

三协议回环实测，每种协议 100 PPS。数值仅展示界面，不代表跨机性能。

## 安装

以 x86_64 为例；其他架构见 [netping-release](https://github.com/calcky/tools/releases/tag/netping-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netping-release/netping-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
```

## 常用命令

```sh
# ICMP，默认每秒一次
netping 192.168.0.1

# 目标机器启动 UDP/TCP 回显服务端
netping -s

# UDP 回显与 TCP 长连接回显
netping -u -c 20 192.168.0.1
netping -t -c 20 192.168.0.1

# 同一目标的 10 条独立 session，每条每秒一次
netping -t -j 10 -r 1 192.168.0.1
netping -u -j 10 -r 1 192.168.0.1

# 普通 TCP 服务的建连耗时
netping -C -p 443 192.168.0.1

# 三协议窗口；第二条将 TCP 改为端口 443 的建连检测
netping -w 192.168.0.1
netping -w -C -P 443 192.168.0.1

# 性能模式：1000 PPS，10 秒
netping -u -b -r 1000 -T 10 192.168.0.1

# 路径 MTU 和 TCP MSS
netping -M 192.168.0.1
netping -S -p 443 192.168.0.1
```

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-u` / `-t` / `-C` | UDP 回显 / TCP 回显 / TCP 建连，默认 ICMP |
| `-s` | 同时监听 UDP 和 TCP；默认端口 11111 |
| `-j N` | 每种协议的独立 session 数，1–256，默认 1；不与 `-s/-M/-S` 使用 |
| `-w` | 同时显示 ICMP、UDP、TCP 的统计与详情 |
| `-p PORT` | 目标或监听端口；默认 11111 |
| `-P PORT` | 仅覆盖窗口中的 TCP 端口，不影响 UDP |
| `-c N` / `-T SEC` | 次数 / 发送时长，先到者结束 |
| `-i SEC` / `-r PPS` | 间隔 / 速率，二者互斥 |
| `-W SEC` | 单次超时；默认 1 秒 |
| `-l BYTES` | 含测试头的应用载荷长度；默认 64 字节 |
| `-b` / `-f` | 性能模式 / 连续单请求 ping-pong；`-f` 需与 `-b` 使用 |
| `-M` / `-S` | 路径 MTU / TCP MSS 探测 |
| `-4` / `-6` | IPv4（默认）/ IPv6 |
| `-h` / `-v` | 帮助 / 版本 |

## 读取结果

逐条输出响应 RTT 或超时，结束时汇总收发、超时、乱序、重复和迟到回复。
RTT 使用毫秒，格式为 `rtt min/avg/max/mdev = ...`，另有 P50/P95/P99 分位数。
性能模式每秒显示 PPS、应用层带宽和 RTT 分布。

`-j` 的速率、间隔和次数按每条 session 计算，`-T` 是共同发送时长。
TCP 回显建立独立长连接，UDP 使用不同源端口，ICMP 使用不同 Echo ID 的逻辑探测流；`-C` 为独立建连调度。
逐条结果带 session 编号；默认汇总全部样本，结束后另列每条 session 的本地端点、收发、失败/超时、pending、平均值和 P95/P99。
整体 RTT 按成功样本数加权，分位数来自合并的样本直方图。单条 session 异常不会停止其他 session。
每条 session 保留有界历史，内存随 `-j` 增长；大量连接压测使用 `flowgen`。

ICMP/UDP 展示探测丢失率；TCP 展示请求失败或超时，不能解释为网络丢包率。
TCP 回显 RTT 不包含初始建连；`-C` 明确测量建连耗时。

## 窗口按键

方向键或 `j/k` 选择协议，空格暂停/恢复发送，`r` 重新开始，`q` 或 Ctrl+C 退出。
暂停时继续处理在途请求；退出后打印各协议汇总。
`-w -j N` 为每种协议建立 N 条 session；按 `s` 在所选协议总览和 session 明细间切换，`j/k` 选择 session。
暂停和重置作用于全部 session；退出后打印各协议总计与 session 表。

## 注意事项

- UDP/TCP 回显需要 `netping -s`；ICMP 和普通 TCP 建连不需要配套服务端。
- ICMP 权限不足时需要 `CAP_NET_RAW` 或调整系统 ping socket 权限。
- MTU 只有获得明确的报文过大证据并验证可达尺寸时才报告精确值；超时可能只是丢包或 ICMP 被过滤。
- MSS 是 TCP 载荷字节数，不等于 MTU；TCP 选项可能让实际发送 MSS 小于握手通告值。

[完整手册](https://github.com/calcky/tools/blob/master/netping/README.md)
