# flowgen

使用配套回显服务端生成多会话 TCP/UDP 负载，记录请求响应并生成离线 RTT 和 HTML 时序报告。

## 安装

以 x86_64 为例；其他架构见 [flowgen-release](https://github.com/calcky/tools/releases/tag/flowgen-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/flowgen-release/flowgen-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 flowgen-linux-x86_64 "$HOME/.local/bin/flowgen"
```

## 常用命令

目标机器启动服务端：

```sh
flowgen -s -p 11112 -w 4 -o results/server-1
```

客户端固定会话测试：2 秒预热到 100 个会话，每个会话 20 PPS，持续 10 秒。

```sh
flowgen -u -c 100 -a 2 -r 20 -T 10 -w 1 \
  -P 20000-29999 -o results/fixed-1 192.168.0.1
```

TCP 会话更替：达到 100 个会话后，每秒替换 20 个。

```sh
flowgen -t -c 100 -a 2 -U 20 -r 20 -T 10 -w 1 \
  -P 20000-29999 -o results/churn-1 192.168.0.1
```

重复分析已有记录，不产生网络流量：

```sh
flowgen -R results/churn-1
```

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-s` | 服务端，同一端口提供 TCP 控制、TCP/UDP 数据通道 |
| `-t` / `-u` | 客户端 TCP / UDP，二选一 |
| `-c N` | 目标会话数；默认 1000 |
| `-a SEC` | 预热时间；默认 10 秒 |
| `-U RATE` | 预热后每秒替换的会话数；默认 0，不更替 |
| `-r PPS` | 每个就绪会话的请求速率；默认 10 |
| `-l BYTES` | 含协议头的应用消息长度；默认 128 字节 |
| `-T SEC` | 不含预热的负载时长；默认 60 秒，`0` 持续运行 |
| `-W SEC` | 建立、请求和排空超时；默认 1 秒 |
| `-w N` | 工作线程数 |
| `-B IP` / `-P LOW-HIGH` | 源 IP（可重复指定）/ 源端口池 |
| `-Q SEC` | 明确允许冷却后复用五元组；默认不复用 |
| `-L MODE` | 记录方式：`events`（默认）、`summary`、`off` |
| `-o DIR` / `-R DIR` | 记录目录 / 离线分析目录 |
| `-p PORT` | 服务端口；默认 11112 |
| `-4` / `-6` | IPv4（默认）/ IPv6 |
| `-h` / `-v` | 帮助 / 版本 |

## 查看报告

[![flowgen HTML 报告的延迟、样本、流量和会话时序](../assets/screenshots/flowgen-report.png)](../assets/screenshots/flowgen-report.png)

64 个 UDP 会话的回环实测，每会话 20 PPS、负载 12 秒；用于展示报告，不代表容量上限。

默认 `events` 模式下，客户端结束后自动分析，并在结果目录生成 `report.html`。
直接在浏览器打开即可，无需服务端或互联网连接。
报告包含 RTT Avg/P90/P99 等时序、会话就绪数量、收发速率、带宽和异常计数；CSV 保留分析数据。

`-R` 在终端显示汇总、延迟分布和诊断表。RTT 是完整往返时间；乱序按会话统计，抖动是同一会话相邻序号成功响应的 RTT 差绝对值。

## 注意事项

- 每次运行使用新的 `-o` 目录，避免覆盖记录。
- 所有初始会话就绪后才开始发包；目标请求速率为 `N × r`，不是 TCP/UDP 的线速 PPS。
- 请求与响应的应用消息长度相同。TCP 可能分段或合并，UDP 可能分片。
- 默认尽量不复用五元组。源地址必须已配置；为更替测试准备至少 `N + ceil(U × T)` 个可用源 IP/端口组合，并留失败余量。
- `limited`、`skipped` 表示本机容量或调度受限，不是网络丢包。TCP 超时也不是网络丢包率。
- 会话容量受文件描述符、内存和端口池限制；工具不自动修改 sysctl 或配置 IP。

[完整手册](https://github.com/calcky/tools/blob/master/flowgen/README.md)
