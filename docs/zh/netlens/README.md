# netlens

分层查看 Linux 网络流量、错误、丢弃和资源压力，从概览进入连接、网卡或协议详情。

## 开始使用

```sh
sudo netlens
sudo netlens -i eth0,eth1 -d 0.5
```

默认每秒采样。`-d` 接受 0.25–60 秒；`-i` 筛选网口相关行，不改变主机或命名空间总计。
使用 `netlens --help` 查看参数。

从 Overview 选中一层或网口，按 Enter 打开详情，Esc 返回。也可以直接运行 `netlens socket` 等页面命令。

[![netlens 分层概览与回环网口统计](../assets/screenshots/netlens-overview.png)](../assets/screenshots/netlens-overview.png)

隔离网络命名空间中的回环流量。缺失来源保留实际状态，不作为零值展示。

## 按问题进入

| 想看什么 | 阅读 | 直接打开 |
| --- | --- | --- |
| 某个应用的连接、TCP RTT 与重传 | [连接与进程](docs/cli.md) | `netlens socket` |
| 网口流量、排队、丢弃与 CPU 中断 | [网卡、队列与中断](docs/interfaces.md) | `netlens interface` |
| NAT、连接跟踪、路由与邻居 | [路由与连接跟踪](docs/routing.md) | `netlens conntrack` / `route` |
| 单位、累计值、权限或缺失数据 | [指标与数据状态](docs/monitor-metrics.md) | `netlens providers` |
| XDP、TC 与协议栈之间的关系 | [数据包路径](docs/packet-path.md) | 参考说明 |

## 基本操作

| 按键 | 操作 |
| --- | --- |
| Tab / Shift+Tab | 切换页面 |
| 方向键、`j/k` | 选择行或滚动 |
| Enter / Esc | 打开详情 / 返回 |
| `s` / `r` | 切换排序字段 / 反向排序 |
| `/` / Ctrl+U | 筛选连接 / 清空筛选 |
| PgUp/PgDn / Home | 翻页 / 回到首行 |
| `a` | 在支持的详情中显示零值与不可用字段 |
| `t` | 切换间隔值与基线累计值 |
| 空格 / `p` | 暂停显示，采集继续 |
| `q` / Ctrl+C | 退出 |

按 `:` 输入页面名，如 `:softirq`、`:providers`，可直接切页。
连接行第一次点击选择，第二次点击打开详情；可排序表头再次点击会反向排序。

## 使用前了解

工具只读，不抓包、不加载 BPF、不修改网络配置。观察范围是当前网络命名空间，部分主机级指标单独标注。
`sudo` 提高进程和设备数据的可见性，但不能补齐内核或驱动不支持的字段。
`n/a` 不代表零；遇到缺失或过期数据，先查看 Providers。

[下载静态程序](https://github.com/calcky/tools/releases/tag/netlens-release) · [完整手册](https://github.com/calcky/tools/blob/master/netlens/README.md)
