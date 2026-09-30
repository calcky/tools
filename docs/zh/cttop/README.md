# cttop

实时查看 Linux conntrack 连接、流量和异常信号，支持聚合下钻、NAT 视图及文件离线分析。

[![cttop 静态快照的源地址聚合与详情](../assets/screenshots/cttop-static.png)](../assets/screenshots/cttop-static.png)

静态样例快照，使用文档示例地址。累计包数和字节来自文件，带宽及变化速率为 `N/A`。

## 常用命令

```sh
# 按原始源 IP 聚合
sudo cttop

# 每个连接一行
sudo cttop -g none

# 按 mark、源 IP 或目标服务聚合
sudo cttop -g mark,src
sudo cttop -g dst,dport,proto

# 筛选 TCP 443，并查看 NAT 后的端点
sudo cttop -p tcp -D 443
sudo cttop -N -g src,sport

# 周期文本输出，共三次
sudo cttop -b -c 3

# 分析一次当前 conntrack 快照并退出
sudo cttop summary

# 导出后离线读取，或通过管道读取
sudo conntrack -L -o extended > conntrack.txt
cttop -f conntrack.txt
cttop summary -f conntrack.txt
sudo conntrack -L | cttop -f
sudo conntrack -L | cttop summary -f
```

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `summary` | 分析一次快照并退出；`--summary` 作为兼容写法保留 |
| `-g FIELDS` | 聚合字段：`src,sport,dst,dport,proto,zone,mark`；`none` 不聚合 |
| `-N` | 显示 NAT 转换后的正向端点 |
| `-s IP` / `-d IP` | 原始源 / 目标 IP 筛选 |
| `-S PORT` / `-D PORT` | 原始源 / 目标端口筛选 |
| `-p PROTO` | 协议筛选，如 `tcp`、`udp` |
| `-f [FILE]` | 读取 conntrack 文本快照；无文件名或 `-` 时读取标准输入 |
| `-i SEC` | 显示间隔；默认 1 秒 |
| `-r SEC` | 全量校准及带宽采样间隔；默认 5 秒 |
| `-m N` | 每组最小存活连接数；默认 0 |
| `-b` / `-c N` | 文本报告 / 报告次数 |
| `-h` / `-v` | 帮助 / 版本 |

## 读取结果

实时视图显示连接数量、状态分布、原始与回复方向的带宽、包数和字节数，以及新建、销毁和内核丢弃等信号。
按端口聚合后可回车进入该组，再按其他字段继续聚合。

包数和字节数需要内核 conntrack accounting 提供计数；缺失时显示 `N/A`。
带宽根据连续采样的字节差计算，覆盖不完整会明确标记，不将缺失数据当作零流量。

`summary` 汇总协议、TCP 状态、Top 来源/目标/服务/mark、NAT 和未应答连接。
包数和字节数会标出计数器覆盖范围；实时快照还显示内核连接表占用与累计失败/丢弃计数。
单次快照不能推算带宽、新建速率或连接年龄。`summary` 可与 `-N` 及连接筛选选项组合，
不能与周期报告或聚合选项 `-b/-c/-g/-i/-r/-W/-m` 组合。

## 窗口按键

| 按键 | 操作 |
| --- | --- |
| `0` | 每个连接一行 |
| `1`..`7` / `g` | 选择聚合字段 / 编辑字段列表 |
| Enter / Esc | 下钻 / 返回上一级 |
| `n` | 切换原始方向与 NAT 视图 |
| `/` / `s` | 搜索 / 切换排序 |
| 方向键、`j/k` | 选择行 |
| `h` / `q` | 帮助 / 退出 |

## 注意事项

实时监控需要目标网络命名空间中的 `CAP_NET_ADMIN`，一般使用 `sudo`；静态文件分析不需要 root。
静态快照只能显示已记录的包数、字节数和连接状态，无法计算带宽、新建速率或连接年龄。
命令行 IP/端口筛选始终匹配原始五元组，即使当前使用 NAT 视图。
工具只读，不修改防火墙或自动启用 accounting。

[下载静态程序](https://github.com/calcky/tools/releases/tag/cttop-v0.2.0) · [完整手册](https://github.com/calcky/tools/blob/master/cttop/README.md)
