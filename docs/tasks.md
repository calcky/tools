# 常见任务

以下命令从仓库根目录执行，假定已运行对应的 `make` 构建目标。

## 网卡硬中断和软中断

```sh
./bin/irqtop -n
./bin/irqstat -n 1 5
```

`irqtop` 用于交互查看，`irqstat` 用于周期文本输出。筛选、阈值、CPU 分布及 softnet 指标见 [irqtop 手册](irqtop/README.md)。

## 同时检查 ICMP、UDP 和 TCP

服务端：

```sh
./bin/netping -s
```

客户端，替换为服务端地址：

```sh
./bin/netping -w 192.168.0.1
```

UDP/TCP 回显需要配套服务端。普通 TCP 服务的建连耗时可以直接检测：

```sh
./bin/netping -C -p 443 192.168.0.1
```

更多见 [netping 手册](netping/README.md)，包括性能模式、MTU 和 MSS。

## 查看 conntrack 或分析导出文件

```sh
sudo ./bin/cttop
sudo ./bin/cttop -g mark,src
sudo ./bin/cttop -g none
```

离线分析不需要 root，导出时需要读取 conntrack 的权限：

```sh
sudo conntrack -L -o extended > conntrack.txt
./bin/cttop -f conntrack.txt
sudo conntrack -L | ./bin/cttop -f
```

按回车下钻，`g` 切换聚合，`n` 切换 NAT 视图。计数和静态快照的限制见 [cttop 手册](cttop/README.md)。

## 多会话测试与离线报告

先启动 flowgen 服务端，再从客户端发起测试。完整的固定会话、连接更替和结果分析示例见 [flowgen 手册](flowgen/README.md)。

```sh
./bin/flowgen -s -p 11112 -w 1 -o results/server-1
```

在另一终端运行 100 个 UDP 会话的回环测试：

```sh
./bin/flowgen -u -c 100 -a 2 -r 20 -T 10 -w 1 \
  -P 20000-29999 -o results/fixed-1 127.0.0.1
./bin/flowgen -R results/fixed-1
```

每次运行使用新的结果目录。报告包含 RTT 分布和收发统计，具体语义以手册为准。

## 网络栈监控

```sh
sudo ./bin/netlens
./bin/netlens --help
```

从整体状态进入网口、socket 等详情。参阅 [命令与交互](netlens/docs/cli.md) 和 [指标含义](netlens/docs/monitor-metrics.md)。
