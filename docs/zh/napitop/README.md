# napitop

按网卡和 NAPI 实例观察 poll 工作量、触及 budget 的比例、poll 耗时及 CPU 热点，辅助定位收包处理压力。

## 安装

从 [napitop-release](https://github.com/calcky/tools/releases/tag/napitop-release) 安装 x86_64 静态程序：

```sh
curl -fL https://github.com/calcky/tools/releases/download/napitop-release/napitop-linux-x86_64 -o napitop
chmod +x napitop
install -m 755 napitop "$HOME/.local/bin/napitop"
```

确保 `$HOME/.local/bin` 已加入 `PATH`。Release 同时提供 ARMv7 和 ARM64 程序；运行时需要 BPF/tracing 权限。

## 常用命令

```sh
napitop                 # 实时窗口
napitop -i eth0         # 只看一个网卡
napitop -d 0.5          # 每 0.5 秒采样
napitop -i eth0 -c 10   # 输出十次纯文本快照
```

窗口用 `j/k` 或方向键选行，`[`/`]` 翻看该 NAPI 的 CPU，`s` 切换按工作量、budget 比例、平均耗时排序，`q` 或 Ctrl+C 退出。重定向输出时自动使用纯文本；不指定 `-c` 会持续输出。`NO_COLOR` 可关闭颜色。

## 选项

| 选项 | 含义 |
| --- | --- |
| `-i IFACE` | 仅显示当前网络命名空间内指定网卡 |
| `-d SEC` | 采样间隔，0.1–60 秒，默认 1 秒 |
| `-c N` | 输出 N 次纯文本快照后退出 |
| `-h` / `-V` | 帮助 / 版本 |

## 指标与限制

- `poll/s` 是 NAPI poll 调用速率；`work/s` 累加驱动返回的 work，通常接近处理包数，但不是所有驱动的线上包数。`work/poll` 为二者之比。
- `budget%` 是返回 work 达到本次 budget 的 poll 比例，**不是丢包率**。还需结合吞吐、CPU、驱动错误及 softnet 指标判断。
- `avg us` 从 `__napi_poll` 入口计到 `napi_poll` 事件；`p50 us*` 和 `p99 us*` 是以微秒为单位的 2 的幂直方图区间边界，不是精确分位数；`>16384` 表示落在开放尾桶。无匹配耗时样本时显示 `-`。
- 主表按 NAPI 实例聚合；CPU 以处理 work 排序，详情每页展示三个。NAPI ID 不等于硬件队列号。
- `map miss` 和 `timing miss` 非零代表采集有缺口。BPF map 的逐项读取不是全局原子快照，短周期数据可能有轻微差异。
- 需要 Linux 6.6+、BTF、`napi_poll` tracepoint、`__napi_poll` fentry 及 BPF/tracing 权限；只观察当前网络命名空间，不修改网卡配置。
- 已在隔离 veth 流量下验证约 90 至 123k work/s 的读数变化，未构造出 budget 触顶场景；内核 BPF 探针开销也没有可靠的定量结果。

[完整手册](https://github.com/calcky/tools/blob/master/napitop/README.md)
