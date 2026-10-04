# cachetop

用硬件 PMU 查看 LLC 读访问与未命中、MPKI、IPC 和 CPU 迁移，辅助检查进程线程的绑核效果。

## 安装

以 x86_64 为例；另提供 ARMv7 和 ARM64 静态程序，见 [cachetop-release](https://github.com/calcky/tools/releases/tag/cachetop-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/cachetop-release/cachetop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 cachetop-linux-x86_64 "$HOME/.local/bin/cachetop"
```

## 常用命令

```sh
cachetop                   # 全机逐 CPU
cachetop -p 1234           # 指定进程，逐线程查看
cachetop -p 1234 -d 0.5    # 每 0.5 秒刷新
cachetop -p 1234 -c 10     # 十次纯文本快照
```

窗口中使用 `j/k` 或方向键选择，`m`、`p`、`i`、`c` 分别按 LLC 未命中速率、MPKI、IPC、CPU/TID 编号排序，`q` 退出。

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-p PID` | 指定进程，按 TID 显示；省略时按主机 CPU 显示 |
| `-d SEC` | 采样间隔，0.1–60 秒，默认 1 秒 |
| `-c N` | 输出 N 次纯文本快照，不进入窗口 |

## 指标与限制

- `LLC rd/s`、`LLC miss/s` 是末级缓存**读**访问与读未命中速率；`rd hit% = 1 - misses / accesses`，不是全部缓存访问的命中率。MPKI 为每千条已完成指令的 LLC 读未命中数；IPC 为每周期已完成指令数。
- `migrate/s` 是 CPU 迁移事件速率。进程视图的 `CPU` 只是线程最近一次运行的 CPU，**不是**整个采样区间的驻留分布或允许绑核范围。
- `PMU run%` 表示硬件计数器的运行覆盖率。低于 100% 时计数会按运行时间缩放，覆盖率越低估计越不稳定。事件不可用或分母为零时显示 `-`，不把缺失项当作零。
- 需要可用的硬件 PMU 和 `perf_event_open` 权限；受 `perf_event_paranoid` 限制时可能需要 root 或 `CAP_PERFMON`。全机采样通常需要更高权限。不同 CPU 的通用 LLC 事件可用性和含义可能不同。
- LLC miss 降低不必然改善吞吐或尾延迟。比较绑核方案时应固定流量，并同时核对 PPS、丢包、CPU 占用和延迟。可用 `perf list` 与 `perf stat -t TID -e cycles,instructions,LLC-loads,LLC-load-misses` 交叉核对计数口径。

[完整手册](https://github.com/calcky/tools/blob/master/cachetop/README.md)
