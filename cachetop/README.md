# cachetop

`cachetop` 用 Linux `perf_event_open` 的硬件 PMU 计数器观察末级缓存（LLC）读访问、读未命中、指令、周期和 CPU 迁移。适合检查 XSK、网络 I/O 和计算线程的绑核效果，不依赖 eBPF。

## 使用

```sh
cachetop                  # 全机逐 CPU
cachetop -p 1234          # 指定进程逐 TID，顶部显示进程汇总
cachetop -p 1234 -d 0.5   # 每 0.5 秒采样
cachetop -p 1234 -c 3     # 输出三次纯文本快照
```

窗口中用 `j/k` 或方向键移动，`m`、`p`、`i`、`c` 分别按 LLC 未命中速率、MPKI、IPC、CPU/TID 编号排序；`q` 或 Ctrl+C 退出。`-c` 文本模式不需要终端。

## 指标口径

- `LLC rd/s` 是通用 LLC 读访问事件（`PERF_COUNT_HW_CACHE_LL:READ:ACCESS`）的速率；`LLC miss/s` 是对应的读未命中速率。`rd hit% = 100 * (1 - misses / accesses)`，**不是**各级缓存或所有访问类型的全局命中率。
- `MPKI` 是每千条已完成指令对应的 LLC 读未命中数；`IPC` 是每周期已完成指令数。汇总先累加计数再计算比值，不平均各 CPU 的百分比。
- `migrate/s` 是 CPU 迁移事件速率。进程视图的 `CPU` 取自 `/proc` 最近运行 CPU，不代表线程在该 CPU 的时间占比；绑核范围可另查 `taskset` 或 `/proc/PID/task/TID/status`。
- `PMU run% = time_running / time_enabled`。PMU 复用时按该比例缩放计数器速率；覆盖率低时估计不稳定。`-` 表示事件不可用、无运行时间或分母为零。任一行缺少 LLC 事件时，汇总 LLC 比率显示 `-`，不伪装成全量统计。

硬件事件的可用性和含义取决于 CPU 和内核。通用 LLC 事件不可用时，仍显示指令、周期和 IPC，LLC 项显示 `-`；迁移事件不可用时也显示 `-`。不会以含义更宽泛的 `cache-misses` 代替 LLC 读未命中。正式比较前建议在目标机检查 `perf list`，并用 `perf stat -t TID -e cycles,instructions,LLC-loads,LLC-load-misses` 交叉核对。

根据 `/proc/sys/kernel/perf_event_paranoid` 的配置，可能需要 root 或 `CAP_PERFMON`；全机逐 CPU 模式通常需要更高权限。进程中新出现的线程先建立基线，下一采样区间才有速率。超过 4096 个线程时拒绝启动，避免打开过多 perf 文件描述符。
