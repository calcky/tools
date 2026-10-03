# systop

`systop` 使用 eBPF 统计系统调用与进程的调用速率，可选统计系统调用耗时。默认打开终端窗口；`-c` 输出适合重定向的文本快照。

需要以 root 或具有相应 BPF/tracepoint 权限的账户运行。以下示例省略提权前缀：

```sh
systop                 # 实时窗口
systop -p 1234         # 按线程列出 PID 1234 的调用，另看该进程的 syscall 排行
systop -d 0.5 -c 5    # 每 0.5 秒打印一次，共 5 次
systop -c 1 -n 20     # 每张表显示前 20 行
systop -L -p 1234     # 测量调用耗时并查看进程 1234
systop -L -c 3        # 文本快照中显示平均耗时和 P95
systop -L -o calls    # 耗时模式改按调用次数排序
```

窗口按 `Tab` 切换 syscall/进程表，`j/k` 或方向键选择，`Enter` 按所选 syscall 或 PID 筛选另一张表，`Esc` 清除筛选，`-L` 时按 `s` 切换总耗时/调用次数排序，`q` 或 Ctrl+C 退出。`-p` 时进程表改为线程表，默认选中线程表；`Enter` 可查看该线程的 syscall 分布，`Esc` 返回进程汇总，仍保留 `-p`。窄终端一次显示一张表，宽终端并排显示。

| 选项 | 用途 |
| --- | --- |
| `-d SEC` | 采样间隔，默认 1 秒 |
| `-c N` | 输出 N 次文本快照 |
| `-p PID` | 显示该进程的 syscall 分布和按 TID 区分的线程榜 |
| `-n N` | 文本模式每张表的行数，默认 12 |
| `-L` | 启用系统调用进入/退出配对和耗时统计，开销高于默认模式 |
| `-o calls\|time` | `-L` 模式的排序方式；默认按区间总耗时，`calls` 改按调用次数 |
| `-h`, `-V` | 帮助和版本 |

`CALLS/s` 是采样区间内 `sys_enter` 次数除以实际采样时长。使用 `-L` 时，`TIME ms/s` 是区间内已完成调用的墙钟耗时总和除以采样秒数，多个线程相加可以超过 1000 ms/s；默认用它排序。`AVG ms` 是已完成调用的平均进入到退出耗时，包含阻塞和调度等待，不是 CPU 执行时间；跨区间的调用在退出所在区间计入耗时。`P95~ms` 是对数微秒分桶的近似值，仅在全局 syscall 榜提供；按 PID 筛选后只显示该进程的平均耗时，P95 为 `-`。未完成的调用不计入耗时，不能用 `TIME ms/s` 除以 `CALLS/s` 求平均值。

全局 syscall 次数使用 per-CPU 数组；进程明细使用最多 65536 个键的 LRU 映射。`-p` 时另启用只记录目标进程的线程映射，以 TID 和线程启动时间区分线程生命周期。`process keys` 和 `thread keys` 都是“生命周期 × syscall 编号”组合，不是进程或线程数；接近上限或出现 `thread-map errors` 时明细可能不完整。耗时配对使用 65536 键的有界 Hash；`inflight` 是采样时近似的未完成线程调用数，接近上限时需关注 `start failures`，写满不会静默淘汰。`unmatched exits` 包含启动时已在执行的调用以及未记录成功的调用；`process misses` 表示进程明细已缺失，全局耗时仍可用；`abandoned` 是线程退出时尚未观察到 `sys_exit` 的记录，不一定是错误。`paired` 是成功配对的完成调用数，不能与同一区间的 `CALLS/s` 直接计算覆盖率。映射并非原子快照，不应强行相加对账。未知 syscall 显示为 `sys_<编号>`；编号超出 0–1023 时计入 `out-of-range`。

## 安装

需要 Linux BTF、`sys_enter` tracepoint 和加载 BPF 的权限，通常以 root 运行。运行时不修改内核配置。x86_64 下载示例（安装到 `/usr/local/bin` 需相应写权限）：

```sh
curl -fL https://github.com/calcky/tools/releases/download/systop-release/systop-linux-x86_64 -o systop
install -m 755 systop /usr/local/bin/systop
```

Release 也提供 ARMv7 和 ARM64 静态可执行文件。源码构建可使用 `make systop` 与 `make install-systop`。
