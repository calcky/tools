# gomemtop

定时读取 Go 程序的 heap pprof，在终端窗口中查看当前堆占用和调用栈增长；指定本机 PID 后，还能对比进程 RSS 与 Go 运行时内存。增长是排查线索，不等于内存泄漏。

目标程序需在可信网络上提供 `net/http/pprof`。pprof 可能暴露函数名和程序内部信息，不应公开监听。

## 安装

以 x86_64 为例；其他架构见 [gomemtop-release](https://github.com/calcky/tools/releases/tag/gomemtop-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/gomemtop-release/gomemtop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 gomemtop-linux-x86_64 "$HOME/.local/bin/gomemtop"
```

确保 `$HOME/.local/bin` 在 `PATH` 中。

## 常用命令

```sh
# 每 30 秒采样；接受服务根地址或完整 heap URL
gomemtop http://127.0.0.1:6060

# 同时读取本机 PID 的 RSS 和 Go 运行时信息，按 d 查看详细分析
gomemtop -p 8110 http://127.0.0.1:6060

# 每 10 秒采样，单次请求超时 5 秒
gomemtop -i 10 -T 5 http://127.0.0.1:6060/debug/pprof/heap
```

## 选项

| 选项 | 含义 |
| --- | --- |
| `-p PID` | 读取本机进程的 RSS 与 Go 运行时信息；PID 必须在当前 `/proc` 可见 |
| `-i SEC` | 采样间隔，默认 30 秒，范围 0.2–3600 秒 |
| `-T SEC` | HTTP 请求超时，默认 10 秒，范围 0.2–3600 秒 |
| `-h` / `-V` | 帮助 / 版本 |

## 窗口操作

| 按键 | 操作 |
| --- | --- |
| `j/k`、方向键 | 选择调用栈；详细分析中用于滚动 |
| PageUp / PageDown | 翻动调用栈帧或分析内容 |
| `m` | 切换 `inuse_space` / `alloc_space` |
| `b` | 用当前样本重设基线 |
| `g` | 切换主动 GC；切换后重新设基线 |
| `d` | 显示或关闭 RSS 详细分析，仅 `-p` 可用 |
| 空格 / `r` | 暂停或恢复自动采样 / 立即采样 |
| `q`、Ctrl+C | 退出并恢复终端 |

## 结果与边界

主榜单默认按相对基线的 `inuse_space` 增长排序；选中调用栈可看当前值、上次变化、基线变化和完整帧。`alloc_space` 表示累计分配压力，不是存活内存。

使用 `-p` 时显示 RSS、匿名/文件/共享驻留页及 Go `MemStats`。诊断提示至少需要三次成功的配对采样，会列出数据依据和排查方向；按 `d` 可查看堆保留、span 空隙和 RSS 差值等细项。各计数器并非互斥的 RSS 分区，HTTP 与 `/proc` 的读取也非原子快照；无法据此直接判定泄漏或把 RSS 差值全部归因于 native 内存。

默认不触发 GC。开启主动 GC 会影响目标延迟；未经 GC 的堆增长也可能是正常回收周期。远程 pprof 目标的 RSS 需在目标主机运行 `gomemtop -p` 读取；无法读取的指标会标记为不可用。工具只在内存中保留聚合结果，不保存原始 profile。

[完整手册](https://github.com/calcky/tools/blob/master/gomemtop/README.md)
