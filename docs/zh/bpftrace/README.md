# bpftrace

使用简短脚本动态跟踪 Linux 内核和进程。提供 ARMv7、ARM64、x86_64 的全静态程序。

## 安装

从[下载页面](https://github.com/calcky/tools/releases/tag/bpftrace-release)选择匹配架构的附件。
以 x86_64 为例：

```sh
chmod +x bpftrace-linux-x86_64
sudo ./bpftrace-linux-x86_64 --info
```

程序不依赖目标系统的动态 musl/glibc，但跟踪功能仍取决于内核支持及权限。

## 常用命令

```sh
# 列出系统调用 tracepoint
sudo ./bpftrace-linux-x86_64 -l 'tracepoint:syscalls:sys_enter_*'

# 打印执行程序的进程名
sudo ./bpftrace-linux-x86_64 -e \
  'tracepoint:syscalls:sys_enter_execve { printf("%s\n", comm); }'

# 每秒统计各进程的 read 调用次数
sudo ./bpftrace-linux-x86_64 -e \
  'tracepoint:syscalls:sys_enter_read { @[comm] = count(); } interval:s:1 { print(@); clear(@); }'

# 执行已有脚本
sudo ./bpftrace-linux-x86_64 trace.bt
```

按 Ctrl+C 停止跟踪。

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-e SCRIPT` | 运行内联脚本 |
| `-l [PATTERN]` | 列出匹配的探针 |
| `-p PID` | 附加到现有进程，具体范围取决于探针类型 |
| `-c COMMAND` | 启动命令并跟踪其运行期间 |
| `--info` | 查看内核与跟踪能力 |
| `--help` / `--version` | 帮助 / 版本 |

## 注意事项

- 一般需要 root 或对应的跟踪权限；容器可能额外限制 BPF。
- 部分脚本需要内核 BTF；静态程序不会补齐内核缺失的功能。
- 高频探针和大量打印会影响被测系统，先选择较小的跟踪范围。
- 本静态版本不提供 `skb_output` 功能。

[下载静态程序](https://github.com/calcky/tools/releases/tag/bpftrace-release) · [完整说明](https://github.com/calcky/tools/blob/master/bpftrace/README.md) · [上游手册](https://bpftrace.org/docs)
