# bpftop

实时查看 eBPF 程序的事件速率、平均运行时间和估算 CPU 占用；可进入单个程序的趋势图。这里提供上游 bpftop v0.9.0 的 ARMv7、ARM64、x86_64 静态编译版本。

## 安装

以 x86_64 为例；其他架构与校验和见 [bpftop-release](https://github.com/calcky/tools/releases/tag/bpftop-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/bpftop-release/bpftop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 bpftop-linux-x86_64 "$HOME/.local/bin/bpftop"
```

## 常用用法

```sh
bpftop          # 实时查看所有已加载的 eBPF 程序
bpftop -d 2     # 每 2 秒刷新一次
bpftop -h       # 查看完整帮助
```

在窗口中用 `j/k` 或方向键选择程序，Enter 查看趋势图，`f` 过滤，`s` 排序，`q` 退出。

## 选项

| 选项 | 含义 |
| --- | --- |
| `-d, --delay SEC` | 刷新间隔，1-3599 秒，默认 1 秒 |
| `-h, --help` | 显示帮助 |
| `-V, --version` | 显示上游程序版本 |

## 注意事项

- 程序明确要求 root；静态链接不意味着无需内核支持。上游要求 Linux 5.8 或更高版本，旧内核的可用功能可能有限。
- 程序通过内核 BPF 运行时统计计算速率和 CPU 占用估计，运行期间会启用统计，退出时关闭；这不是主机整体 CPU 占用。
- 没有显示程序时，先确认当前内核中确有已加载的 eBPF 程序及访问权限。

[上游说明](https://github.com/jfernandez/bpftop) · [本仓库打包说明](https://github.com/calcky/tools/blob/master/bpftop/README.md)
