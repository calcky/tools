# bpfmap

只读的 BPF map 终端查看器。列表显示 map ID、名称、类型、容量、键值大小和 bpffs pin 路径；进入 map 后限量预览键值，并观察相邻采样的变化。不会创建、更新或删除任何 BPF map。

## 用法

读取 map 元数据通常需要 `CAP_BPF` 或 `CAP_SYS_ADMIN`；读取 map 条目还取决于该 map 的权限与类型。使用具备相应权限的账号运行。

```sh
bpfmap
bpfmap -m 42
bpfmap -n 32 -d 2
```

| 选项 | 作用 |
| --- | --- |
| `-m ID` | 直接进入指定 map |
| `-n N` | 每轮最多读取 N 条，默认 64，范围 1-256 |
| `-d SEC` | 条目刷新间隔，默认 1 秒，范围 0.2-60 秒 |
| `-h` / `-V` | 帮助 / 版本 |

`Enter` 打开 map，`Esc` 返回列表；`j/k` 或方向键移动，`r` 立即刷新，`h` 查看帮助，`q` 或 Ctrl+C 退出。列表每 5 秒刷新，pin 路径扫描最多访问 2048 个节点；条目每轮最多读取 `-n` 个，另做一次无值的下一键检查来标记截断。设置 `NO_COLOR=1` 可禁用颜色。需要交互终端。

## 解读

- 列表中的 `CAPACITY` 通常是 map 的最大条目数；ringbuf 显示带 `B` 单位的缓冲区字节数。`KEY` 和 `VALUE` 是单个键和值的字节数，不是整张 map 的内存占用。详情中的 `KEY` 标识一个条目，`VALUE` 是当前读到的内容，具体含义由创建 map 的程序定义。
- 支持普通 hash、array、per-CPU hash/array、LRU hash 和 LPM trie 的只读预览。ringbuf、队列/栈、程序数组、socket/设备引用等类型只显示元数据；不调用会消耗数据的 `pop` 或 `lookup_and_delete`。
- 有 map BTF 时用 libbpf 解码键值；无法加载 BTF 或解码失败时显示有界的十六进制预览。单个键或值超过 4096 字节、per-CPU 条目超过 64 KiB 时不预览。每轮总读取预算最多 2 MiB。
- `DELTA` 中 `+N` 仅用于 BTF 证实的无符号整数值；结构体可显示顶层整数字段的差值，per-CPU 整数值先按 CPU 求和。`=` 表示字节未变，`changed` 表示无法细分的内容变化，`reset/-` 表示数值下降，`new` 表示该键上轮未观察到。它是两轮原始差值，不是每秒速率。不可预览的 map 不显示空的键值表。
- 预览始终从 map 的首键开始，并非随机样本；大 map 只看到前 N 条。并发写入 hash 时遍历不是原子快照，可能漏键、重复键或读不到已删除的键。不能将预览数量或变化量解释为整张 map 的总量。
- 未找到 pin 路径不代表没有 pin：路径可能在别的 mount namespace、无权访问，或超出 pin 扫描上限。

## 开发

```sh
make check-bpfmap
make bpfmap
make install-bpfmap
```

构建需要 Rust、C 编译器、libbpf、libelf 与 zlib 的开发文件。`bpfmap` 不加载 eBPF 程序，也不修改现有 map。
