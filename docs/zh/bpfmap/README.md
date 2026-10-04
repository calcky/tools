# bpfmap

只读查看 BPF map 的类型、容量、键值大小、pin 路径，以及受限条目预览和相邻采样的变化。适合在终端持续观察少量 map 条目；一次性查询、导出或修改 map 时仍可使用 `bpftool`。

## 安装

`bpfmap` 尚未发布官方 GitHub Release 或预编译程序。正式发布后会在此补充已验证的安装命令；开发构建见[项目 README](https://github.com/calcky/tools/blob/master/bpfmap/README.md)。

读取 map 元数据通常需要 `CAP_BPF` 或 `CAP_SYS_ADMIN`；读取条目还取决于 map 权限和类型。以下命令假设当前账号已有足够权限。

## 常用命令

```sh
bpfmap                # 列出当前可访问的 map
bpfmap -m 42          # 直接查看 map ID 42
bpfmap -n 32 -d 2     # 每 2 秒预览最多 32 个条目
```

| 选项 | 作用 |
| --- | --- |
| `-m ID` | 直接进入指定 map。 |
| `-n N` | 每轮最多读取 N 条，默认 64，范围 1-256。 |
| `-d SEC` | 条目刷新间隔，默认 1 秒，范围 0.2-60 秒；列表每 5 秒刷新。 |
| `-h` / `-V` | 帮助 / 版本。 |

`Enter` 打开选中的 map，`Esc` 返回列表；`j/k` 或方向键移动，`r` 立即刷新，`h` 查看帮助，`q` 或 Ctrl+C 退出。需要交互终端；`NO_COLOR=1` 可禁用颜色。

## 如何解读

列表中的 `CAPACITY` 通常是定义的最大条目数；ringbuf 则显示带 `B` 单位的缓冲区字节数。`KEY` 和 `VALUE` 是单个键和值的字节数，不是总内存占用。`PIN PATH` 只覆盖当前可见的 bpffs 路径；未显示不代表 map 没有在其他 mount namespace 中 pin。

详情每行的 `KEY` 标识条目，`VALUE` 是当前读到的值，含义取决于创建 map 的程序。若有可用 BTF，工具会尝试解码；否则显示有界十六进制值。per-CPU 无符号整数值会先跨 CPU 求和，非整数值只显示 CPU0 预览及 CPU 数量。

`DELTA` 是同一键与上一轮观察值之间的**原始差值，不是每秒速率**。BTF 确认的无符号整数显示 `+N`；结构体可显示顶层整数字段变化。`new` 表示上轮未观察到该键，`=` 表示字节未变，`changed` 表示变化但无法量化，`reset/-` 表示数值下降。

## 读取边界

- 只预览普通 hash、array、per-CPU hash/array、LRU hash 和 LPM trie。ringbuf、队列/栈、程序数组及 socket/设备引用类 map 只显示元数据，不执行可能消费数据的操作。
- 预览从首键开始，每轮最多读取 `-n` 条，总读取预算最多 2 MiB；单键/值超过 4096 字节或 per-CPU 条目超过 64 KiB 时不预览。`Entries 64/64+` 中的 `+` 表示还有未预览的键。
- 并发更新中的 hash 遍历不是原子快照，可能漏键、重复键或读到变化中的值。预览数量和差值不能代表整张 map 的总量或速率。
- pin 路径扫描最多访问 2048 个节点；列表和扫描不完整时会在窗口中标记。工具不会创建、更新或删除 map。
