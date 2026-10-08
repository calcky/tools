# bpfmap

只读的 BPF map 终端查看器。列表显示完整名称、类型、当前计数和容量；进入 map 后限量预览键值，并观察相邻采样的变化。不修改业务 map，也不消费队列或 ringbuf 数据。

## 用法

Linux 6.6 上列表枚举和按 ID 打开 map 都需要 `CAP_SYS_ADMIN`，条目读取还取决于 map 权限。自动计数使用临时只读 BPF iterator，需要 Linux 6.6+、内核 BTF、相关 BPF 功能及加载权限（通常包括 `CAP_BPF`/`CAP_PERFMON`，或 `CAP_SYS_ADMIN`）。不可用时保留元数据与预览，未知计数显示 `-`。

```sh
bpfmap
bpfmap -m 42
bpfmap -n 32 -d 2
```

| 选项 | 作用 |
| --- | --- |
| `-m ID` | 直接进入指定 map |
| `-n N` | 每页最多显示 N 条匹配结果，默认 64，范围 1-256 |
| `-d SEC` | 条目与计数刷新间隔，默认 1 秒，范围 0.2-60 秒 |
| `-h` / `-V` | 帮助 / 版本 |

`Enter` 打开 map 或展开选中条目，`Tab` 切换 Entries/Info，`Esc` 返回条目表或 map 列表；`j/k` 或方向键移动/滚动，PgUp/PgDn 翻页，`r` 刷新并重试计数采集，`c` 对可遍历类型执行后台键计数扫描，`h` 查看帮助，`q` 或 Ctrl+C 退出。元数据每 5 秒刷新。设置 `NO_COLOR=1` 可禁用颜色。需要交互终端。

普通键值表中，`/` 搜索显示的 KEY/VALUE（不区分大小写），`f` 按原始 key 精确 lookup（不适用于最长前缀匹配的 LPM Trie），`x` 清除查询；`[`/`]` 读取上一页/下一页数据，PgUp/PgDn 只移动当前页视口。精确 key 输入完整十六进制字节，按内核内存顺序：例如小端机器的 u32 key 1 输入 `01 00 00 00`，不是 `00000001`。搜索检查当前页之外的条目；显示扫描数、partial 和 more，未完成不代表没有匹配项。切换查询后丢弃旧查询结果。

## 详情

- Entries 保留限量键值表；再按 `Enter` 展开 BTF 字段与十六进制原始字节。per-CPU map 展示各 CPU 的值，包括零值；无法读取 possible CPU 编号时以 `CopyN` 标记，不猜 CPU ID。展开跟随原始 key，当前预览找不到该键时明确提示，不保留旧值。
- KEY/VALUE 使用紧凑值与 `字段=值`，识别的 IP 直接显示为 `192.168.200.1` 或 `fe80::62be:b4ff:fe2d:41bb`。已核对的 flow key 显示 `源IP:端口 -> 目的IP:端口 TCP/UDP`；ICMP 显示两端地址与 Echo id，不把 id 当端口。列宽按内容分配，竖线分隔，长内容最多换成三行，更多内容以 `...` 提示，可按 `Enter` 查看完整 BTF 和原始字节。仅在列表省略全零的 reserved 字段，详情完整保留。BTF 详情用空格缩进，不输出会移动终端光标的制表符。
- 支持 BTF 的 `in_addr`/`in6_addr`、明确为 `__be32` 的源/目的 IP 字段，以及已核对网络字节序的 `aiwan_xdp_local_ips`、IPv6 key 和 flow key（按 address_family 4/6 解码）。普通整数、只有 `__be32` 的标量及语义不明的字节数组不猜为地址；无 BTF 时保留 hex。详情 `Display`/`IP address` 是可读解释，BTF MEMORY VALUES 保留内存数值，网络序端口的内存数值可能与 Display 不同。`/` 可搜索地址、端口或协议；`f` 仍输入原始 key，例如 `c0 a8 c8 01`。
- BTF 确认的 per-CPU 无符号整数增加 VALUE/DELTA/SHARE 分布；SHARE 是各 CPU 正增量占比，最大正增量加粗高亮。首次采样无增量，数值下降显示 reset，不推测回绕。`v` 主动启用计数器解释后增加 RATE/s，除以实际相邻采样时间；普通整数不自动当包数或字节数。零值和原始/BTF 数据仍保留，跨 CPU 读取非原子。
- ProgArray、ArrayOfMaps、HashOfMaps 默认显示引用条目：key、目标 ID、名称及类型/容量等说明。lookup 返回对象 ID，不是创建者传入的 FD。`Enter` 进入 inner map 或查看程序类型、UID、JIT 大小及最多 64 个引用 map ID；`Esc` 返回原 map，最多下钻 16 层。元数据读取失败仍保留 ID 并显示 unavailable，不断言悬空引用，也不推断程序挂载位置或进程所有者。
- Info 分为配置、计数、BTF/pin 和引用程序：显示原始 flags 与名称、冻结状态、内核报告的 memlock、map_extra、CPU 副本数、BTF 类型 ID/声明和全部可见 pin 路径。memlock 不是已用条目的字节数或进程 RSS；frozen 只表示用户态更新/删除限制，程序访问限制以 flags 为准。
- 引用程序显示 ID、内核名称、类型与加载 UID；来自加载程序的 map ID 列表，不代表当前挂载位置或持有者进程。查询在后台进行，最多 1 秒、4096 个程序及每个程序 4096 个 map ID；权限失败、消失或超限显示 partial。打开详情时查询，在 Info 页每 5 秒或按 `r` 更新。
- XSKMAP 默认打开 socket 表：`KEY` 是 map 槽位，`IFACE`/`QUEUE` 是该 socket 的真实绑定，`MODE` 为 Copy/Zero-copy，`STATE` 为 Ready（尚未绑定）、Bound 或 Unbound（绑定已解除）。**Key 不一定等于 Queue**。宽屏增加 IFINDEX/NETNS，窄屏放在选中区域；网卡名称与 netns 来自 socket 的设备，避免跨命名空间误配名称。`Enter` 展开，`Tab` 查看 Info；rings 与活动统计可用 `xsktop` 查看。
- XSKMAP 通过独立、只读的 CO-RE iterator 在后台读取，普通用户态 lookup 仍不提供 socket 值。每次最多扫描前 16384 个槽位，返回最多 `-n` 个非空引用；more exist 表示还有未展示的 socket，partial 表示扫描超限或读取失败。`!` 表示该条目部分字段读取失败，`-` 表示未知/未绑定，不猜队列 0。无采集权限或所需 BTF 时显示错误，`r` 重试；这些绑定不是并发更新下的原子快照。Queue、Ringbuf 等其他不可预览类型仍默认打开 Info。

## 解读

- `NAME` 优先从 BTF `.maps` 中匹配名称前缀、类型、容量与键值类型，恢复唯一完整名称。匹配有歧义或无 BTF 时保留内核名称，不猜测；内核名称通常最多 15 字节。窄屏列表可能截断，选中区域和详情显示完整名称。
- `COUNT` 根据类型表示键数、固定槽位数、已占用引用槽位或缓冲区已用字节。选中区域显示来源。`CAPACITY` 是最大条目数，ringbuf 则是字节容量。`KEY`/`VALUE` 是单个键值大小，窄屏移到选中区域。
- Hash（含 per-CPU、LRU、HashOfMaps）读取内核计数器；LPM Trie、DevMapHash、SockHash 读取对应计数；Queue/Stack 只读 head/tail 计算深度，不执行 pop。
- Array/Per-CPU Array/StructOps 显示固定 `N slots`，不是非零或有效值数量。XSKMAP、程序/性能事件/cgroup/map 数组、DevMap、CPUMap、SockMap、ReuseportSockarray、StackTrace 统计非空引用槽位，无法读取时显示 `-`。
- Ringbuf/UserRingbuf 显示 `N B` 已用/已保留字节，包含记录头和填充，不是消息条数。Bloom Filter 无法恢复准确不同元素数；没有支持的只读计数方法的 storage 等类型显示 `-`。
- 自动引用扫描每个 map 最多 16384 个槽位，每轮共最多 65536 个；`N part` 是已观察数量，不能当作整张 map 总数。`c` 键扫描去重，不读 value，最多 2 秒、约 16 MiB 内存及 100 万次成功键读取；到达预算同样标为未完成。扫描不会阻塞界面。
- 内核计数和槽位/键扫描都不是并发更新下的原子快照；异常负值或超出容量显示未知，不强行截断到合法范围。稳定 map 的完整计数可核对；动态 map 的结果是观测值。
- 普通键值预览限于 hash、array、per-CPU hash/array、LRU hash 和 LPM trie；XSKMAP 只读查看 socket 绑定，ProgArray/ArrayOfMaps/HashOfMaps 查看引用条目。其余类型显示支持的计数，不读取/消费其数据。
- 有 map BTF 时用 libbpf 解码键值；无法加载 BTF 或解码失败时显示有界的十六进制预览。单个键或值超过 4096 字节、per-CPU 条目超过 64 KiB 时不预览。后台每个读取块最多检查 4096 个键、2 MiB、50 ms（单次内核调用不可抢占）；引用详情最多检查 16384 槽位、2 MiB、50 ms，另留 50 ms 解析目标元数据，返回最多 `-n` 条。引用表也用 `[`/`]` 翻数据页；Linux 6.6 的 map-in-map lookup 可能等待 RCU，读少量槽位也可能 partial。
- `DELTA` 中 `+N` 仅用于 BTF 证实的无符号整数值；结构体可显示顶层整数字段的差值，per-CPU 整数值先按 CPU 求和。`=` 表示字节未变，`changed` 表示无法细分的内容变化，`reset/-` 表示数值下降，`new` 表示该键上轮未观察到。它是两轮原始差值，不是每秒速率。不可预览的 map 不显示空的键值表。
- `Preview` 是当前页的匹配数量，与 `COUNT` 无关。搜索遇到空的未完成块时自动继续，最多检查 65536 个键或 2 秒，之后按 `]` 继续。搜索依据显示值，不搜索未显示的原始/BTF 深层字段。实时遍历可能漏键或再次遇到已读键；每块去重，不把分页当全表快照。不推断 lookup miss、更新失败、LRU 淘汰或精确创建/删除率。
- 未找到 pin 路径不代表没有 pin：路径可能在别的 mount namespace、无权访问，或超出 pin 扫描上限。

## 开发

```sh
make check-bpfmap
make bpfmap
make install-bpfmap
```

构建需要 Rust、C 编译器、支持 BPF/CO-RE 的 Clang、libbpf、libelf、zlib/zstd 开发文件。跨架构构建可用 `BPFMAP_BPF_OBJECT` 指定预编译的 `count.bpf.o`。计数 iterator 及其内部预算 map 仅在进程存续期间存在，不 pin，不挂载到业务网络或修改现有 map。
