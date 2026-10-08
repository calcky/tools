# bpfmap

只读查看 BPF map 的完整名称、类型、当前计数、容量和条目变化。适合持续观察 map 占用与少量键值；一次性导出或修改仍可使用 `bpftool`。

## 安装

以 x86_64 为例；ARMv7、ARM64 版本与校验和见 [bpfmap-release](https://github.com/calcky/tools/releases/tag/bpfmap-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/bpfmap-release/bpfmap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 bpfmap-linux-x86_64 "$HOME/.local/bin/bpfmap"
```

Linux 6.6 上列表枚举和按 ID 打开 map 都需要 `CAP_SYS_ADMIN`，条目读取还取决于 map 权限。自动计数需要 Linux 6.6+、内核 BTF、map iterator/kfunc 及 BPF 加载权限，通常包括 `CAP_BPF`/`CAP_PERFMON` 或 `CAP_SYS_ADMIN`。计数不可用时保留元数据与预览。以下命令假设当前账号已有足够权限。

## 常用命令

```sh
bpfmap                # 列出当前可访问的 map
bpfmap -m 42          # 直接查看 map ID 42
bpfmap -n 32 -d 2     # 每 2 秒预览最多 32 个条目
```

| 选项 | 作用 |
| --- | --- |
| `-m ID` | 直接进入指定 map。 |
| `-n N` | 每页最多显示 N 条匹配结果，默认 64，范围 1-256。 |
| `-d SEC` | 条目与计数刷新间隔，默认 1 秒，范围 0.2-60 秒；元数据列表每 5 秒刷新。 |
| `-h` / `-V` | 帮助 / 版本。 |

`Enter` 打开 map 或展开条目，`Tab` 切换 Entries/Info，`Esc` 返回上一级；`j/k` 或方向键移动/滚动，PgUp/PgDn 翻页，`r` 刷新并重试采集，`c` 执行后台键计数扫描，`h` 查看帮助，`q` 或 Ctrl+C 退出。需要交互终端；`NO_COLOR=1` 可禁用颜色。

普通键值表：`/` 按显示的 KEY/VALUE 搜索（不区分大小写），`f` 精确查询原始 key（不适用于最长前缀匹配的 LPM Trie），`x` 清除；`[`/`]` 读取上/下一页，PgUp/PgDn 只移动当前页视口。key 输入完整十六进制字节，使用内核内存顺序，例如小端 u32 key 1 为 `01 00 00 00`。扫描数和 partial 表示覆盖范围，未完成不代表没有匹配。

## 详情

KEY/VALUE 显示紧凑值或 `字段=值`，可识别的 IP 直接显示可读地址。已核对的 flow key 显示 `源IP:端口 -> 目的IP:端口 TCP/UDP`；ICMP 显示地址与 Echo id。列宽随内容分配，竖线分隔，长内容最多换成三行，`...` 表示需按 `Enter` 查看完整内容。全零 reserved 只在列表省略；详情保留完整 BTF 和 hex，用空格缩进。`Display`/`IP address` 是可读解释，BTF MEMORY VALUES 保留内存数值，网络序端口的内存数值可能不同。

IPv4 如 `192.168.200.1`，IPv6 如 `fe80::62be:b4ff:fe2d:41bb`，可用 `/` 搜索地址、端口或协议。支持 `in_addr`/`in6_addr`、明确为 `__be32` 的源/目的 IP 字段，以及已核对的 `aiwan_xdp_local_ips`、IPv6 key 和 flow key（address_family 4/6）。普通整数、孤立的 `__be32` 和未知字节数组不猜为 IP；无 BTF 时保留 hex。`f` 仍输入原始 key，例如 `c0 a8 c8 01`。

- **Entries**：限量键值表。再按 `Enter` 查看展开的 BTF 字段、原始十六进制字节和 per-CPU 各 CPU 的值，包括零值。展开跟随原始 key；该键不在当前预览时提示，不展示旧值。CPU 编号不可获取时以 `CopyN` 标记。
- **per-CPU 分布**：BTF 确认的无符号整数展示 VALUE/DELTA/SHARE，最大正增量加粗高亮。SHARE 为正增量占比；首次采样显示 `-`，下降显示 reset。按 `v` 主动启用计数器解释后增加 RATE/s，使用实际采样间隔；不自动推断包数/字节数。原始/BTF 数据仍保留。
- **引用条目**：ProgArray、ArrayOfMaps、HashOfMaps 展示 key、目标 ID、名称及类型/容量。`Enter` 下钻 inner map 或查看程序类型、UID、JIT 大小及最多 64 个引用 map ID；`Esc` 返回，最多下钻 16 层。lookup 返回对象 ID，不是 FD；目标不可读取仍保留 ID，显示 unavailable。
- **Info**：按配置、计数、BTF/pin 和引用程序分区，展示 flags、frozen、memlock、map_extra、CPU 副本数、类型 ID/声明及所有可见 pin 路径。memlock 是内核报告的分配量，不是已用条目字节或进程 RSS；frozen 是用户态写入限制，程序读写看 flags。
- **引用程序**：展示 ID、内核名称、类型与加载 UID；是加载程序的引用关系，不代表当前挂载位置或持有者进程。后台查询最多 1 秒、4096 个程序及每个程序 4096 个 map ID，读取失败或超限标为 partial。打开详情时查询，Info 页每 5 秒或按 `r` 更新。
- **XSKMAP**：默认打开 socket 表，显示 KEY、IFACE、QUEUE、MODE（Copy/Zero-copy）和 STATE（Ready：尚未绑定、Bound、Unbound：绑定已解除）。KEY 是 map 槽位，**不一定等于队列号**；宽屏增加 IFINDEX/NETNS，窄屏在选中区域显示。网卡名称与 netns 来自 socket 绑定的设备。`Enter` 展开，`Tab` 查看 Info；rings 与活动统计见 [xsktop](../xsktop/README.md)。其他不可预览类型默认打开 Info。

## 如何解读

`NAME` 从 BTF `.maps` 中按名称前缀、类型、容量及键值类型恢复唯一完整名称；无 BTF 或匹配有歧义时保留内核名称，不猜测。列表截断的名称可在选中区域与详情完整查看。

`COUNT` 的含义取决于类型，选中区域显示来源；`-` 表示未知，不是空表。`CAPACITY` 是最大条目数，ringbuf 为字节容量。`KEY`/`VALUE` 是单个键值大小，窄屏移到选中区域。`PIN PATH` 只覆盖当前可见的 bpffs 路径。

| Map 类型 | COUNT 含义 |
| --- | --- |
| Hash、Per-CPU Hash、LRU、HashOfMaps | 内核维护的键数。 |
| LPM Trie、DevMapHash、SockHash | 对应内核计数。 |
| Array、Per-CPU Array、StructOps | 固定 `N slots`，不是非零/有效值数；不乘 CPU 副本数。 |
| XSKMAP、程序/事件/cgroup/map 数组、DevMap、CPUMap、SockMap、ReuseportSockarray、StackTrace | 非空引用槽位数。 |
| Queue、Stack | 当前深度，只读 head/tail，不 pop。 |
| Ringbuf、UserRingbuf | 已用/已保留 `N B`，包含记录头和填充，不是消息条数。 |
| Bloom Filter、无可用只读计数方法的 storage 等类型 | `-`；不推测数量。 |

需要相应内核 BTF 字段；缺失或读取失败时显示未知。所有动态计数均不是并发更新下的原子快照。负值或超出容量的异常值显示未知，不强行截断。

条目表的 `KEY` 标识条目，`VALUE` 是当前读到的值，含义取决于创建 map 的程序。若有可用 BTF，工具会尝试解码；否则显示有界十六进制值。per-CPU 无符号整数在表中跨 CPU 求和，其他值预览第一个 possible CPU；展开后可看各 CPU 的值。跨 CPU 读取不是原子快照。

`DELTA` 是同一键与上一轮观察值之间的**原始差值，不是每秒速率**。BTF 确认的无符号整数显示 `+N`；结构体可显示顶层整数字段变化。`new` 表示上轮未观察到该键，`=` 表示字节未变，`changed` 表示变化但无法量化，`reset/-` 表示数值下降。

## 读取边界

- 普通键值预览支持 hash、array、per-CPU hash/array、LRU hash 和 LPM trie；XSKMAP 只读查看绑定，ProgArray/ArrayOfMaps/HashOfMaps 查看引用条目。其余类型仅显示支持的计数，不读取/消费其数据。
- XSKMAP 的普通用户态 lookup 不提供 socket 值，详情使用独立 CO-RE iterator，需要相关 BTF 字段与加载权限。每次最多扫描前 16384 个槽位，返回最多 `-n` 个 socket；more exist 表示还有未展示的引用，partial 表示扫描超限或读取失败。`!` 标记条目字段读取失败，`-` 表示未知/未绑定。不可用时明确报错，`r` 重试；绑定字段不是原子快照。
- 自动引用扫描每个 map 最多 16384 个槽位，每轮共最多 65536 个；`N part` 表示未完成，不是全表总数。`c` 对可遍历类型去重计数，不读 value，预算为 2 秒、约 16 MiB 内存及 100 万次成功键读取，超限也显示未完成。
- 每页最多 `-n` 条匹配结果，每块最多检查 4096 个键、2 MiB、50 ms；单键/值超过 4096 字节或 per-CPU 条目超过 64 KiB 时不预览。空的 partial 搜索块自动继续，最多 65536 个键或 2 秒，之后 `]` 继续。搜索依据显示值，不扫描未展示的深层字段；more exist 与 COUNT 无关。
- 引用详情最多检查 16384 槽位、2 MiB、50 ms，另留 50 ms 解析元数据，返回最多 `-n` 条；`[`/`]` 翻数据页。map-in-map lookup 在 Linux 6.6 上可能等待 RCU，即使小表也可能 partial。超限或元数据不可读取显示 partial；时间预算在调用间检查，单次内核调用不可抢占。不会推断程序挂载位置、进程持有者、lookup miss、更新失败或 LRU 淘汰。
- 并发更新中的 hash 遍历不是原子快照，可能漏键、重复键或读到变化中的值。预览数量和差值不能代表整张 map 的总量或速率。
- pin 扫描最多访问 2048 个节点，元数据列表最多 8192 个 map。采集在后台进行。临时计数 iterator 及内部预算 map 随程序退出释放，不 pin，不挂载到业务网络，不修改现有 map。
