# fdtop

基于 eBPF 的应用 I/O 监控，按 **进程 -> FD** 下钻。分别统计文件、
TCP/UDP/UNIX socket、管道/FIFO、字符设备、块设备文件和 POSIX MQ。
指定进程时提供类似 lsof 的完整 FD 清单，并叠加读写速率、读写 OPS。
单独区分 EVENTFD、TIMERFD、SIGNALFD、EPOLL、BPFMAP、BPFPROG、BTF；
XSK 显示绑定网卡及队列。
这里的吞吐是应用操作的字节数，不是磁盘请求量或网卡线上流量。
原项目名为 iotop，现更名为 fdtop，避免与传统磁盘 iotop 混淆。

## 安装

本次发布使用唯一标签 `fdtop-release`，提供 x86_64 和 ARM64 静态二进制。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/fdtop-release/fdtop-linux-x86_64
install -m 755 fdtop-linux-x86_64 ~/.local/bin/fdtop
```

ARM64 使用 `fdtop-linux-arm64`；确保 `~/.local/bin` 位于 PATH。
需要 Linux 6.6+、BTF、
raw syscall tracepoint、fentry、BPF/tracing 权限。首版面向原生 x86_64 和
ARM64 ABI；32 位兼容及 x32 调用不采集，compat 统计跳过的兼容 ABI
系统调用数（包含非 I/O 调用）。ARM64 尚需实机验证。

## 使用

```sh
fdtop                      # 进程榜单，Enter 查看 FD
fdtop -p 1234              # 全部已打开 FD，包含空闲 FD
fdtop -p 1234 -t xsk       # XSK 网卡/队列及系统调用次数
fdtop -l -p 1234           # 按需采集调用耗时、分位数和最长在途时间
fdtop -p 1234 -f 12        # 只看该进程的 FD 12
fdtop -n nginx -t socket   # 进程名子串 + socket 类型
fdtop -t pipe -d 0.5       # 每 0.5 秒刷新管道 I/O
fdtop -t eventfd           # 只显示 eventfd，另支持 timerfd/signalfd
fdtop -p 1234 -c 5         # 五次文本快照
fdtop -p 1234 -j -c 5      # JSON Lines，包含每个 FD 的区间和累计数据
fdtop -e -p 1234           # FD 打开、复制、关闭事件窗口
fdtop -e -p 1234 -j > fd-events.jsonl  # 持续保存事件及丢失计数
```

`-p` 的 PID 属于运行 fdtop 的 PID 命名空间所能对应的内核 PID；首版应在
宿主机 PID 命名空间运行。重定向自动使用文本输出；`-b` 强制文本。
`-h` 查看帮助，`-v` 查看版本。终端至少 80x18；`NO_COLOR` 禁用颜色。

| 选项 | 含义 |
| --- | --- |
| `-p PID` | 内核侧过滤进程，并列出该进程全部已打开 FD |
| `-f FD` | 指定 FD，需要同时指定 `-p` |
| `-n COMM` | 进程名子串过滤（内核 comm，最长 15 字节） |
| `-t TYPE` | file/socket/tcp/udp/unix/xsk/netlink/pipe/char/block/mq/eventfd/timerfd/signalfd/epoll/bpfmap/bpfprog/btf/other，不区分大小写；socket 包含所有 socket 子类型 |
| `-d SECONDS` | 刷新周期，默认 1 秒，范围 0.1-60 秒 |
| `-l` | 完整延迟采集；默认轻量模式不采集耗时 |
| `-e` | 按需开启 FD 生命周期采集，直接进入事件视图 |
| `-c COUNT` | 输出指定次数文本/JSON 快照后退出 |
| `-b` / `-j` | 文本 / JSON Lines |

`j/k` 或上下键选择，`Enter` 从进程进入 FD，`Esc` 返回；`s` 切换吞吐、
在途数量和操作次数排序；`h` 查看帮助，`q` 或 Ctrl+C 退出。
FD 主表显示访问模式、读写速率、ROPS/s、WOPS/s、错误和在途数量；详情显示累计量、错误、
EAGAIN 和重启调用次数。`-l` 额外提供区间 avg/P95/P99、采集以来的 max
以及最长在途时间。进程榜单仍按本周期 I/O 展示；`-p` 或进入进程 FD 视图后，
每次采样补充 `/proc/PID/fd` 的完整数字 FD 清单，不包含 lsof 的 cwd、txt、mem 行。
`MODE` 为 `r/w/rw/path`，表示打开权限，不代表发生了读写。
`open` 是当前清单中的 FD；`closed` 是本周期有 I/O、采样时已关闭的对象；
`reused` 是 FD 编号已用于其他对象的旧记录；`unconfirmed` 表示读取竞争或
多个对象身份无法唯一匹配；`invalid` 是无法关联有效对象的调用。
关闭对象的区间记录仍参与 I/O 汇总，不把相同 FD 编号的不同代对象混为一行。
清单读取失败或超过 65536 个 FD 时明确提示不完整，不默认为空清单。

`ROPS/s/WOPS/s` 分别为已完成的读/写端点操作尝试数，包含错误和 EAGAIN；
文本的 `AGAIN/s`、`ERR/s` 及窗口详情分别显示这些情况。空闲对象的零值只代表
本采集器支持的调用没有完成，不表示 epoll、BPF、mmap 等活动不存在。
XSK 的字节速率显示 `-`，JSON 的 `read_bytes_s/write_bytes_s` 为 `null`，
OPS 仍是 syscall 次数，不是包数；底层 `read/write` 计数仅为 syscall 原始值。

默认 **light** 模式保留精确计数和在途数量，省去逐调用时间戳、耗时累计、
最大值和直方图更新；不进行事件抽样。**latency** 模式由 `-l` 开启。
模式在启动时确定，标题及 JSON 的 `mode`/`latency` 字段标明当前模式。
轻量模式未采集的延迟显示 `-`，JSON 中为 `null`，不能解释为零耗时。
两种模式都保留相同的有界 map 容量，轻量模式不承诺降低 map 内存占用。

## FD 事件视图

窗口按 `e` 首次开启事件采集并切换视图；之后 `e` 在 I/O 与事件视图间切换，
采集继续进行。默认不开启事件探针。首次开启时若已进入某个进程的 FD 视图，
则只跟踪该 PID；否则跟踪所有进程。作用域固定到退出，标题明确显示 PID 或
all processes；`-p` 不自动追踪子进程。`-f/-n/-t` 同样作用于事件。

| 事件 | 含义 |
| --- | --- |
| `EXISTING` | 指定进程启动采集前清单中的已有 FD；时间是基线观测边界，不是打开时间 |
| `OPEN` | 安装一个 FD，包括 open、socket、accept、pipe/socketpair、匿名 FD、MQ、BPF、SCM_RIGHTS 接收等 |
| `DUP` | 复制或替换 FD；可识别来源时显示 source FD |
| `CLOSE` | FD 移除，原因可为普通关闭、replace、cloexec、table-release |
| `INHERIT` | fork 得到的 FD，归属子进程；全局采集时可见 |
| `UPDATE` | bind/connect 成功或 connect 正在建立；XSK 显示绑定网卡/队列，不表示业务包收发 |

无需发生 read/write：两次采样间就打开并关闭的对象也会产生事件。
`dup2/dup3` 覆盖按旧对象 CLOSE、新对象 DUP 展示；`dup2(fd, fd)` 不生成伪事件。
普通关闭及 close_range 通过内核 FD 移除入口观察；close-on-exec 和最后一次
文件表释放在对应内核路径扫描。后者是文件表关闭，不是 `__fput` 对象最终释放。
失败的打开/复制调用不生成成功事件；本视图不是所有 syscall 尝试的审计日志。

事件为单独的 eBPF ring buffer，容量 4 MiB；窗口和待输出队列各保留最多
8192 条。窗口最新事件在上，文本/JSON 按接收顺序输出；多 CPU 的时间戳可能交错。
`losses` 四项依次是 ring 满、元数据读取失败、map 容量不足、批量扫描截断；
`history_evicted` 是窗口滚动淘汰，`output_dropped` 是未输出队列溢出，
`decode_errors` 是格式错误。计数非零时不能声称记录完整。
`-c` 按周期输出批次；退出先停探针再排空，必要时追加尾部批次。

每个事件携带当时的类型、inode、设备、文件名及独立对象 cookie；
JSON 的 `event_object_id` 属于事件采集器，不与 I/O 的 `object_id` 比较。
事件探针保存文件名（最多 63 字节），不保证已关闭对象的完整路径；
`EXISTING` 可使用清单中的完整路径。普通 socket 事件显示类型和 inode，
当前地址可切回 I/O 详情查看。XSK 的 UPDATE 直接保存绑定网卡名称、索引和队列。

覆盖边界：

- 核心入口为 `fd_install`、`file_close_fd_locked`（旧内核 `pick_file`）、
  `do_dup2`、`do_close_on_exec`、`exit_files/put_files_struct`，另跟踪 fork 和 bind/connect。
  必需入口缺失或不可挂载时明确报错，不静默退化成完整事件视图。
- 跟踪普通数字 FD 表；io_uring fixed-file 注册槽不是普通 FD，不作为 OPEN/CLOSE。
  事件归属执行内核操作的 PID/TID；共享 FD 表的修改不会复制到每个共享进程名下，
  io-wq 等代执行上下文也不自动归因到请求提交者。
- fork/exec/最终释放每次最多扫描 65536 个 FD 槽位，超出会增加 scan loss。
  共享表还有其他引用时退出不会伪造整个表的 CLOSE；最后释放时才记录表关闭。
- `EXISTING` 只为选中进程提供；基线清单与挂载不是原子操作，边界可能存在竞争，
  不能用它还原开始采集前的历史。兼容 ABI 的安装/关闭仍走内核入口，但不解码
  其原生 syscall 编号，因此 DUP 的 source FD 和 UPDATE 不保证可用。

## 采集口径

- EVENTFD/TIMERFD/SIGNALFD 根据内核匿名 inode 类型及创建时名称区分，
  不依赖 FD 关闭后仍能读取 `/proc`；普通同名文件不会误分类。
  eventfd 成功读写通常是 8 字节，timerfd 读取也是 8 字节；这里不把
  返回的计数器值解释为操作次数。signalfd 按实际读取的字节数统计。
  创建、配置和 epoll 等待调用不计为读写 I/O；无法识别的匿名 FD 归 OTHER。

- 覆盖 `read/write`、`pread/pwrite`、`readv/writev`、`preadv/pwritev`（含 v2）、
  `recvfrom/sendto`、`recvmsg/sendmsg`、`recvmmsg/sendmmsg`、
  `mq_timedreceive/mq_timedsend`、`sendfile/splice/tee/copy_file_range/vmsplice`。
  libc 的 recv/send、mq_receive/mq_send 通常使用上述 syscall。
- 只按实际成功返回长度计算，包含短读写。mmsg 按每条消息返回长度求和；
  MQ send 返回 0 时使用发送长度。批量长度读取失败会计入 batch gap，
  该调用的字节数不猜测。MSG_PEEK 的复制字节也计入读取量。
- syscall 耗时包含睡眠、阻塞和调度；不是磁盘服务时间、TCP RTT 或网络
  单向时延。两种模式都显示 pending；`-l` 才显示最长等待及完成调用的延迟分布。
- P95/P99 是区间微秒级 log2 直方图的桶上界，标记 `~`；max 为该 FD
  对象在整个采集期间的最大值。错误和 EAGAIN 调用也参与调用耗时统计。
  内核 restart 返回值单独计数，操作次数按 syscall 尝试计，不是假定的业务请求数。
- `sendfile/splice/tee/copy_file_range` 在读写两端各记一次操作、各记对应字节。
  不把读写两列相加当作有效传输吞吐。OPS/s 均按端点操作计数，
  FD 过滤可能只保留一次传输的其中一端。JSON 的 `calls` 字段对双 FD
  传输只在读端计一次，可用于未过滤端点时的调用汇总。
- 使用进程启动时间和观察到的 open-file 对象 cookie 区分 PID/FD 复用。
  dup FD 分行，详情显示本周期活跃的同对象 FD。重新绑定同一 FD 到同一个
  尚未释放的 open-file 对象沿用统计；重新打开文件产生新对象。
  对象最终释放后，下一次采样结算并回收内核记录。
- FD 元数据在 syscall 入口读取；其他线程同时关闭或替换 FD 存在竞争窗口。
  不把该窗口中的对象身份当作严格审计依据。路径从 `/proc` 读取前后核对 inode
  和设备；已关闭对象保留最近成功查询的路径，无缓存则使用内核文件名与 inode。
- 进程榜单的活跃 FD 元数据最多每秒查询一次；选中进程的完整清单按 `-d`
  周期刷新，开销随该进程 FD 数量增加。XSK 诊断 dump 最多每秒一次。
  TCP/UDP 查询当前本地和对端地址，
  UNIX 显示本地及对端路径或抽象名称，未命名端显示 `unnamed`。
  XSK 查询绑定网口索引与队列，网口名无法解析时显示 `ifindex`；
  使用 `NETLINK_SOCK_DIAG`，需要内核 `CONFIG_XDP_SOCKETS_DIAG`，
  以及 socket 所在命名空间的 `CAP_NET_ADMIN` 以核对命名空间；
  仅解析与采集器处于同一网络命名空间的 XSK，跨命名空间明确提示。
  NETLINK 显示协议编号、port ID（`pid` 字段）与组掩码。
  socket 查询通过 `pidfd_getfd` 短暂复制 FD，核对 inode/设备后查询并关闭副本，
  不读写业务数据、不修改 socket 选项；副本存续期间会短暂延长对象生命周期。
  需要允许 ptrace 访问目标进程，通常需要相应命名空间的 `CAP_SYS_PTRACE`；
  seccomp/Yama 等可能限制查询，BPF 采集权限不代表一定能查询 socket。
- `[live]` 表示本次成功查询，`[cached]` 表示沿用上次成功结果，
  `[observed]` 表示只有内核观测信息；`[proc]` 表示仅取得 proc 对象名称，
  socket 地址查询失败。详情显示查询年龄及失败原因；JSON 提供
  `inode`、内核编码的 `device`、`metadata_source`、`metadata_age_ms`、
  `metadata_error`。年龄只针对成功查询，未查询成功为 `null`。
  PIPE/匿名 FD 的内核稳定标签属于 `observed`，清单查询成功则为 `live`。
  无 I/O 的清单对象 `object_id=0`，不是 eBPF 对象 cookie，也不用于判断 dup 关系。
  JSON 另有 `access/state/read_ops_s/write_ops_s`，`inventory_error` 报告清单问题。
  未连接 UDP 不逐包记录 sendto 的目标；UNIX 未命名 socket 没有路径可显示。
  各类伪文件系统目前归 FILE，并不意味着落盘。
- 内核累计计数使用原子更新；多字段快照不完全同时，极短周期可有边界偏差。
  表容量为 16384 个 FD 对象、16384 个在途线程、65536 个对象 cookie。
  `gaps` 按容量/元数据读取/批量读取分别报告，非零表示采集不完整。
  采集器自身排除；默认系统级采集开销与全机 syscall 频率有关，优先用 `-p` 聚焦。
  `-n/-t` 是显示过滤；增大 `-d` 只减少用户态快照/刷新频率，不减少每次
  syscall 的探针执行。高频小块 I/O 下仍可能明显扰动吞吐，适合按需诊断。
- 不覆盖 io_uring、Linux AIO、mmap 页访问、System V MQ、ioctl、fsync，
  也不测底层块请求或 XSK mmap ring 流量。完整清单可包含这些对象，但
  不因此扩大 I/O 采集范围。已在探针挂载前开始的调用不追溯。

## 开发验证

仓库根目录运行 `make fdtop`、`make check-fdtop`、
`make install-fdtop PREFIX="$HOME/.local"`。
编译依赖与 cputop 一致：Rust、Clang BPF、libbpf/libelf/zlib/zstd。

具备权限的测试机上运行 `python3 fdtop/tests/integration.py bin/fdtop`，
测试仅使用临时文件、POSIX MQ 和 loopback/socketpair，验证已知字节数、
FD 复用、dup、阻塞、EAGAIN 与双 FD 传输；两种模式都会验证，轻量模式
还检查未采集延迟为 null。fixture 需要 C 编译器。

`python3 fdtop/tests/metadata.py bin/fdtop` 验证两种模式的 UDP 重连地址、
UNIX 抽象名称、NETLINK、未绑定 XSK 和元数据缓存状态；需要 BPF、XDP
socket diagnostic 及目标 socket 查询权限；缺失诊断模块时验证明确的回退提示。
`python3 fdtop/tests/inventory.py bin/fdtop` 验证空闲 FD 完整性、访问模式、
监听 socket、匿名对象和过滤。已在 speed-cpe2 对 aiwan-cpe 对照 lsof：
129 个 open FD 一致，6 个 XSK 的 eth0/eth1/eth2 q0/q1 与 ss 一致。

`python3 fdtop/tests/events.py bin/fdtop` 验证不读写的短命对象、各类 FD、
SCM_RIGHTS、dup 覆盖、close_range、CLOEXEC、退出关闭、fork 继承及事件窗口。

采集开销测试（同样需要 BPF 权限和 C 编译器，建议在空闲测试机运行）：

```sh
python3 fdtop/tests/benchmark.py "$(command -v fdtop)" fdtop/target/overhead
python3 fdtop/tests/soak.py "$(command -v fdtop)" fdtop/target/overhead
```

第一条交错执行三轮不开采集、轻量全局/PID、完整延迟全局/PID 采集，
每次负载持续 3 秒；`global/pid` 为轻量模式，`latency-` 为完整模式。
负载固定在允许使用的前两个 CPU（只有一个可用时使用一个）。可在命令末尾
附加旧版可执行文件路径，同轮交错比较旧版全局/PID 模式；环境与 CPU 编号
保存在 `environment.json`，报告中的 `old-` 表示旧版。
覆盖 4KiB 缓存文件读写、管道、TCP，以及 1472B UDP。生成 `report.md`、
`results.json` 和原始采样。第二条测试 TCP 连续负载 30 秒及结束后空闲
10 秒，生成 `soak.json`。只使用临时文件及 loopback，不修改系统参数。
UDP 按实际接收字节计算吞吐，发送量与接收量均保存，不能把发送速率当成
无损吞吐。CPU 同时记录工作负载和采集器；eBPF 开销通常记在工作负载上，
不能仅凭采集器 CPU 判断开销。RSS 仅包含用户态，不包含内核 BPF map。
这是一组高 syscall 频率的短时压力测试，不代表日常业务或长期稳定性。
