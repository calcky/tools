# 连接与进程

## 找到目标连接

```sh
netlens socket
```

按 `/` 输入筛选条件，Ctrl+U 清空。Enter 打开所选连接详情，Esc 返回。

```text
proc cc-switch
port 15722
tcp and (port 443 or port 8443)
src net 192.168.0.0/24
ip6 and host ::1
```

`proc` 是独立条件，按进程名子串匹配，忽略大小写，不与 IP 表达式混用。
名称来自 `/proc/<pid>/comm`，通常最多 15 字节，不匹配完整命令行。尚未解析的进程不会命中。

IP 条件支持 `host/net/port/portrange`、协议、`src/dst`、`and/or/not` 和括号，不解析 DNS。
`and` 与 `or` 优先级相同，从左向右结合，复杂条件请加括号。
Socket 的 `src/dst` 是本地/远端，不是连接的发起/接受角色。

## 查看本机两端进程

两个本机应用之间的 TCP 连接合并为一行：

```text
LOCAL              REMOTE             PROCESS
127.0.0.1:15722     127.0.0.1:48000     123/cc-switch <-> 456/codex
```

LOCAL 使用稳定的端点排序，不代表客户端或服务端；筛选不会反转方向。
列表的队列、RTT 等属于 LOCAL，不是两个 socket 的总和。详情分别展示两端进程及可用诊断。
仅在同一命名空间观察到唯一反向 socket 时配对，不会凭监听进程猜测连接归属。
UNIX 通过内核 peer-inode 配对；UDP 不凭端口猜测对端进程。

进程名未出现时，先看归属状态：

| 状态 | 含义 |
| --- | --- |
| `resolving` | 等待进程扫描 |
| `unmatched` | 已扫描但没有匹配 FD |
| `restricted` | 有进程不可读 |
| `partial` | 扫描受其他错误或容量限制影响 |
| `denied` / `unavailable` | 扫描本身失败 |

短连接可能在采样或扫描前关闭，缺少名称不代表没有进程。

## 看 TCP 为什么慢

[![netlens 的 TCP 连接双端进程与分组诊断](../../assets/screenshots/netlens-tcp.png)](../../assets/screenshots/netlens-tcp.png)

实际回环连接：两端进程、流量、窗口、拥塞控制和时延分别展示，内核 RTT 不等于应用 RTT。

Enter 进入详情，先看应用流量、RTT、重传，再看拥塞与流量控制。

| 指标 | 怎么读 |
| --- | --- |
| RTT | 内核 TCP RTT 估计，不是应用请求响应时延 |
| MSS | 当前发送段的载荷大小，不是 MTU |
| `snd_cwnd` | 拥塞窗口，通常按段；字节比较需乘 MSS |
| `snd_wnd` | 对端通告的接收窗口，限制本端发送 |
| `rcv_wnd` / `rcv_space` | 本端接收窗口 / 接收自动调优空间估计，二者不同 |
| `app` / `acked-app` | 接收应用字节 / 已确认发送的应用字节 |
| `all-seg` | 全部 TCP 段，包含控制段，不是应用消息数 |
| 重传 | 传输层重发信号，不可直接换算为单向丢包率 |

`LIMIT BASIS` 用 busy-time 的变化计算受限比例，不使用整个采样间隔作分母。
50% 的主导限制阈值，以及 `CWND?`、`APP?` 都是显示启发式，不是瓶颈证明。
`ACTIVE` 仅表示未观察到主导时间限制。监听行显示 pending/backlog，不显示连接 RTT。

## 其他 socket 与队列

在 `/` 中输入独立类型条件，例如 `unix`、`netlink`、`vsock`、`xdp`；`path=/run/` 筛选 UNIX 路径。
还支持 RAW、DCCP、SCTP、MPTCP、PACKET、TIPC，以及相应可用子类型。
覆盖 `ss` 的 socket 家族，不代表所有 `ss` 选项；诊断支持取决于内核。

| 类型 | RECV-Q / SEND-Q 口径 |
| --- | --- |
| TCP | 载荷字节；监听行为待接受连接数 / backlog 上限 |
| UDP、RAW | 已分配队列内存，不是纯载荷 |
| UNIX stream | 接收字节 / 发送分配内存 |
| UNIX datagram | RECV-Q 为下一条 datagram 大小 |
| PACKET、NETLINK | 分配内存 |
| TIPC | 包数 |
| VSOCK、XDP | 占用不可用；ring 容量不是当前占用 |

RAW 显示 IP 协议号而非伪造端口；procfs 回退无稳定 cookie，不承诺缓存归属。
AF_XDP 的队列 ID、UMEM、ring 配置和可用错误字段，不等于 XDP 程序动作计数。
其收发路径见[数据包路径](packet-path.md#xdp)。
