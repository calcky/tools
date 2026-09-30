# xsktop

实时查看当前网络命名空间中的 AF_XDP socket，按网口和队列显示 RX/TX 速率、错误和所属进程。

## 下载

从 [xsktop-release](https://github.com/calcky/tools/releases/tag/xsktop-release) 下载 ARMv7、ARM64 或 x86_64 的静态程序。例如：

```sh
curl -fLO https://github.com/calcky/tools/releases/download/xsktop-release/xsktop-linux-x86_64
chmod +x xsktop-linux-x86_64
sudo ./xsktop-linux-x86_64
```

## 常用命令

```sh
sudo xsktop                   # 实时窗口
sudo xsktop -i eth0           # 仅看指定网口
sudo xsktop -d 0.5            # 每 0.5 秒刷新
sudo xsktop -c 5 -d 1 > log   # 采样 5 次，输出纯文本
```

窗口中用方向键或 `j/k` 选择 socket，`s` 切换排序，`q` 退出。

## 关键选项

| 选项 | 含义 |
| --- | --- |
| `-i IFACE` | 限定网口 |
| `-d SEC` | 采样间隔，最小 0.1 秒 |
| `-c N` | 输出 N 次文本采样，不需要终端 |

## 注意事项

- 需要 Linux 6.6+、`CONFIG_XDP_SOCKETS_DIAG`、内核 BTF 和 fentry/fexit BPF 支持；通常需要 root 或相应能力。
- RX 表示进入 XSK，TX 表示内核取走描述符，不等于应用已消费或报文已上网线。ring 显示的是容量，不是实时占用。
- `UMEM fill empty`、`TX empty` 是事件，不计入 RX/TX 错误。共用 UMEM 的 socket 可能共享 fill-ring 事件。同一网口/队列有多个 XSK 时，速率显示为 `-`；其中一个关闭后的首个采样区间仍可能包含其流量。
- 已验证 veth 上的 generic/copy 与 native/copy；真实网卡 zero-copy 和多缓冲报文尚未验证。

[完整手册](https://github.com/calcky/tools/blob/master/xsktop/README.md)
