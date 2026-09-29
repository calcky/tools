# 安装与使用

## 下载静态程序

在[概览](index.md)选择工具，打开对应下载页面，再选择 CPU 架构。

| CPU 架构 | 附件后缀 |
| --- | --- |
| x86-64 / AMD64 | `linux-x86_64` |
| AArch64 / ARM64 | `linux-arm64` |
| ARMv7，硬浮点 ABI | `linux-arm`，netlens 为 `linux-armv7` |

例如安装 x86_64 版本的 netping：

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netping-release/netping-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
netping -h
```

确保 `$HOME/.local/bin` 在 `PATH` 中。附件为静态 Linux 程序，无需 Rust 运行环境或目标系统的动态 musl/glibc。
ARMv7 版本不能用于 ARMv5/ARMv6 或软浮点系统。

## 使用 irqstat

irqstat 和 irqtop 使用同一个程序，以命令名称选择输出方式。下载 irqtop 后建立链接：

```sh
install -m 755 irqtop-linux-x86_64 "$HOME/.local/bin/irqtop"
ln -sfn irqtop "$HOME/.local/bin/irqstat"
irqstat -n 1 5
```

## 从源码安装

需要 Rust 和 C 编译工具链；建议使用当前 Rust stable。

```sh
git clone https://github.com/calcky/tools.git
cd tools
make netping
make install-netping PREFIX="$HOME/.local"
```

将 `netping` 替换成 `irqtop`、`flowgen`、`cttop` 或 `netlens`，即可安装对应工具。
需要系统级安装时执行 `sudo make install-netping`，默认目录为 `/usr/local/bin`。

## 权限

普通 UDP/TCP 测试无需 root。ICMP 和内核跟踪可能需要额外权限，conntrack 实时监控需要目标网络命名空间中的 `CAP_NET_ADMIN`。
容器内运行通常只能看到该容器的网络命名空间。具体要求见各工具页面。
