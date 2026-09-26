# 安装与构建

## 下载静态程序

在 [GitHub Releases](https://github.com/calcky/tools/releases) 选择对应工具及 CPU 架构。附件为 Linux 可执行文件，不需要 Rust 运行环境。

| 架构 | 常见附件后缀 |
| --- | --- |
| x86-64 / AMD64 | `linux-x86_64` |
| AArch64 / ARM64 | `linux-arm64` |
| ARMv7，硬浮点 ABI | `linux-arm`，netlens 为 `linux-armv7` |

以 netping 为例，下载后执行：

```sh
chmod +x netping-linux-x86_64
./netping-linux-x86_64 -h
```

需要放入 PATH 时：

```sh
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
```

确保 `$HOME/.local/bin` 已加入 PATH。各版本附件名称和适用架构以对应发布说明为准。

## 从源码构建

需要 Linux、Rust 及本机 C 编译工具链。irqtop、netping、flowgen、cttop 声明最低 Rust 1.88，netlens 声明最低 Rust 1.82；建议使用当前 stable 或对应 CI 固定版本构建整个仓库。

```sh
git clone https://github.com/calcky/tools.git
cd tools
make
```

生成的程序：

```text
bin/
  irqtop
  irqstat -> irqtop
  netping
  flowgen
  cttop
  netlens
```

只构建一个工具：

```sh
make cttop
./bin/cttop -h
make netping
./bin/netping -h
```

## 安装

先构建，再选择用户目录或系统目录：

```sh
make install PREFIX="$HOME/.local"
# 或安装到 /usr/local/bin
sudo make install
```

单独安装一个工具使用 `make install-cttop` 等目标。打包时可以指定 `DESTDIR`：

```sh
make install-cttop DESTDIR=/tmp/tools-package
```

## 检查

```sh
make check-cttop
make check-netping
make check
```

检查入口包含格式检查、测试和 Clippy。涉及真实网络、网络命名空间或流量注入的额外测试，其运行条件在各工具手册中列出。
