# netcap

[ByteDance netcap](https://github.com/bytedance/netcap) 可在指定内核函数或
tracepoint 处抓取 skb 报文。此目录提供 1.0.1 版的三架构静态构建。

## 安装

以 x86_64 为例；其他架构见 [netcap-release](https://github.com/calcky/tools/releases/tag/netcap-release)。

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netcap-release/netcap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netcap-linux-x86_64 "$HOME/.local/bin/netcap"
```

```sh
netcap skb -f icmp_rcv@1 -e 'icmp' -i eth0 -w icmp.pcap -c 10
```

`skb` 模式需要跟踪权限、debugfs 和与运行内核匹配的已准备头文件。自定义内核可设置
`BCC_KERNEL_SOURCE`。静态程序内含 BCC/LLVM，无需目标机安装 Clang 或动态库；
但不使用 `-w` 的文本输出仍会调用外部 `bash` 和 `tcpdump`。
`raw`/`mbuf` 模式需要匹配的 AF_XDP/DPDK 进程，本次未做运行验证。
x86_64 已实测抓包；ARM64、ARMv7 只验证了构建和启动。

完整命令见[中文文档](../docs/zh/netcap/README.md)或
[English docs](../docs/en/netcap/README.md)。

## 从源码构建

上游源码固定在 `027dd2a763ebc893474f398b1eb28aab156e51c7`，
使用 Alpine/musl、BCC 0.34 和 LLVM 18，并对旧版 gobpf 接口做最小兼容修补。
需要 Docker；ARM 构建还需要跨架构 `binfmt_misc` 支持。

```sh
bash netcap/build-static.sh x86_64
bash netcap/build-static.sh arm64
bash netcap/build-static.sh arm
```

产物和校验和位于 `netcap/dist/`。可设置 `NETCAP_JOBS` 限制并行编译数。
