# 构建、检查与发布

## 项目组织

每个 Rust 工具是独立 crate，有自己的 `Cargo.toml`、锁文件、README 和测试。仓库根目录 Makefile 提供统一构建、检查和安装入口。

```text
irqtop/        硬中断、软中断与 softnet
netping/       延迟与路径探测
flowgen/       多会话负载与结果分析
cttop/         conntrack 监控与离线查看
netlens/       网络栈监控
bin/           本机构建产物，不提交
docs/          文档站入口与维护说明
.github/       构建、检查和发布 workflow
```

## 修改与验证

在具体工具目录修改源码，运行对应检查：

```sh
make check-cttop
make cttop
```

测试应覆盖改动涉及的参数、协议、指标语义和显示行为。需要权限或隔离网络环境的测试，遵循工具 README 中的条件。

## 静态编译与发布

各工具的 workflow 在 `.github/workflows/`，负责 musl 静态构建、验证及标签触发发布。通常提供 ARMv7、ARM64 和 x86_64 产物，各工具具体步骤以对应 workflow 为准。

发布前更新该工具版本与发布说明，确认测试通过，再推送与 `Cargo.toml` 一致的标签，例如 `cttop-v0.1.0`。发布任务会在构建验证通过后上传附件。不要重复使用已发布标签。

下载产物无需依赖 glibc；仍须核对 CPU 架构和 ARM 浮点 ABI。普通 `make` 是本机构建，不等同于 workflow 的 musl 静态构建。

## 文档检查

```sh
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r docs/requirements.txt
.venv-docs/bin/mkdocs build --strict
```

完整文档流程见[文档维护与托管](documentation.md)。
