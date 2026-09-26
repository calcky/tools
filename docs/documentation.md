# 文档维护与托管

## 内容来源

本站由 MkDocs 和 Material 主题构建。导航在根目录 `mkdocs.yml`。

- `docs/` 保存概览、安装、任务示例和维护说明。
- 各工具 README 是工具手册的唯一来源，修改参数说明时直接编辑该 README。
- `docs/generate.py` 在构建时将工具 README、已有发布说明和 netlens 参考文档加入虚拟文档目录，保留原有相对链接。
- `site/` 是生成结果，不提交。构建不需要编译 Rust 程序。

目前生成器明确包含 irqtop、netping、flowgen、cttop、netlens，避免将实验目录或工作记录自动公开。新增工具时，同时修改生成器和导航。

## 本地预览

```sh
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r docs/requirements.txt
.venv-docs/bin/mkdocs serve --dev-addr 127.0.0.1:8000
```

浏览器访问 `http://127.0.0.1:8000`。提交前运行：

```sh
.venv-docs/bin/mkdocs build --strict
```

GitHub 的 `Documentation` workflow 执行相同的严格构建，并保留 HTML 产物用于检查。

## 接入 Read the Docs

仓库已提供 `.readthedocs.yaml`：使用 Python 3.12，安装 `docs/requirements.txt`，读取 `mkdocs.yml`，构建警告会使任务失败。

首次托管需要仓库所有者在 [Read the Docs](https://app.readthedocs.org/dashboard/) 中完成导入：

1. 登录并关联有权访问 `calcky/tools` 的 GitHub 账号。
2. 导入 `https://github.com/calcky/tools`，默认分支选择 `master`。
3. 选择可用的项目标识，例如 `calcky-tools`；以平台实际分配结果为准。
4. 确认使用仓库根目录的 `.readthedocs.yaml`，触发首次构建。
5. 检查 GitHub 集成/webhook，确保后续推送触发重建。

平台构建时提供 `READTHEDOCS_CANONICAL_URL`，本站用它生成 canonical URL。本地构建默认使用本地预览地址，不预设尚未注册的公网域名。

## 版本策略

tools 内各工具独立发版，文档站默认跟随 `master` 的 `latest`。某个工具标签对应的是整个仓库在该时间点的快照，并不表示其他工具同时发布同一版本。

Read the Docs 仅能构建包含文档配置的分支或标签。旧标签没有本站配置时不要启用文档构建。需要固定版本文档时，在平台中启用合适的仓库版本，并明确它是仓库快照。
