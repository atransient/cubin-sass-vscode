# Cubin SASS Preview

在 VS Code 中查看、编辑和汇编 NVIDIA **sm_90** SASS。打开 `.cubin`，同时查看指令、
16 字节编码和调度控制字段，也可以直接编辑 Linux CUDA 可执行文件、共享库和目标文件中的设备代码。

[English](README.md) · 简体中文

## 功能

- 按 kernel 浏览 SASS，支持语法高亮、折叠、过滤和指令位布局。
- 编辑指令、寄存器、modifier、控制字段和原始字节，支持撤销与重做。
- 以 `.nvsass` 源码编辑标号、指令和控制码，再汇编回 cubin；源码与预览支持滚动联动。
- 对比 cubin，导出和重放 JSON patch。
- 直接编辑 Linux CUDA 可执行文件、`.so`、`.o` 中未压缩的 sm_90 cubin。

## 环境要求与支持范围

- 扩展运行所在主机需要 **VS Code 1.75+**、**Python 3.10+**，以及在 `PATH` 中的 CUDA Toolkit **`nvdisasm`**。
  缺少 `nvdisasm` 时，预览退化为字节和控制字段显示。
- 已验证平台为 **Linux**。使用 Remote-SSH 时，Python 和 CUDA 工具需要装在远程主机。
- 预览、反汇编、编辑和汇编验证**无需 GPU**。
- 编辑与汇编目前仅支持 **sm_90**。宿主文件中的内嵌 cubin 必须等长回写，暂不支持压缩的设备 image。

汇编以现有 cubin 为基底。未支持的指令形式可能被拒绝；验证通过不代表修改后的程序计算正确。
详细边界见[编辑模式与限制](docs/usage.zh-CN.md#支持的文件与编辑模式)。

## 安装

使用 Node.js 20+ 和 npm 从源码构建 VSIX：

```bash
git clone https://github.com/atransient/cubin-sass-vscode.git
cd cubin-sass-vscode
npm ci
npm run package
code --install-extension ./cubin-sass.vsix
```

也可以在 VS Code 中通过 **扩展 → 从 VSIX 安装…** 安装构建好的文件。
Remote-SSH 用户需安装到远程主机。
VSIX 包含 Python 后端、指令数据和模板库，插件会自动定位；Node.js 和 npm 仅用于构建与开发。

## 快速开始

1. 在 VS Code 中打开一个 `.cubin`。本仓库提供小型示例：
   [`corpus/cubins/fma.sm_90.cubin`](corpus/cubins/fma.sm_90.cubin)。
2. 点击 SASS 文本、控制字段或指令字节进行编辑。**Ctrl+Z** 撤销，在 cubin 标签页按 **Ctrl+S** 保存。
3. 命令面板运行 **Cubin: 以 SASS 源码打开**，进入 `.nvsass` 文本编辑模式。
4. 保存源码，将汇编结果写入已打开的 cubin 缓冲区；再保存 cubin 标签页，写入磁盘。

打开 Linux CUDA 可执行文件、`.so` 或 `.o` 时，运行 **Cubin: 打开可执行文件中的 sm_90 SASS**，
或选择 **打开方式 → SASS preview (CUDA Host ELF)**。编辑后保存宿主文件标签页。

## 文档

| 文档 | 内容 |
| --- | --- |
| [使用手册](docs/usage.zh-CN.md) | 编辑模式、增删指令限制、源码汇编、JSON patch |
| [配置与故障排查](docs/usage.zh-CN.md#配置) | Python 与 CUDA 路径、后台任务、保存冲突 |
| [命令行](docs/usage.zh-CN.md#命令行) | 脱离 VS Code 使用 Python 后端 |
| [架构说明](docs/architecture.md) | 插件与后端结构、运行数据、迁移背景 |

## 参与贡献与反馈

欢迎通过 [GitHub Issues](https://github.com/atransient/cubin-sass-vscode/issues) 报告问题或提出建议。
开发环境、测试和打包流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，版本变化见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

[MIT](LICENSE)，署名信息见 [NOTICE](NOTICE)。CUDA 工具与驱动库需另行安装。
