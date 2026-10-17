# Cubin SASS Preview

独立的 VS Code 插件，用于查看、编辑和汇编 NVIDIA **sm_90** cubin，也支持直接编辑
Linux CUDA 可执行文件、`.so`、`.o` 中内嵌的 sm_90 设备代码。
由 `nv_isa` 中的插件模块及其必要后端迁移而来，插件、Python 实现、指令数据和小型模板库均在本项目内，无需原仓库。

## 功能

- 打开 `.cubin`，查看 SASS、16 字节编码、控制字段和指令位布局。
- 修改指令、寄存器、modifier、控制码和原始字节；支持撤销、重做与保存。
- 对比两个 cubin，导出和应用 JSON patch。
- 将 cubin 打开为 `.nvsass` 文本，编辑后汇编回缓冲区；支持标号及源码/预览滚动联动。
- 查看 Linux 可执行文件、`.so`、`.o` 中未压缩的 sm_90 cubin，并进行等长回写。

编辑与汇编目前仅支持 **sm_90**。未标定形式可能被拒绝；反汇编回环与驱动加载通过并不代表程序计算正确。

## 支持范围与指令数量限制

独立 cubin 和宿主 ELF 都支持修改、插入、删除指令，但两种编辑模式的空间限制不同：

| 输入文件 | 编辑模式 | 增删指令的限制 |
| --- | --- | --- |
| 独立 `.cubin` | 预览中的 `+` / `−` | section 大小不变。插入消耗目标函数尾部的 NOP 空位；删除移动后续指令，末尾补 NOP。 |
| 独立 `.cubin` | `.nvsass` 源码 | 支持已有代码 section 扩容、缩容，不受尾部 NOP 数量限制；需要通过布局和重定位验证。 |
| Linux CUDA 可执行文件、`.so`、`.o` | 预览中的 `+` / `−` | 在选中的内嵌 cubin 中进行同样的定长增删。 |
| Linux CUDA 可执行文件、`.so`、`.o` | `.nvsass` 源码 | 内嵌 cubin 的总字节数必须保持不变；导致总长度变化的修改会被拒绝。 |

例如，目标函数尾部有 2 条可用 NOP，预览模式就有 2 个插入空位；独立 cubin 需要
继续增加指令时，可切换到源码模式。两种模式都要验证指令形式与分支重定位，有空位
也可能因其他验证失败而拒绝编辑。目前不支持新增或删除整个代码 section。

宿主文件的编辑对象是 `.nv_fatbin` 中**未压缩的 sm_90 设备代码**，宿主 ELF 布局保持不变，
无需重新链接宿主程序；压缩 image 暂不支持，包含多个 sm_90 image 时需要选择其中一个。

这里的“汇编 cubin”是以现有 cubin 为基底，把修改后的 `.nvsass` 汇编回去。
CUDA C++ / PTX 到 cubin 的编译由 `nvcc`、`ptxas` 等工具另行完成。

## 环境与安装

运行需要 VS Code 1.75+、Python 3.10+；Python 后端只使用标准库。
完整 SASS 功能需要 CUDA Toolkit 的 `nvdisasm` 在扩展宿主的 `PATH` 中。
已验证平台为 Linux，支持 Remote-SSH；远程连接时 Python 和 CUDA 工具需装在远程主机。
预览和汇编无需 GPU。可选的驱动加载检查仅加载模块，不执行修改后的 kernel。

构建 VSIX 需要 Node.js 20+ 和 npm：

```bash
npm ci
npm run package
code --install-extension ./cubin-sass.vsix
```

Remote-SSH 用户也可以在远程扩展界面使用“从 VSIX 安装”。插件自动定位随包提供的 Python 后端，不要求打开原仓库。
开发时直接在本项目根目录打开 VS Code 并按 F5。

## 使用

打开 `corpus/cubins/fma.sm_90.cubin` 即可预览。点击指令、字段或字节进行编辑，Ctrl+Z 撤销，Ctrl+S 保存。
命令面板运行 `Cubin: 以 SASS 源码打开` 可进入文本模式。
源码栏 Ctrl+S 将汇编结果写入 cubin 缓冲区，再保存 cubin 标签页才会写入磁盘。

宿主 ELF 使用命令 `Cubin: 打开可执行文件中的 sm_90 SASS`，或通过“打开方式”选择 `SASS preview (CUDA Host ELF)`。
从宿主预览打开源码时，源码保存先更新同一个宿主文件缓冲区，再保存宿主标签页才落盘。
如果源码对应的基底文件未在自定义编辑器中打开，保存源码会在验证通过后直接写回基底。
虚拟源码汇编失败时保留未保存状态，基底保持不变。

二进制保存会在校验后再次检查磁盘基底；发现外部修改或删除时拒绝覆盖，编辑内容保留。
“另存为”也会检查校验期间目标文件是否变化。窗口恢复时即使原文件已丢失，仍能打开
有效备份；重新创建文件前会完整校验其中的指令。

后台任务默认最多并行 2 个、额外排队 32 个，每个任务总超时为 120 秒（含排队）。
可通过 `cubinSass.backendConcurrency`（1–8）和 `cubinSass.backendTimeout`（1–3600 秒）调整。
命令面板运行 `Cubin: 取消后台任务` 可取消当前窗口中的后台工作；过期预览及已关闭文档
的任务自动取消。Linux 上会同时终止 Python 及其启动的工具子进程；后台验证取消或超时时
保留编辑内容，不提交保存。

```bash
python3 scripts/cubin_sass.py corpus/cubins/fma.sm_90.cubin
```

命令行输出为 JSON。详细功能、限制及 patch 示例见 [使用手册](docs/usage.zh-CN.md)。

## 开发与测试

```bash
npm ci
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
npm test
python3 -m ruff check .
python3 -m pytest
npm run package
```

完整 Python 测试需要 `nvdisasm`，涉及编译 CUDA 源码的测试还需要 `nvcc`；默认跳过较慢的全语料测试。
使用 `NVISA_SLOW=1 python3 -m pytest` 可开启这些测试。
CI 保留不依赖 CUDA 的快速检查和 VSIX 打包，同时增加 CUDA 12.9.1 任务，运行全部
Python 测试（含慢语料测试）以及接入真实后端的 JavaScript 往返测试。CUDA 任务会检查
工具是否存在，避免工具缺失时把集成测试静默跳过；这些测试无需 GPU。

`data/` 是运行必需的数据快照，应当提交到 Git；`data/manifest.json` 记录来源与哈希。
原仓库的扫描流水线、性能模型和大型实验产物没有迁入。
项目结构见 [架构说明](docs/architecture.md)。

项目使用 MIT 许可证，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
源码仓库：<https://github.com/atransient/cubin-sass-vscode>，问题请在这里提交。
扩展 ID 为 `atransient.cubin-sass`；上架 Marketplace 需要先注册 `atransient` publisher。
