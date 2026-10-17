# Cubin SASS Preview

View, edit and assemble NVIDIA **sm_90** SASS in VS Code. Open a `.cubin` to inspect
instructions, their 16-byte encodings and scheduling fields together, or edit device
code embedded in a Linux CUDA executable, shared library or object file.

English · [简体中文](README.zh-CN.md)

## Features

- Browse kernels with syntax coloring, folding, filtering and instruction bit layouts.
- Edit SASS, registers, modifiers, control fields and raw bytes with undo/redo.
- Edit `.nvsass` source with labels and control codes, then assemble it back into the cubin;
  source and preview scrolling stay in sync.
- Compare cubins and export or replay JSON patches.
- Edit uncompressed sm_90 cubins inside Linux CUDA executables, `.so` and `.o` files.

## Requirements and scope

- **VS Code 1.75+**, **Python 3.10+** and CUDA Toolkit **`nvdisasm`** on the extension host's `PATH`.
  Without `nvdisasm`, preview falls back to bytes and control fields.
- **Linux** is the validated platform. With Remote-SSH, install Python and CUDA tools on the remote host.
- **No GPU required** for preview, disassembly, editing or assembly validation.
- Editing and assembly support **sm_90 only**. Host-file edits must preserve the embedded cubin's
  total byte size; compressed device images are unsupported.

Assembly uses an existing cubin as its base. Unknown instruction forms may be rejected;
successful validation does not guarantee that edited code computes correctly.
See the [editing limits (中文)](docs/usage.zh-CN.md#支持的文件与编辑模式) for details.

## Install

Build a VSIX from source with Node.js 20+ and npm:

```bash
git clone https://github.com/atransient/cubin-sass-vscode.git
cd cubin-sass-vscode
npm ci
npm run package
code --install-extension ./cubin-sass.vsix
```

You can also install a built VSIX through **Extensions → Install from VSIX…**.
With Remote-SSH, install it on the remote host.
The VSIX includes the Python backend, instruction data and template pool; the installed
extension locates them automatically. Node.js and npm are only needed for building and development.

## Quick start

1. Open a `.cubin` in VS Code. This checkout includes a small example:
   [`corpus/cubins/fma.sm_90.cubin`](corpus/cubins/fma.sm_90.cubin).
2. Click SASS text, a control field or instruction bytes to edit. Use **Ctrl+Z** to undo
   and **Ctrl+S** in the cubin tab to save.
3. Run **Cubin: 以 SASS 源码打开** from the command palette to edit `.nvsass` source.
4. Save the source to assemble into the open cubin buffer, then save the cubin tab to write to disk.

For a Linux CUDA executable, `.so` or `.o`, run **Cubin: 打开可执行文件中的 sm_90 SASS**,
or choose **Open With… → SASS preview (CUDA Host ELF)**. Save the host-file tab to write its edits.

## Documentation

| Guide | Contents |
| --- | --- |
| [Usage guide (中文)](docs/usage.zh-CN.md) | Editing modes, insertion/deletion limits, source assembly and JSON patches |
| [Configuration and troubleshooting (中文)](docs/usage.zh-CN.md#配置) | Python and CUDA paths, background tasks and save conflicts |
| [Command line (中文)](docs/usage.zh-CN.md#命令行) | Use the Python backend without VS Code |
| [Architecture](docs/architecture.md) | Extension/backend structure, runtime data and migration background |

## Contributing and feedback

Bug reports and feature requests are welcome in [GitHub Issues](https://github.com/atransient/cubin-sass-vscode/issues).
See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, tests and packaging,
and [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for attribution. CUDA tools and driver libraries are installed separately.
