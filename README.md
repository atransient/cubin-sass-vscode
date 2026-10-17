# Cubin SASS Preview

A standalone VS Code extension for inspecting and editing NVIDIA **sm_90** device code
in standalone cubins and Linux CUDA executables, shared libraries and object files.
Open a `.cubin` to see SASS, its 16-byte instruction encodings and scheduling
fields together. The Python backend, instruction tables and small CUDA template
pool are included in this repository and in the VSIX.

[中文说明](README.zh-CN.md) · [Detailed usage (中文)](docs/usage.zh-CN.md) · [Architecture](docs/architecture.md)

## Features

- Preview kernels with syntax coloring, folding, filtering and instruction bit layouts.
- Edit SASS instructions, register operands, modifiers, control fields and raw bytes.
- Keep changes in the editor buffer with undo/redo; write to disk with Ctrl+S.
- Compare cubins and export/replay JSON patches.
- Open a cubin as `.nvsass` source, then assemble changes back with labels and control codes.
- Extract and edit uncompressed sm_90 device ELF images inside Linux CUDA executables,
  shared libraries and object files. Host edits must preserve the embedded cubin's size.
- Synchronize scrolling between source and preview.

## Supported files and instruction-count limits

Both file types support instruction replacement, insertion and deletion, with different
space constraints depending on the editing mode:

| Input | Editing mode | Insertion and deletion limits |
| --- | --- | --- |
| Standalone `.cubin` | Preview `+` / `−` | Fixed section size. Insertion consumes a trailing NOP slot in the target function; deletion shifts instructions and fills the tail with a NOP. |
| Standalone `.cubin` | `.nvsass` source | Supports growing and shrinking existing code sections, subject to layout and relocation validation. No trailing NOP budget is required. |
| Linux CUDA executable, `.so` or `.o` | Preview `+` / `−` | Uses the same fixed-size editing rules inside the selected embedded cubin. |
| Linux CUDA executable, `.so` or `.o` | `.nvsass` source | The embedded cubin's total byte size must remain unchanged. Source edits that change that size are rejected. |

For example, two available trailing NOPs provide room for two preview insertions. To add
more instructions to a standalone cubin, use source mode. Both modes still validate
instruction forms and branch relocation; available space alone does not guarantee an edit
can be applied. Adding or removing whole code sections is currently unsupported.

Host-file editing targets uncompressed sm_90 device images in `.nv_fatbin`. The outer ELF
layout remains unchanged, so there is no host relinking step. Compressed device images
are unsupported; if multiple sm_90 images exist, select the image to edit.

Assembly here means assembling edited `.nvsass` against an existing cubin base. CUDA
C++/PTX compilation is performed separately with tools such as `nvcc` or `ptxas`.

## Requirements

- VS Code 1.75 or later.
- Python **3.10+** on the machine running the extension. The runtime uses only the Python standard library.
- NVIDIA CUDA Toolkit `nvdisasm` on that machine's `PATH` for disassembly and assembly validation.
  Without it, preview falls back to bytes and control fields.
- Linux is the validated platform. Remote-SSH runs the extension and CUDA tools on the remote host.

A GPU is not needed for preview, disassembly, editing or round-trip validation.
Optional driver-load checks need a CUDA driver, a compatible device and a C compiler;
missing prerequisites are reported as skipped. They do not execute edited kernels.

Editing and assembly currently support **sm_90 only**. Unknown forms may be rejected.
Successful disassembly and driver loading do not prove that an edited program computes correctly.

## Install from a VSIX

Build a VSIX from this checkout, or use one provided by your project's release:

```bash
npm ci
npm run package
code --install-extension ./cubin-sass.vsix
```

Node.js 20+ and npm are needed to build and test the extension, not to use an installed VSIX.
In Remote-SSH, use **Extensions → Install from VSIX…** for the remote host.
The installed extension finds its bundled backend automatically, regardless of the open workspace.

Alternatively, open this project in VS Code and press **F5** to launch an Extension Development Host.

## Quick start

1. Open `corpus/cubins/fma.sm_90.cubin` in VS Code.
2. Click an instruction, a control chip or its bytes to edit. Use Ctrl+Z to undo.
3. Run **Cubin: 以 SASS 源码打开** for a text editor view.
4. Saving the source assembles into the cubin's editor buffer. Save the cubin tab to write the file.

For a host executable, run **Cubin: 打开可执行文件中的 sm_90 SASS** from the command palette,
or choose **Open With… → SASS preview (CUDA Host ELF)**.
Edits stay in the host file's editor buffer until you save that tab; saving source opened
from its preview first updates that same buffer. If a source's base is not open in a
custom editor, saving source validates and writes directly to the base file. Failed source
assembly keeps the virtual source dirty and leaves the base unchanged.

The backend also works without VS Code:

```bash
python3 scripts/cubin_sass.py corpus/cubins/fma.sm_90.cubin
python3 scripts/cubin_sass.py edited.cubin --diff original.cubin
```

CLI output is JSON, including source export responses. Failed operations return a nonzero exit
status. See `--help` for patch and assembly options.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `cubinSass.pythonPath` | `python3` | Python interpreter on the extension host. |
| `cubinSass.scriptPath` | `scripts/cubin_sass.py` | Bundled backend by default; custom relative paths resolve from the workspace (or the extension without one). |
| `cubinSass.backendTimeout` | `120` | Task timeout in seconds, including queue time (1–3600). |
| `cubinSass.backendConcurrency` | `2` | Maximum simultaneous backend tasks (1–8); up to 32 additional tasks can queue. |
| `cubinSass.scrollSync` | `true` | Synchronize source and preview scrolling. |
| `cubinSass.showBytes` | `true` | Show instruction bytes. |
| `cubinSass.showCtrl` | `true` | Show decoded control fields. |

`pythonPath` and `scriptPath` are machine-scoped: they are read from user or remote
settings only, so a repository's `.vscode/settings.json` cannot choose what the extension
executes. The extension is disabled in untrusted workspaces (Restricted Mode).

CUDA commands inherit the extension host's `PATH`. If VS Code cannot find Python or
`nvdisasm`, configure Python explicitly and start the extension host with the CUDA
Toolkit `bin` directory in `PATH`.

Run **Cubin: 取消后台任务** to cancel pending and running backend work. Superseded
previews and work for closed documents are cancelled automatically. On Linux,
cancellation and timeout terminate the Python process group, including CUDA tool
children. If backend validation is cancelled or times out, the save retains edits
and does not write the file.

Binary saves check the disk baseline again after validation and refuse external
changes or deletion. Save As also checks for destination changes during validation.
If the original file is missing during VS Code backup recovery, the backup can
still be opened and saved; recreating the file requires full instruction validation.

## Development and tests

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

The full Python suite needs `nvdisasm`; tests that explicitly exercise `nvcc` need the CUDA compiler too.
The default suite omits slow corpus-wide tests. Run them with `NVISA_SLOW=1 python3 -m pytest`.
CI has a fast job for the toolchain-independent Python subset, JavaScript tests and VSIX packaging,
plus a CUDA 12.9.1 job that runs the complete Python suite, including slow corpus tests, and
JavaScript tests with real backend roundtrips. The CUDA job verifies tool availability and requires
those backend tests to run. Neither job needs a GPU or Marketplace credentials.

`data/` contains versioned runtime snapshots, not temporary build output. Keep it in Git.
`data/manifest.json` records source file hashes and the bundled data hashes.
The original ISA scanning pipeline and unrelated GPU performance research are outside this project.
Small compiled CUDA fixtures are included with their source kernels under `corpus/`.

## Publishing

The source lives at <https://github.com/atransient/cubin-sass-vscode>; please report issues there.
The extension ID is `atransient.cubin-sass`. Publishing to the VS Code Marketplace requires
the `atransient` publisher to be registered and its credentials; building a local VSIX does not.

## License

MIT; see [LICENSE](LICENSE) and [NOTICE](NOTICE). CUDA tools and driver libraries are installed separately.
