# Contributing

Bug reports and feature requests are welcome in [GitHub Issues](https://github.com/atransient/cubin-sass-vscode/issues).
A pull request should describe the resulting behavior and relevant test results.

## Development setup

Use Node.js 20+, Python 3.10+ and the CUDA Toolkit on Linux for the full development workflow.
The installed extension's Python backend uses only the standard library; the packages below are development tools.

```bash
npm ci
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

Open the repository root in VS Code and press **F5** to launch an Extension Development Host
and test the custom editor interactively.
See [Architecture](docs/architecture.md) for the repository layout and runtime data provenance.

## Tests

```bash
npm test
python3 -m ruff check .
python3 -m pytest
```

The full Python suite needs `nvdisasm`; tests that compile CUDA source also need `nvcc`.
The default suite omits slow corpus-wide tests. Enable them with:

```bash
NVISA_SLOW=1 python3 -m pytest
```

CI runs a fast job without CUDA and a separate CUDA 12.9.1 job with the complete Python
suite, including slow corpus tests, and real backend JavaScript roundtrips. The CUDA job
verifies tool availability and requires those backend tests to run. Both jobs run without a GPU.
To require the JavaScript backend tests locally instead of skipping them when tools are missing:

```bash
CUBIN_SASS_REQUIRE_CUDA=1 npm test
```

## Implementation guidelines

Keep ISA bit definitions in the Python backend; the extension consumes those definitions.
Preserve undo/redo, explicit disk saves, round-trip validation and source/base conflict checks.

`data/` contains versioned runtime snapshots and must stay in Git. For changes to runtime
tables, update their hashes in `data/manifest.json` and describe where the replacement data
came from. Small compiled CUDA fixtures live with their source kernels under `corpus/`.
Do not commit vendor toolchains, personal paths, large production binaries, caches or generated VSIX packages.

## Packaging and publishing

```bash
npm run package
```

Verify that `cubin-sass.vsix` includes the Python backend and runtime data.
CI also builds the VSIX in its fast job.

The extension ID is `atransient.cubin-sass`. Publishing to the VS Code Marketplace requires
the `atransient` publisher to be registered and its credentials. Building and installing a
local VSIX requires no Marketplace credentials.
