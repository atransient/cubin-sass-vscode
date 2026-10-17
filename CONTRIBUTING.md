# Contributing

Use Node.js 20+, Python 3.10+ and the CUDA Toolkit on Linux for the full development workflow.
Run `npm ci`, install `requirements-dev.txt`, then run `npm test`, `python3 -m ruff check .` and `python3 -m pytest`.
Run `npm run package` to verify the distributable includes the Python backend and data.
Press F5 in VS Code to test the custom editor interactively.

CI runs a fast job without CUDA and a separate CUDA 12.9.1 job with the full Python
suite (`NVISA_SLOW=1`) and real backend JavaScript integration tests. Both run without
a GPU. To require the JavaScript backend tests locally instead of skipping them when
tools are missing, run `CUBIN_SASS_REQUIRE_CUDA=1 npm test`.

Keep ISA bit definitions in the Python backend; the extension consumes those definitions.
Preserve undo/redo, explicit disk saves, round-trip validation and source/base conflict checks.
For changes to runtime tables, update their hashes in `data/manifest.json` and describe
where the replacement data came from. Do not commit vendor toolchains, personal paths,
large production binaries, caches or generated VSIX packages.

A pull request should describe the resulting behavior and relevant test results.
