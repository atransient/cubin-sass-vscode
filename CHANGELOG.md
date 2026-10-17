# Changelog

## Unreleased

- Recheck disk contents, cancellation and editor revisions after staging binary saves, before replacing the destination.
- Release closed virtual source caches so reopening exports the current cubin contents.
- Share concurrent source recovery jobs and discard stale recovery results after newer exports, saves or closure.
- The save gate reports a missing or pre-sm_90 `nvdisasm` as a tool problem instead of illegal encodings.
- Quote file names in the copied `xxd` command.
- Accept `URZ` and named uniform registers/predicates in operand cells; label them by name.
- Undo/redo entries recorded before a disk reload or revert are skipped instead of corrupting the new content.
- Host ELF reflow and source assembly return only the embedded cubin, so large executables stay under the output limit.
- Binary saves and CLI `--out` writes replace files atomically, preserving mode and symlinks.
- Add `ruff` to the development requirements and CI.
- `pythonPath` and `scriptPath` are machine-scoped; workspace settings can no longer choose what runs.
- Declare the extension unsupported in untrusted workspaces and virtual workspaces.
- Stop searching the opened cubin's parent directories for a backend script.
- Refuse to open one file in both SASS preview types at once.
- Read and write `.nvsass` sources as UTF-8 regardless of locale; use a CSPRNG for webview nonces.
- Remove references to design notes and documents that are not part of this repository,
  including requirement tags shown in error messages, tooltips and CLI help.
- Publish as `atransient.cubin-sass` with repository, issue tracker and homepage metadata.

## 0.1.0

- Refuse binary saves that conflict with external disk changes, including Save As destinations.
- Recover valid backups when the original file is missing and validate before recreating it.
- Keep assembly template text and encodings scoped to their kernel sections.
- Bound backend concurrency and queue size; add configurable timeout, cancellation and process-group cleanup.
- Extract the Cubin SASS Preview extension and its Python backend into a standalone repository.
- Bundle sm_90 field tables and small CUDA template fixtures.
- Resolve the backend relative to the installed extension.
- Add VSIX packaging, development setup and automated tests.
