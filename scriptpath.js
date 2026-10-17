'use strict';

// Keep script discovery independent from vscode so the development-install
// layout can be tested with plain Node.  In that layout the extension itself
// is symlinked from ~/.vscode-server/extensions into this repository.

const fs = require('fs');
const path = require('path');

const DEFAULT_SCRIPT = 'scripts/cubin_sass.py';

function resolveScriptPath({
  configured = DEFAULT_SCRIPT,
  workspaceRoot = null,
  extensionDir,
  exists = fs.existsSync,
  realpath = fs.realpathSync,
}) {
  if (path.isAbsolute(configured)) return configured;

  // Resolve the installed extension or development symlink first. The backend
  // is bundled beside package.json, independent of the active workspace.
  // Only the default
  // path gets this treatment; an explicitly configured relative path keeps
  // its documented workspace-relative meaning.
  if (configured === DEFAULT_SCRIPT && extensionDir) {
    try {
      const realExtensionDir = realpath(extensionDir);
      const candidate = path.resolve(realExtensionDir, configured);
      if (exists(candidate)) return candidate;
    } catch (_err) {
      // A broken development symlink falls through to the unresolved path below.
    }
  }

  // Never search the opened file's directories, and never let the default
  // fall back to a workspace copy: a cubin from an untrusted download must not
  // choose which script runs. A missing backend then produces a clear error.
  const root = configured === DEFAULT_SCRIPT ? extensionDir : (workspaceRoot || extensionDir);
  return path.resolve(root || '.', configured);
}

module.exports = { DEFAULT_SCRIPT, resolveScriptPath };
