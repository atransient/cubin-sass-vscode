'use strict';

// Load the real extension and virtual filesystem against a small VS Code host.
// Tests control backend completion order; all binary IO uses real temp files.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');

const root = path.resolve(__dirname, '../..');
const realRequire = createRequire(path.join(root, 'extension.js'));

function uri(scheme, filePath, query = '') {
  return { scheme, path: filePath, fsPath: filePath, query,
    toString: () => `${scheme}:${filePath}${query ? '?' + query : ''}` };
}

class Emitter {
  constructor() {
    this.listeners = new Set();
    this.event = (f) => {
      this.listeners.add(f);
      return { dispose: () => this.listeners.delete(f) };
    };
  }
  fire(value) { for (const f of this.listeners) f(value); }
  dispose() { this.listeners.clear(); }
}

function loadExtension() {
  const commands = new Map();
  const providers = new Map();
  const errors = [];
  const warnings = [];
  const saved = new Emitter();
  const changed = new Emitter();
  const closed = new Emitter();
  const dispos = () => ({ dispose() {} });
  const stub = {
    Uri: {
      file: (p) => uri('file', p),
      from: ({ scheme, path: p, query }) => uri(scheme, p, query),
      parse: (s) => {
        const m = /^([^:]+):([^?]*)(?:\?(.*))?$/.exec(s);
        return uri(m[1], m[2], m[3] || '');
      },
      joinPath: (u, ...parts) => uri(u.scheme, path.join(u.fsPath, ...parts)),
    },
    EventEmitter: Emitter,
    Disposable: class { constructor(f) { this.dispose = f; } },
    RelativePattern: class {},
    Range: class { constructor(...args) { this.args = args; } },
    WorkspaceEdit: class {
      constructor() { this.edits = []; }
      replace(u, _range, text) { this.edits.push({ uri: u, text }); }
    },
    Diagnostic: class {},
    DiagnosticSeverity: { Error: 0 },
    FileType: { File: 1 },
    FileChangeType: { Changed: 1, Created: 2, Deleted: 3 },
    FileSystemError: {
      FileNotFound: (u) => new Error(`FileNotFound: ${u}`),
      NoPermissions: (m) => new Error(m),
    },
    languages: {
      createDiagnosticCollection: () => ({ set() {}, dispose() {} }),
      registerFoldingRangeProvider: dispos,
      setTextDocumentLanguage: async (doc, language) => { doc.languageId = language; return doc; },
    },
    workspace: {
      textDocuments: [],
      fs: {
        readFile: (u) => fs.promises.readFile(u.fsPath),
        writeFile: (u, bytes) => fs.promises.writeFile(u.fsPath, bytes),
        delete: (u) => fs.promises.unlink(u.fsPath),
        rename: async (from, to, { overwrite = false } = {}) => {
          if (!overwrite && fs.existsSync(to.fsPath)) throw new Error(`FileExists: ${to}`);
          await fs.promises.rename(from.fsPath, to.fsPath);
        },
      },
      getConfiguration: () => ({ get: () => undefined }),
      getWorkspaceFolder: () => null,
      registerFileSystemProvider: dispos,
      createFileSystemWatcher: () => ({ onDidChange: dispos, onDidCreate: dispos, dispose() {} }),
      onDidSaveTextDocument: saved.event,
      onDidChangeTextDocument: changed.event,
      onDidCloseTextDocument: closed.event,
      openTextDocument: async (u) => stub.workspace.textDocuments.find((d) => d.uri.toString() === u.toString())
        || sourceDoc(u, (await api.nvsassFS.readFile(u)).toString('utf8')),
      applyEdit: async (edit) => {
        for (const change of edit.edits) {
          const doc = stub.workspace.textDocuments.find((d) => d.uri.toString() === change.uri.toString());
          doc.setText(change.text);
        }
        return true;
      },
    },
    window: {
      registerCustomEditorProvider: (id, p) => { providers.set(id, p); return dispos(); },
      onDidChangeTextEditorVisibleRanges: dispos,
      showErrorMessage: (m) => { errors.push(m); },
      showWarningMessage: async (m) => { warnings.push(m); },
      showInformationMessage() {},
      showTextDocument: async (doc) => {
        const editor = { document: doc };
        stub.window.activeTextEditor = editor;
        return editor;
      },
    },
    commands: {
      registerCommand: (id, f) => { commands.set(id, f); return dispos(); },
      executeCommand: async () => {},
    },
  };
  const cache = new Map();
  function load(file, suffix = '') {
    const mod = { exports: {} };
    const require = (name) => {
      if (name === 'vscode') return stub;
      if (name === './nvsassfs.js') {
        if (!cache.has(name)) cache.set(name, load('nvsassfs.js'));
        return cache.get(name);
      }
      return realRequire(name);
    };
    vm.runInNewContext(fs.readFileSync(path.join(root, file), 'utf8') + suffix,
      { module: mod, exports: mod.exports, require, Buffer, process, console,
        __dirname: root, setTimeout, clearTimeout }, { filename: file });
    return mod.exports;
  }
  const extension = load('extension.js', `
module.exports.testing = { CubinDocument, Provider, assembleIntoBuffer,
  resultBytes, writeBinaryAtomic,
  assembleOntoDisk, assembleSourceDoc, rebaseSourcesFor, nvsassFS, backend, runScriptOnce,
  setRunner: (f) => { runScript = f; }, setProvider: (p) => { activeProvider = p; } };
`);
  const api = extension.testing;
  api.nvsassFS.onDidChangeFile((events) => {
    for (const event of events) {
      const doc = stub.workspace.textDocuments.find((d) => d.uri.toString() === event.uri.toString());
      if (doc && !doc.isDirty) {
        const entry = api.nvsassFS.entries.get(event.uri.toString());
        if (entry && doc.getText() !== entry.content.toString('utf8')) {
          doc.setText(entry.content.toString('utf8'), false);
        }
      }
    }
  });
  function sourceDoc(u, initial, dirty = false) {
    let text = initial;
    const doc = { uri: u, version: 1, isDirty: dirty, languageId: 'nvsass', isClosed: false,
      getText: () => text,
      get lineCount() { return text.split('\n').length; },
      lineAt(n) {
        const line = text.split('\n')[n];
        return { text: line, range: { start: { line: n, character: 0 }, end: { line: n, character: line.length } } };
      },
      setText(value, isDirty = true) {
        text = value; this.version++; this.isDirty = isDirty;
        changed.fire({ document: this, contentChanges: [{ text: value }] });
      },
      close() {
        this.isClosed = true;
        const documents = stub.workspace.textDocuments;
        const index = documents.indexOf(this);
        if (index >= 0) documents.splice(index, 1);
        closed.fire(this);
      },
      async save() {
        try {
          if (u.scheme === 'nvsass') await api.nvsassFS.writeFile(u, Buffer.from(text));
          else await stub.workspace.fs.writeFile(u, Buffer.from(text));
          this.isDirty = false;
          for (const f of saved.listeners) await f(this);
          return true;
        } catch { return false; }
      },
    };
    stub.workspace.textDocuments.push(doc);
    return doc;
  }
  function panel() {
    let receive;
    const messages = [];
    const disposed = new Emitter();
    return { active: true, messages, onDidDispose: disposed.event,
      dispose: () => disposed.fire(),
      receive: (m) => receive(m),
      webview: {
        cspSource: 'test:', asWebviewUri: (u) => u.toString(),
        postMessage: (m) => messages.push(m),
        onDidReceiveMessage: (f) => { receive = f; return dispos(); },
      },
    };
  }
  return { ...api, extension, vscode: stub, commands, providers, errors, warnings,
    sourceDoc, panel, context: { subscriptions: [], extensionUri: stub.Uri.file(root) } };
}

module.exports = { loadExtension };
