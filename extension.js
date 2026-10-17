'use strict';
// .cubin 的自定义编辑器。扩展本身不懂 ISA —— 位定义只有一份，在
// nvisa/model/codec.py 里；这里只负责跑 scripts/cubin_sass.py 拿 JSON、渲染，
// 以及把改动攒在内存里等 Ctrl+S。
//
// 编辑模型：改动只进缓冲区，标签页显示脏标记，Ctrl+S 才落盘，Ctrl+Z 可撤销。
// 故意不做「点一下立刻写文件」—— 手改的基底往往是「只编译一次」的东西，
// 手滑就没了。

const vscode = require('vscode');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

const VIEW_TYPE = 'cubinSass.preview';
const HOST_VIEW_TYPE = 'cubinSass.hostPreview';
const ALL_TEXT_SECTIONS = '__all_text_sections__';
// 源码/预览滚动同步用的纯逻辑（行 <-> 段内地址）与 webview 共用一份。
const V = require('./media/view.js');
// `.nvsass` 的内存文件系统 —— 源码是 cubin 的视图，不在磁盘上留文件。
const { NvsassFS, SCHEME: NVSASS_SCHEME } = require('./nvsassfs.js');
const { baseHash, declaredBase } = require('./basehash.js');
const { BaseHistory } = require('./basehistory.js');
const { resolveScriptPath } = require('./scriptpath.js');
const { BackendRunner } = require('./backend.js');
const backend = new BackendRunner();

// 窗口重载后 VS Code 会把 `nvsass:` 的 tab 重新打开，但内存是空的 —— uri 里
// 带着「基底 + section」，照着它从 cubin 里重新导一遍。未保存的源码由
// VS Code 的 dirty-document 备份保护；汇编失败时不能把源码标成已保存。
// `.nvsass` 的汇编要拿「打开着的那份 cubin 缓冲区」当基底（两个视图共用一份
// 字节，见下面 `assembleIntoBuffer`），所以这里留一个模块级句柄；activate() 里赋值。
let activeProvider = null;

const nvsassFS = new NvsassFS(async (baseUri, section, image) => {
  // 开着的那份缓冲区优先（它才是当前真相）；没开就退回磁盘。
  const live = liveCubin(baseUri);
  if (!live && !fs.existsSync(baseUri.fsPath)) return null;
  const data = live ? live.data
    : Buffer.from(await vscode.workspace.fs.readFile(baseUri));
  const res = await emitSource(baseUri, data, section, image);
  if (res.ok && live) rememberContainer(live, res.container);
  return res.ok ? res.source : null;
}, async (uri, text) => {
  const doc = vscode.workspace.textDocuments.find((d) => d.uri.toString() === uri.toString());
  if (!doc) throw new Error('源码文档已经关闭，未执行汇编。');
  const res = await assembleSourceDoc(doc, { silent: true, saving: true, text });
  return res.source || text;
});

// 两个方向共用一个抑制窗：谁在滚谁说了算，另一边在这段时间里不回推，
// 否则两栏会互相推着走（markdown 预览踩过的坑）。
const SYNC_QUIET_MS = 250;
const scrollSync = { until: 0 };

function cfg() {
  return vscode.workspace.getConfiguration('cubinSass');
}

/**
 * 优先从扩展自身目录加载随包提供的后端；否则相对路径仍按 cubin 所属的
 * 工作区解析。这样服务器账户只需维护一个扩展软连接，多根工作区也对。
 */
function resolveScript(uri) {
  const raw = cfg().get('scriptPath');
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  return resolveScriptPath({
    configured: raw,
    workspaceRoot: folder ? folder.uri.fsPath : null,
    extensionDir: __dirname,
  });
}

/** 跑 cubin_sass.py。`stdinData` 非空就把缓冲区喂给它，解析未保存的内容。 */
function runScriptOnce(uri, args, stdinData, python, options = {}) {
  const script = resolveScript(uri);
  const argv = [script, ...args];
  backend.setConcurrency(cfg().get('backendConcurrency'));
  const configuredTimeout = cfg().get('backendTimeout');
  const seconds = Number.isFinite(configuredTimeout)
    ? Math.max(1, Math.min(3600, configuredTimeout)) : 120;
  return backend.run(python, argv, {
    cwd: path.dirname(script), input: stdinData, timeoutMs: seconds * 1000,
    owner: uri.toString(), hint: `跑的是: ${python} ${argv.join(' ')}`, ...options,
  });
}

async function runScript(uri, args, stdinData, options) {
  return runScriptOnce(uri, args, stdinData, cfg().get('pythonPath') || 'python3', options);
}

async function withTempCubin(data, action) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-sass-'));
  try {
    const file = path.join(dir, 'input.cubin');
    fs.writeFileSync(file, data);
    return await action(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Full file bytes from a backend result. With `--payload-only` a host ELF
 * result carries just its embedded cubin; patch it into the bytes we sent.
 */
function resultBytes(res, base) {
  const bytes = Buffer.from(res.data, 'hex');
  if (res.data_scope !== 'payload') return bytes;
  const c = res.container || {};
  const lo = Number(c.payload_offset);
  if (!c.embedded || bytes.length !== Number(c.payload_size)
      || !Number.isSafeInteger(lo) || lo < 0 || lo + bytes.length > base.length) {
    throw new Error('后端返回的内嵌 cubin 与宿主文件布局不符，未应用。');
  }
  const out = Buffer.from(base);
  bytes.copy(out, lo);
  return out;
}

function snapshotOf(doc) {
  return { revision: doc.revision, image: doc.image, diskMissing: doc.diskMissing,
    data: Buffer.from(doc.data), savedData: Buffer.from(doc.savedData) };
}

function isCurrent(doc, snapshot) {
  return !doc.disposed && doc.revision === snapshot.revision && doc.image === snapshot.image;
}

function assertCurrent(doc, snapshot) {
  if (!isCurrent(doc, snapshot)) throw new Error('操作期间 cubin 已改变，未应用过期结果，请重试。');
}

function assertSourceCurrent(doc, text, version) {
  if (doc.isClosed || doc.version !== version || doc.getText() !== text) {
    throw new Error('操作期间源码已改变，未应用过期结果，请重新保存。');
  }
}

async function readOptionalFile(uri) {
  try {
    return Buffer.from(await vscode.workspace.fs.readFile(uri));
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'FileNotFound') return null;
    throw e;
  }
}

async function assertDiskBaseline(uri, expected) {
  const current = await readOptionalFile(uri);
  if (current === null ? expected !== null : expected === null || !current.equals(expected)) {
    throw new Error('磁盘文件已被外部修改或删除，保存已停止，编辑内容仍保留。请重新载入磁盘版本或另存为。');
  }
}

function writeLocalAtomic(uri, data) {
  // A symlinked target keeps its link; the file it points to is replaced.
  const target = fs.realpathSync(uri.fsPath);
  const mode = fs.statSync(target).mode & 0o7777;
  const dir = fs.mkdtempSync(path.join(path.dirname(target), '.cubin-sass-'));
  try {
    const file = path.join(dir, 'output.cubin');
    const fd = fs.openSync(file, 'w');
    try {
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(file, mode);
    fs.renameSync(file, target);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function permissionDenied(e) {
  return e && (e.code === 'EACCES' || e.code === 'EPERM' || e.code === 'NoPermissions');
}

/**
 * Save a binary without ever leaving a half-written file at `target`: write a
 * sibling temporary file, then rename it over the target. Renaming also keeps
 * a running executable intact (an in-place write fails with ETXTBSY) and
 * preserves the original mode. Hard links to the old file are not updated.
 */
async function writeBinaryAtomic(target, data) {
  if (target.scheme !== 'file') return vscode.workspace.fs.writeFile(target, data);
  let real = target.fsPath;
  let mode = null;
  try {
    real = fs.realpathSync(target.fsPath);
    mode = fs.statSync(real).mode & 0o7777;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  const tmp = vscode.Uri.file(path.join(path.dirname(real),
    `.${path.basename(real)}.cubin-sass-${crypto.randomBytes(6).toString('hex')}`));
  try {
    await vscode.workspace.fs.writeFile(tmp, data);
  } catch (e) {
    // A writable file in a read-only directory cannot be replaced by rename.
    if (!permissionDenied(e)) throw e;
    return vscode.workspace.fs.writeFile(vscode.Uri.file(real), data);
  }
  try {
    if (mode !== null) fs.chmodSync(tmp.fsPath, mode);
    await vscode.workspace.fs.rename(tmp, vscode.Uri.file(real), { overwrite: true });
  } catch (e) {
    try { await vscode.workspace.fs.delete(tmp); } catch (_) { /* already gone */ }
    throw e;
  }
}

// ---------------------------------------------------------------------------
// document：持有字节 + 撤销栈
// ---------------------------------------------------------------------------

class CubinDocument {
  constructor(uri, data) {
    this.uri = uri;
    this.revision = 0;
    // Bumped whenever the buffer is replaced from disk outside the undo stack.
    // VS Code keeps that stack, but its offsets describe the older bytes.
    this.epoch = 0;
    this.disposed = false;
    this._saveQueue = Promise.resolve();
    this.data = Buffer.from(data);       // 当前（可能未保存的）内容
    this.savedData = Buffer.from(data);  // 上次落盘的内容，用来算脏不脏
    this.diskMissing = false; // restored backup whose original file no longer exists
    this.diffAgainst = null;
    this.image = null;       // fatbin image index; null lets the backend auto-select
    this.container = null;   // selected payload coordinates inside a host ELF
    this.containers = new Map(); // known coordinates for independently bound source images
    this.experimental = false;   // 上次落盘时绕过了保存安全闸
    this._onDidChange = new vscode.EventEmitter();
    this.onDidChangeCustomDocument = this._onDidChange.event;
    this._onRender = new vscode.EventEmitter();
    this.onRender = this._onRender.event;   // 内容变了，让 webview 重画
  }

  static async open(uri, backupId) {
    // A valid backup must remain recoverable after the original was removed.
    const backup = backupId ? await vscode.workspace.fs.readFile(vscode.Uri.parse(backupId)) : null;
    const onDisk = backupId ? await readOptionalFile(uri) : await vscode.workspace.fs.readFile(uri);
    const data = backup || onDisk;
    const doc = new CubinDocument(uri, data);
    doc.savedData = Buffer.from(onDisk === null ? data : onDisk);
    doc.diskMissing = onDisk === null;
    return doc;
  }

  get data() { return this._data; }
  set data(value) { this._data = value; this.revision++; }

  /** 把一段字节写进某个文件偏移，登记为一次可撤销的编辑。 */
  applyEdit(fileOff, newBytes, label) {
    if (!Number.isSafeInteger(fileOff) || fileOff < 0 || fileOff + newBytes.length > this.data.length) {
      throw new Error('编辑位置越过 cubin 文件边界。');
    }
    const old = Buffer.from(this.data.subarray(fileOff, fileOff + newBytes.length));
    const next = Buffer.from(newBytes);
    if (old.equals(next)) return;
    this._write(fileOff, next);
    const epoch = this.epoch;
    this._onDidChange.fire({
      label,
      undo: () => this._replay(epoch, label, () => this._write(fileOff, old)),
      redo: () => this._replay(epoch, label, () => this._write(fileOff, next)),
    });
    this._onRender.fire();
  }

  /** 整个文件换一份内容（插入/删除会挪动整段，不是改某 16 字节）。
   *  仍登记成一次可撤销的编辑 —— 撤销栈上看得见「插入了哪条」。 */
  applyWhole(newData, label) {
    const old = Buffer.from(this.data);
    const next = Buffer.from(newData);
    if (old.equals(next)) return;
    this.data = next;
    const epoch = this.epoch;
    this._onDidChange.fire({
      label,
      undo: () => this._replay(epoch, label, () => { this.data = old; }),
      redo: () => this._replay(epoch, label, () => { this.data = next; }),
    });
    this._onRender.fire();
  }

  /** Undo/redo of an edit made before the last reload would splice old bytes
   *  into a different file, so it is skipped and the disk content is kept. */
  _replay(epoch, label, apply) {
    if (epoch !== this.epoch) {
      vscode.window.showWarningMessage(
        `「${label}」发生在磁盘版本重新载入之前，已跳过这次撤销/重做，内容保持磁盘版本。`);
      return;
    }
    apply();
    this._onRender.fire();
  }

  /** Replace the buffer with the disk content; earlier undo entries go stale. */
  reloadFromDisk(onDisk) {
    this.epoch++;
    this.data = Buffer.from(onDisk);
    this.savedData = Buffer.from(onDisk);
    this.diskMissing = false;
    this.container = null;
    this.containers.clear();
    this._onRender.fire();
  }

  _write(fileOff, buf) {
    buf.copy(this.data, fileOff);
    this.revision++;
  }

  async save(cancel) {
    await this.saveAs(this.uri, cancel);
  }

  async saveAs(target, cancel, snapshot = snapshotOf(this), expectedTarget) {
    if (cancel && cancel.isCancellationRequested) throw new Error('保存已取消。');
    const sameTarget = target.toString() === this.uri.toString();
    if (expectedTarget === undefined) {
      expectedTarget = sameTarget
        ? (snapshot.diskMissing ? null : snapshot.savedData) : await readOptionalFile(target);
    }
    await assertDiskBaseline(target, expectedTarget);
    if (cancel && cancel.isCancellationRequested) throw new Error('保存已取消。');
    assertCurrent(this, snapshot);
    await writeBinaryAtomic(target, snapshot.data);
    if (sameTarget) {
      this.savedData = Buffer.from(snapshot.data);
      this.diskMissing = false;
    }
    assertCurrent(this, snapshot);
  }

  async revert() {
    this.reloadFromDisk(await vscode.workspace.fs.readFile(this.uri));
  }

  async backup(dest, cancel) {
    await vscode.workspace.fs.writeFile(dest, Buffer.from(this.data));
    return {
      id: dest.toString(),
      delete: async () => {
        try { await vscode.workspace.fs.delete(dest); } catch (e) { /* 已经没了 */ }
      },
    };
  }

  dispose() {
    this.disposed = true;
    backend.cancelOwner(this.uri.toString());
    this._onDidChange.dispose();
    this._onRender.dispose();
  }
}

// ---------------------------------------------------------------------------

function nonce() {
  return crypto.randomBytes(16).toString('base64');
}

function html(webview, extensionUri) {
  const uri = (...p) => webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, ...p));
  const n = nonce();
  return `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';
  style-src ${webview.cspSource}; script-src 'nonce-${n}'; font-src ${webview.cspSource};">
<link rel="stylesheet" href="${uri('media', 'main.css')}">
<title>SASS preview</title>
</head>
<body>
<header>
  <span id="title"></span>
  <span class="grow"></span>
  <input id="filter" type="search" placeholder="过滤：FFMA、R12、0x00a0 …">
  <label><input type="checkbox" id="tCtrl"> 控制段</label>
  <label><input type="checkbox" id="tBytes"> 字节</label>
  <label><input type="checkbox" id="tCells"> 格子</label>
  <label><input type="checkbox" id="tDiffOnly"> 只看差异</label>
</header>
<div id="banner" hidden></div>
<main id="out"></main>
<div id="hint">点 SASS 改整条指令 · 点字段改值 · 点字节改十六进制 · Ctrl+S 保存 · Ctrl+Z 撤销</div>
<script nonce="${n}" src="${uri('media', 'bits.js')}"></script>
<script nonce="${n}" src="${uri('media', 'view.js')}"></script>
<script nonce="${n}" src="${uri('media', 'main.js')}"></script>
</body>
</html>`;
}

class Provider {
  constructor(context) {
    this.context = context;
    this._onDidChangeCustomDocument = new vscode.EventEmitter();
    this.onDidChangeCustomDocument = this._onDidChangeCustomDocument.event;
    /** uri.toString() -> {doc, panel} —— 对比命令要拿到当前活动的那个 */
    this.live = new Map();
  }

  async openCustomDocument(uri, openContext = {}) {
    const doc = await CubinDocument.open(uri, openContext.backupId);
    doc.onDidChangeCustomDocument((e) => {
      this._onDidChangeCustomDocument.fire({ document: doc, ...e });
    });
    return doc;
  }

  async resolveCustomEditor(document, panel) {
    const key = document.uri.toString();
    // Both view types accept a .cubin. Two editors would hold two independent
    // buffers of one file and overwrite each other's saves.
    const other = this.live.get(key);
    if (other && other.doc !== document) {
      throw new Error(`${path.basename(document.uri.fsPath)} 已在另一个 SASS 预览中打开，`
        + '请先关闭那个标签再换一种方式打开。');
    }
    panel.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.context.extensionUri],
    };
    panel.webview.html = html(panel.webview, this.context.extensionUri);

    this.live.set(key, { doc: document, panel });
    // InsKey/cell_map is the expensive layer.  Keep the initial preview lean;
    // once requested it stays enabled for this editor so edits still refresh
    // the visible cells correctly.
    let includeCells = false;
    let choosingImage = false;
    let refreshSerial = 0;
    let closed = false;

    const refresh = async () => {
      const serial = ++refreshSerial;
      const snapshot = snapshotOf(document);
      panel.webview.postMessage({ type: 'loading' });
      const args = [document.uri.fsPath, '--stdin'];
      if (document.image !== null) args.push('--image', String(document.image));
      if (!includeCells) args.push('--no-cells');
      if (document.diffAgainst) args.push('--diff', document.diffAgainst.fsPath);
      const data = await runScript(document.uri, args, snapshot.data, { key: `preview:${key}` });
      if (closed || serial !== refreshSerial || !isCurrent(document, snapshot)) return;
      if (data.cancelled) {
        panel.webview.postMessage({ type: 'backendCancelled' });
        return;
      }
      if (!data.ok && data.images && data.images.length && !choosingImage) {
        choosingImage = true;
        try {
          const pick = await vscode.window.showQuickPick(data.images.map((x) => ({
            label: `image #${x.index} · ${x.arch}`,
            description: (x.text_sections || []).join(', ') || '无 .text section',
            detail: `${x.section} @ 0x${Number(x.payload_offset).toString(16)}, `
              + `${x.payload_size} bytes`,
            image: x.index,
          })), { title: '这个宿主 ELF 中有多个 sm_90 cubin，请选择要编辑的一个' });
          if (pick) {
            document.image = pick.image;
            refresh();
            return;
          }
        } finally {
          choosingImage = false;
        }
      }
      if (data.ok && data.container) {
        document.container = data.container;
        rememberContainer(document, data.container);
        if (data.container.index !== undefined) document.image = data.container.index;
      }
      data.name = path.basename(document.uri.fsPath);
      data.diffName = document.diffAgainst
        ? path.basename(document.diffAgainst.fsPath) : null;
      data.dirty = document.diskMissing || !document.data.equals(document.savedData);
      data.experimental = document.experimental;       // 上次是实验性保存
      data.revision = snapshot.revision;
      panel.webview.postMessage({ type: 'data', data });
    };
    this.live.get(key).refresh = refresh;

    // 内容变了就重画 webview，并把开着的 `.nvsass` 拉到同一份字节上 ——
    // 格子编辑、撤销/重做、跟随外部改动，全都从这一个点走。
    const sub = document.onRender(() => {
      backend.cancelOwner(key);
      refresh();
      rebaseSourcesFor(document.uri, document.data);
    });

    panel.webview.onDidReceiveMessage(async (m) => {
      try {
        if (['edit', 'assemble', 'reflow'].includes(m.type) && m.revision !== document.revision) {
          throw new Error('预览内容已过期，请等待刷新后再编辑。');
        }
        if (m.type === 'ready') {
          panel.webview.postMessage({
            type: 'defaults',
            showBytes: cfg().get('showBytes'),
            showCtrl: cfg().get('showCtrl'),
          });
          refresh();
        } else if (m.type === 'loadCells') {
          includeCells = true;
          refresh();
        } else if (m.type === 'edit') {
          // 位运算在 webview 里做（字段位置由 python 下发），这里只管登记撤销
          document.applyEdit(m.fileOff, Buffer.from(m.bytes, 'hex'), m.label);
        } else if (m.type === 'assemble') {
          const snapshot = snapshotOf(document);
          // 换整条指令：模板+补丁+回环校验都在 python 侧，这里只搬运结果
          const args = [document.uri.fsPath, '--stdin',
                        '--at', String(m.fileOff), '--assemble', m.text];
          if (document.image !== null) args.push('--image', String(document.image));
          const res = await runScript(document.uri, args, snapshot.data);
          assertCurrent(document, snapshot);
          if (res.ok) {
            document.applyEdit(m.fileOff, Buffer.from(res.bytes, 'hex'),
                               `${m.text} @ +0x${m.fileOff.toString(16)}`);
          } else {
            // Also report outside the webview. If the webview is refreshed or
            // its banner is hidden, the user must still see why the old SASS
            // remained unchanged.
            vscode.window.showErrorMessage(`SASS 汇编失败：${res.error || '未知错误'}`);
          }
          panel.webview.postMessage({ type: 'assembled', res });
        } else if (m.type === 'reflow') {
          const snapshot = snapshotOf(document);
          // 插入/删除一条。段大小不变，但整段字节都会挪，所以整份换掉；
          // 分支重定位、.nv.info 的指令偏移、以及回环复核都在 python 侧。
          const args = [document.uri.fsPath, '--stdin', '--payload-only',
                        '--at', String(m.fileOff)];
          if (document.image !== null) args.push('--image', String(document.image));
          if (m.op === 'insert') args.push('--insert', m.text);
          else args.push('--delete');
          const res = await runScript(document.uri, args, snapshot.data);
          assertCurrent(document, snapshot);
          if (res.ok) {
            document.applyWhole(resultBytes(res, snapshot.data),
                                m.op === 'insert'
                                  ? `插入 ${res.sass} @ +0x${m.fileOff.toString(16)}`
                                  : `删掉 +0x${m.fileOff.toString(16)} 那一条`);
          }
          panel.webview.postMessage({ type: 'reflowed', op: m.op, res });
        } else if (m.type === 'scrolled') {
          revealSourceAt(document.uri, m.section, m.addr);
        } else if (m.type === 'copy') {
          vscode.env.clipboard.writeText(m.text);
          vscode.window.setStatusBarMessage(`已复制: ${m.text}`, 3000);
        }
      } catch (e) {
        const res = { ok: false, error: e.message };
        vscode.window.showErrorMessage(e.message);
        if (m.type === 'assemble') panel.webview.postMessage({ type: 'assembled', res });
        if (m.type === 'reflow') panel.webview.postMessage({ type: 'reflowed', op: m.op, res });
        refresh();
      }
    });

    // 文件在外面被 dd / 脚本改写：没有未保存改动就跟着更新，有就让用户自己定
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(path.dirname(document.uri.fsPath)),
                                 path.basename(document.uri.fsPath)));
    const onExternal = async () => {
      // A delete or a rename-over can race with this read; there is nothing to follow then.
      const onDisk = await readOptionalFile(document.uri).catch(() => null);
      if (onDisk === null || document.disposed) return;
      if (onDisk.equals(document.data)) return;                 // 就是我们自己刚存的
      if (!document.diskMissing && document.data.equals(document.savedData)) { // 干净 -> 直接跟随
        document.reloadFromDisk(onDisk);
        return;
      }
      const pick = await vscode.window.showWarningMessage(
        `${path.basename(document.uri.fsPath)} 在编辑器外被改动了，而这里还有未保存的修改。`,
        { modal: false }, '丢弃我的修改，载入磁盘版本');
      if (pick) await document.revert();
    };
    watcher.onDidChange(onExternal);
    watcher.onDidCreate(onExternal);

    panel.onDidDispose(() => {
      closed = true;
      backend.cancelOwner(key);
      watcher.dispose();
      sub.dispose();
      if (this.live.get(key)?.panel === panel) {
        this.live.delete(key);
        baseHistory.forget(document.uri.fsPath);   // 关掉就别攒着这份 cubin 的字节
      }
    });
  }

  // --- VS Code 的保存/撤销协议 ---
  //
  // 普通保存前先过保存安全闸 —— 改动过的每条指令都必须能被 nvdisasm 解出来。
  // 格子/控制段/字节编辑是前端直接写缓冲区的，路上没有回环校验（只有换整条
  // 指令的 `assemble` 有），所以拦在落盘这一步。要留着非法编码就得在弹窗里
  // 显式选「实验性保存」，选了会在标题上挂标记。
  async gate(doc, snapshot = snapshotOf(doc), cancel) {
    if (cancel && cancel.isCancellationRequested) throw new Error('保存已取消。');
    if (!snapshot.diskMissing && snapshot.data.equals(snapshot.savedData)) return true;
    const check = (diff = []) => runScript(doc.uri, [doc.uri.fsPath, '--stdin',
      ...diff, '--check-save',
      ...(snapshot.image !== null ? ['--image', String(snapshot.image)] : [])], snapshot.data, { token: cancel });
    // Without the original baseline, validate every instruction in the backup.
    const res = snapshot.diskMissing ? await check()
      : await withTempCubin(snapshot.savedData, (tmp) => check(['--diff', tmp]));
    assertCurrent(doc, snapshot);
    if (res.cancelled || res.timedOut || res.infrastructureError) throw new Error(res.error);
    if (res.ok) {
      doc.experimental = false;
      return true;
    }
    const detail = res.error || '保存安全闸没有给出原因。';
    const pick = await vscode.window.showWarningMessage(
      '有改动过的指令 nvdisasm 解不出来，普通保存已被阻止。', { modal: true, detail },
      '实验性保存（保留非法编码）');
    assertCurrent(doc, snapshot);
    if (pick !== '实验性保存（保留非法编码）') {
      throw new Error(`保存被安全闸阻止：${detail}`);
    }
    doc.experimental = true;
    return true;
  }

  async saveCustomDocument(doc, cancel) {
    return this.saveValidated(doc, doc.uri, cancel);
  }

  async saveCustomDocumentAs(doc, dest, cancel) {
    return this.saveValidated(doc, dest, cancel);
  }

  saveValidated(doc, dest, cancel) {
    const save = doc._saveQueue.then(async () => {
      const snapshot = snapshotOf(doc);
      const expectedTarget = dest.toString() === doc.uri.toString()
        ? (snapshot.diskMissing ? null : snapshot.savedData) : await readOptionalFile(dest);
      await this.gate(doc, snapshot, cancel);
      assertCurrent(doc, snapshot);
      await doc.saveAs(dest, cancel, snapshot, expectedTarget);
      const entry = this.live.get(doc.uri.toString());
      if (entry && entry.refresh) entry.refresh();
      if (doc.experimental) {
        vscode.window.showWarningMessage('已按【实验性保存】落盘：文件里有 nvdisasm 解不出来的编码。');
      }
    });
    doc._saveQueue = save.catch(() => {});
    return save;
  }
  revertCustomDocument(doc) { return doc.revert(); }
  backupCustomDocument(doc, ctx, cancel) { return doc.backup(ctx.destination, cancel); }

  active() {
    for (const e of this.live.values()) if (e.panel.active) return e;
    return null;
  }
}

async function pickDiffTarget(entry) {
  const found = await vscode.workspace.findFiles('**/*.cubin', '**/node_modules/**', 2000);
  const items = found
    .filter((u) => u.toString() !== entry.doc.uri.toString())
    .map((u) => ({
      label: path.basename(u.fsPath),
      description: vscode.workspace.asRelativePath(u),
      uri: u,
    }))
    .sort((a, b) => a.description.localeCompare(b.description));
  if (!items.length) {
    vscode.window.showInformationMessage('工作区里没有别的 .cubin 可比。');
    return null;
  }
  const pick = await vscode.window.showQuickPick(items, {
    title: `与哪个 cubin 对比？（当前 ${path.basename(entry.doc.uri.fsPath)}）`,
    matchOnDescription: true,
  });
  return pick ? pick.uri : null;
}

// 以 SASS 源码打开。故意**不**在 Webview 里模拟一个 <textarea> —— 做成真正
// 的文本 document（`.nvsass`），撤销/重做、搜索、多光标、行号、诊断和语法高亮
// 就都是 VS Code 自己的，扩展一行都不用写。解析与导出全在
// `scripts/cubin_sass.py --emit-source` 里，扩展这边不另写一套 parser。
async function emitSource(uri, data, section, image = null, options) {
  const args = [uri.fsPath, '--stdin', '--emit-source'];
  const live = liveCubin(uri);
  const selected = image !== null ? image : (live ? live.image : null);
  if (selected !== null) args.push('--image', String(selected));
  if (!section || section === ALL_TEXT_SECTIONS) args.push('--all-sections');
  else args.push('--section', section);
  return runScript(uri, args, data, options);
}

async function openSourceFor(uri, data, image = null) {
  const live = liveCubin(uri);
  const snapshot = live && snapshotOf(live);
  const res = await emitSource(uri, data, null, image);
  if (!res.ok) {
    vscode.window.showErrorMessage(`导出 SASS 源码失败：${res.error}`);
    return;
  }
  if (live && !isCurrent(live, snapshot)) {
    vscode.window.showErrorMessage('导出期间 cubin 已改变，请重新打开源码。');
    return;
  }
  const selected = res.container
    ? (res.container.embedded ? res.container.index : null)
    : (image !== null ? image : (live ? live.image : null));
  if (live) rememberContainer(live, res.container);
  const existing = sourceDocsFor(uri).find((d) => nvsassFS.sectionOf(d.uri) === res.section
    && nvsassFS.imageOf(d.uri) === selected);
  if (existing && existing.isDirty) {
    await vscode.window.showTextDocument(existing, { preview: false });
    return;
  }
  // 源码进内存文件系统，不落盘：它是 cubin 的一个视图，cubin 才是唯一的真相。
  // 「哪份源码对着哪个 cubin」由 `nvsassFS` 记着，不再靠文件名去猜（老的
  // `<cubin>.<section>.nvsass` 约定只留给磁盘上真实存在的文件）。
  baseHistory.remember(uri.fsPath, data, res.base, selected);
  const dest = nvsassFS.set(uri, res.section, res.source, selected);
  const doc = await vscode.workspace.openTextDocument(dest);
  await vscode.languages.setTextDocumentLanguage(doc, 'nvsass');
  await vscode.window.showTextDocument(doc, { preview: false });
  // Match the cubin preview: leave the first kernel visible and collapse the
  // rest.  They remain ordinary editor folds, so Fold All / Unfold All and
  // clicking the gutter work exactly as for source code.
  if ((res.sections || []).length > 1) {
    const starts = [];
    for (let i = 0; i < doc.lineCount; i++) {
      if (/^\s*\.section\s+\.text\S*/.test(doc.lineAt(i).text)) starts.push(i);
    }
    if (starts.length > 1) {
      await vscode.commands.executeCommand('editor.fold', {
        selectionLines: starts.slice(1),
      });
    }
  }
  for (const w of res.warnings || []) vscode.window.showWarningMessage(w);
  // Ctrl+S 在虚拟文件系统的 writeFile 中等待汇编完成。
  vscode.window.showInformationMessage(
    `已打开 ${(res.sections || [res.section]).length} 个 .text section 的源码` +
    `（基底 ${res.base}，只在内存里，不落盘）。` +
    'Ctrl+S 汇编到 cubin 缓冲区（增删指令也支持）；再保存 cubin 标签才落盘。'
    + '汇编失败时源码保留未保存状态。');
}

// ---------------------------------------------------------------------------
// 基底与源码：**同一个 cubin document 的两个视图**。
//
// 打开的那份 `CubinDocument`（`doc.data`，可能还没落盘）就是唯一的真相：webview
// 的 SASS preview 是它的一个渲染，`.nvsass` 是它的另一个渲染。所以源码的汇编也
// 是 **缓冲区 -> 缓冲区**：拿 `doc.data` 当基底、把结果 `applyWhole()` 回同一个
// document —— 一次可撤销的编辑，标签页变脏，`Ctrl+S` 落盘时照常过保存安全闸。
// 磁盘只有那一次保存会碰。
//
// 这样一来，`.base` 那道冲突闸就回到了它本来的职责：只用来发现**编辑器外面**
// 的改动（watcher 那条路），而不是在我们自己的两个视图之间报「基底对不上」——
// 两个视图共用一份字节，永远对得上。
//
// 只有一种情况仍走「磁盘事务」：`.nvsass` 的基底 cubin 没在自定义编辑器里开着
// （比如单独打开一份磁盘上的 `.nvsass`）。那时没有缓冲区可依，退回
// `--out` 那条原子替换的老路。
// ---------------------------------------------------------------------------

// 汇编那一步自己会把源码重绑好（后端回的文本保住了用户排版），所以在这期间
// 别让 `applyWhole()` 触发的重导插进来把它抹平 —— 用一把按 cubin 计的锁挡住。
const assembling = new Set();

// 每个 cubin 最近几份字节 —— 源码被 Ctrl+Z 退回上一版时，它头里的 `.base` 也跟着
// 退回旧 hash，靠这张表把**那一版基底**找回来（见 `basehistory.js` 的注释）。
const baseHistory = new BaseHistory();

function rememberContainer(doc, container) {
  if (container && container.embedded) doc.containers.set(container.index, container);
}

function containerFor(doc, image) {
  if (!doc) return null;
  return doc.containers.get(image) || (image === doc.image ? doc.container : null);
}

function sourceImage(uri, live) {
  const bound = nvsassFS.imageOf(uri);
  return bound !== null ? bound : (live ? live.image : null);
}

/** Hash the selected cubin payload, not the whole host executable. */
function documentBaseHash(doc, data, image = doc ? doc.image : null) {
  const c = containerFor(doc, image);
  if (c && c.embedded) {
    const lo = Number(c.payload_offset);
    const hi = lo + Number(c.payload_size);
    return baseHash(data.subarray(lo, hi));
  }
  return baseHash(data);
}

/** 开着的、以 `baseUri` 为基底的 `.nvsass` 文档。 */
function sourceDocsFor(baseUri) {
  return vscode.workspace.textDocuments.filter((d) => {
    const b = nvsassFS.baseOf(d.uri);
    return b && b.fsPath === baseUri.fsPath;
  });
}

/** 这个 cubin 在自定义编辑器里开着吗？开着就以它的缓冲区为准。 */
function liveCubin(baseUri) {
  const entry = activeProvider && activeProvider.live.get(baseUri.toString());
  return entry ? entry.doc : null;
}

/**
 * cubin 的字节变了 -> 把开着的源码重新从这份字节导一遍。
 *
 * 触发点只有一个：`CubinDocument` 的内容变了（格子编辑、撤销、跟随外部改动）。
 * 源码没改过就静静换掉（它本来就只是这份字节的视图）；改过了不能悄悄丢，问一句
 * 再说 —— 重导走 WorkspaceEdit，所以 Ctrl+Z 还能把自己的改动拿回来。
 */
async function rebaseSourcesFor(baseUri, inputData) {
  const data = Buffer.from(inputData);
  // 先记下这一版字节（哪怕接下来什么都不做）：源码的撤销栈里可能正躺着一份
  // 声明了这个 hash 的旧正文，回头汇编要拿它当基底。
  const live = liveCubin(baseUri);
  const revision = live && live.revision;
  const now = documentBaseHash(live, data);
  baseHistory.remember(baseUri.fsPath, data, now, live ? live.image : null);
  if (assembling.has(baseUri.toString())) return;
  const docs = sourceDocsFor(baseUri);
  if (!docs.length) return;
  for (const doc of docs) {
    // 已经对着这份字节了就别动 —— 源码自己汇编那一步，后端回的重绑文本保住了
    // 用户的排版/注释/标号名，这里再重导一遍反而会把它抹平。
    const section = nvsassFS.sectionOf(doc.uri);
    const image = sourceImage(doc.uri, live);
    const sourceVersion = doc.version;
    const res = await emitSource(baseUri, data, section, image, { key: `rebase:${doc.uri.toString()}` });
    if (!res.ok || doc.isClosed || doc.version !== sourceVersion
        || (live && (live.disposed || live.revision !== revision))) continue;
    if (live) rememberContainer(live, res.container);
    baseHistory.remember(baseUri.fsPath, data, res.base, image);
    if (declaredBase(doc.getText()) === res.base) continue;
    if (doc.isDirty) {
      const pick = await vscode.window.showWarningMessage(
        `${path.basename(baseUri.fsPath)} 的内容变了，而 `
        + `${path.basename(doc.uri.path)} 还有没汇编的修改 —— 它编的是旧字节。`,
        { modal: false }, '按新内容重新导出（Ctrl+Z 可撤回我的修改）');
      if (!pick) continue;
    }
    if (doc.isClosed || doc.version !== sourceVersion || assembling.has(baseUri.toString())
        || (live && (live.disposed || live.revision !== revision))) continue;
    if (doc.isDirty) {
      const edit = new vscode.WorkspaceEdit();
      edit.replace(doc.uri, new vscode.Range(
        doc.lineAt(0).range.start,
        doc.lineAt(doc.lineCount - 1).range.end), res.source);
      await vscode.workspace.applyEdit(edit);
    } else {
      nvsassFS.replace(doc.uri, res.source);
    }
  }
}

// 整段汇编回 cubin。诊断走 VS Code 自己的 DiagnosticCollection —— 后端给的
// 是 {line, col, end, msg}，这里只负责映射成 Range，不在扩展里另写一套 parser。
const diagnostics = vscode.languages.createDiagnosticCollection('nvsass');

function baseCubinFor(uri) {
  // 虚拟文档（scheme `nvsass:`）的绑定记在 `nvsassFS` 里，一查就有 —— 文件名
  // 怎么写都不影响。下面的文件名约定只服务于磁盘上真实存在的 `.nvsass`。
  const virt = nvsassFS.baseOf(uri);
  if (virt) return virt;
  // 文件名约定：<cubin 去掉后缀>.<section>.nvsass —— 由“以 SASS 源码打开”生成。
  // section 名自己带点（`.text.f`），切分规则在 V.baseCubinCandidates 里，
  // 这里只负责挑第一个真实存在的；都不存在就回第一个候选，让调用方去报错。
  const cands = V.baseCubinCandidates(uri.fsPath);
  if (!cands.length) return null;
  return vscode.Uri.file(cands.find((p) => fs.existsSync(p)) || cands[0]);
}

async function assembleSourceDoc(doc, { silent = false, saving = false, text = doc.getText() } = {}) {
  // Saving a virtual document runs its transaction in FileSystemProvider.writeFile.
  // A command must not start a second assembly after doc.save() fires the event.
  if (!saving && doc.isDirty) {
    await doc.save();
    return;
  }
  const base = baseCubinFor(doc.uri);
  const key = base && base.toString();
  let locked = false;
  try {
    if (!base) throw new Error('找不到这份源码的基底 cubin（约定文件名 <cubin>.<section>.nvsass）。');
    if (assembling.has(key)) throw new Error('这个 cubin 正在汇编，请稍后重新保存源码。');
    const version = doc.version;
    assertSourceCurrent(doc, text, version);
    assembling.add(key);
    locked = true;
    const live = liveCubin(base);
    const res = live ? await assembleIntoBuffer(doc, base, live, text, version)
                     : await assembleOntoDisk(doc, base, text, version);
    if (!res.ok) {
      diagnostics.set(doc.uri, (res.diagnostics || []).map((d) => new vscode.Diagnostic(
        new vscode.Range(d.line, d.col, d.line, d.end), d.msg,
        vscode.DiagnosticSeverity.Error)));
      throw new Error(res.error || '保存前验证失败。');
    }
    diagnostics.set(doc.uri, []);
    // 源码重绑到刚编出来的那份字节（`.base` 与行尾 `// @0x....`）—— 后端回的文本
    // 保住了用户的排版/注释/标号名，比重新导出一遍强。不重绑的话，下一次汇编又会
    // 撞上「基底对不上」。
    if (!saving && doc.uri.scheme === NVSASS_SCHEME && res.source) {
      nvsassFS.replace(doc.uri, res.source);
    }
    if (doc.uri.scheme === 'file' && res.source && res.source !== text) {
      // Rebind a clean on-disk source without replacing newer editor text.
      // Its file watcher will reload the updated header normally.
      try {
        if (fs.readFileSync(doc.uri.fsPath, 'utf8') === text) {
          writeLocalAtomic(doc.uri, Buffer.from(res.source));
        }
      } catch (e) {
        vscode.window.showWarningMessage(`汇编已完成，但源码头重绑失败：${e.message}`);
      }
    }
    for (const w of res.warnings || []) vscode.window.showWarningMessage(w);
    if (res.unchanged) {
      if (!silent) {
        vscode.window.showInformationMessage(
          `${res.count} 条指令与当前 cubin 逐字节一致，没有改动要写。`);
      }
      return res;
    }
    // 报告要说清楚验过什么、没验什么 —— 「驱动加载得了」不等于「算得对」。
    vscode.window.showInformationMessage(
      live
        ? `已按源码更新 ${path.basename(base.fsPath)} 的缓冲区（Ctrl+S 落盘）：`
          + `${res.summary}`
        : `已写回 ${path.basename(base.fsPath)}：${res.summary}`);
    return res;
  } catch (e) {
    vscode.window.showErrorMessage(`汇编未完成：${e.message}`);
    if (saving) throw e;
    return { ok: false, error: e.message };
  } finally {
    if (locked) assembling.delete(key);
  }
}

/**
 * 缓冲区 -> 缓冲区：拿**打开着的那份 cubin 字节**当基底，把结果收回同一个
 * document。磁盘一个字节不碰 —— 落盘是 cubin 自己 `Ctrl+S` 的事（那一步还要过
 * 保存安全闸）。这正是「两个视图共用一份字节」的落点：源码里的 `.base` 记的就是
 * 这份缓冲区的 hash，两边永远对得上。
 */
async function assembleIntoBuffer(sourceDoc, base, live,
                                  text = sourceDoc.getText(), version = sourceDoc.version) {
  const snapshot = snapshotOf(live);
  const image = sourceImage(sourceDoc.uri, live);
  if (image !== null && !containerFor(live, image)) {
    const res = await emitSource(base, snapshot.data, nvsassFS.sectionOf(sourceDoc.uri), image);
    assertCurrent(live, snapshot);
    assertSourceCurrent(sourceDoc, text, version);
    if (!res.ok) return res;
    rememberContainer(live, res.container);
  }
  const container = containerFor(live, image);
  const liveHash = documentBaseHash(live, snapshot.data, image);
  baseHistory.remember(base.fsPath, snapshot.data, liveHash, image);
  // 源码声明的基底就是缓冲区当前这份，那就是常态；对不上时先看看是不是**我们
  // 自己见过的旧版**（用户在源码里按了 Ctrl+Z，正文连同 `.base` 和行尾的
  // `// @0x....` 一起退回上一版）。是的话就拿那一版当基底 —— 撤销源码顺带把
  // cubin 缓冲区带回去，结果照样是一次可撤销的 `applyWhole()`。找不到才让后端
  // 的冲突闸去报「基底在导出之后被改过」。
  const want = declaredBase(text);
  const now = liveHash;
  const rewound = want && want !== now ? baseHistory.get(base.fsPath, want, image) : null;
  let input = rewound || snapshot.data;
  if (rewound && container && container.embedded) {
    const lo = Number(container.payload_offset);
    const hi = lo + Number(container.payload_size);
    const payload = rewound.subarray(lo, hi);
    if (rewound.length !== snapshot.data.length || baseHash(payload) !== want) {
      throw new Error('旧基底的 image 布局已改变，无法安全恢复源码版本。');
    }
    input = Buffer.from(snapshot.data);
    payload.copy(input, lo);
  }
  if (rewound) {
    vscode.window.showInformationMessage(
      `源码撤销回了 ${want} 那一版，cubin 缓冲区跟着退回去重编（Ctrl+Z 可撤销）。`);
  }
  // 后端要一个能当 ELF 读的基底文件，而我们要给的是**缓冲区**，所以落一个临时
  // 文件（跟 exportPatch 一个路数）；源码走标准输入，不落盘。
  return withTempCubin(input, async (tmp) => {
    const args = [tmp, '--assemble-source', '-', '--payload-only'];
    if (image !== null) args.push('--image', String(image));
    const res = await runScript(base, args, text, { key: `source:${sourceDoc.uri.toString()}` });
    assertCurrent(live, snapshot);
    assertSourceCurrent(sourceDoc, text, version);
    if (res.ok && res.data) {
      const next = resultBytes(res, input);
      rememberContainer(live, res.container);
      if (res.container && image === live.image) live.container = res.container;
      baseHistory.remember(base.fsPath, next, res.base || documentBaseHash(live, next, image), image);
      live.applyWhole(next, `按 .nvsass 源码汇编：${res.count} 条`);
    }
    return res;
  });
}

/**
 * cubin 没在编辑器里开着（单独打开一份磁盘上的 `.nvsass`）时的老路：后端一次
 * 事务 —— 临时文件 + 全量验证 + 原子替换，失败时磁盘一个字节没动。
 */
async function assembleOntoDisk(sourceDoc, base,
                                text = sourceDoc.getText(), version = sourceDoc.version) {
  const original = fs.readFileSync(base.fsPath);
  // Run the full save verification on a private copy. Only commit to the real
  // base after checking both the source version and external file changes.
  return withTempCubin(original, async (tmp) => {
    const args = [tmp, '--assemble-source', '-', '--out', tmp];
    const image = nvsassFS.imageOf(sourceDoc.uri);
    if (image !== null) args.push('--image', String(image));
    const res = await runScript(base, args, text, { key: `source:${sourceDoc.uri.toString()}` });
    if (!res.ok) return res;
    assertSourceCurrent(sourceDoc, text, version);
    if (liveCubin(base) || !fs.readFileSync(base.fsPath).equals(original)) {
      throw new Error('基底在汇编期间被打开或修改，未覆盖，请重试。');
    }
    if (sourceDoc.uri.scheme === 'file' && fs.readFileSync(sourceDoc.uri.fsPath, 'utf8') !== text) {
      throw new Error('源码文件在汇编期间被外部修改，未写回 cubin。');
    }
    writeLocalAtomic(base, fs.readFileSync(tmp));
    return { ...res, written: base.fsPath };
  });
}

// ---------------------------------------------------------------------------
// 源码栏 <-> SASS preview 滚动同步。锚点是行尾的 `// @0x0070`（指令在
// 基底里的段内地址），不是行号 —— 源码插删过指令、或预览开着过滤/只看差异
// 时，行号两边对不上，地址永远对得上。
// ---------------------------------------------------------------------------

function syncEnabled() {
  return cfg().get('scrollSync') !== false;
}

/** 当前可见的、以 `baseUri` 为基底的 `.nvsass` 编辑器。 */
function sourceEditorsFor(baseUri) {
  return vscode.window.visibleTextEditors.filter((ed) => {
    if (ed.document.languageId !== 'nvsass') return false;
    const base = baseCubinFor(ed.document.uri);
    const live = liveCubin(baseUri);
    const image = nvsassFS.imageOf(ed.document.uri);
    return base && base.toString() === baseUri.toString()
      && (image === null || (live && live.image === image));
  });
}

/** 预览滚到了某条指令 -> 把源码栏滚到同一条。 */
function revealSourceAt(baseUri, section, addr) {
  if (!syncEnabled() || Date.now() < scrollSync.until) return;
  for (const ed of sourceEditorsFor(baseUri)) {
    const lines = ed.document.getText().split('\n');
    const bound = nvsassFS.sectionOf(ed.document.uri);
    if (section && bound !== ALL_TEXT_SECTIONS && V.sourceSection(lines) !== section) continue;
    const line = V.sourceLineFor(lines, addr, section);
    if (line < 0) continue;
    scrollSync.until = Date.now() + SYNC_QUIET_MS;
    ed.revealRange(new vscode.Range(line, 0, line, 0),
                   vscode.TextEditorRevealType.AtTop);
  }
}

/** 源码栏滚到了某一行 -> 把预览滚到同一条指令。 */
function syncPreviewFromSource(provider, ed) {
  if (!syncEnabled() || Date.now() < scrollSync.until) return;
  if (ed.document.languageId !== 'nvsass') return;
  const base = baseCubinFor(ed.document.uri);
  if (!base) return;
  const entry = provider.live.get(base.toString());
  if (!entry) return;
  const image = nvsassFS.imageOf(ed.document.uri);
  if (image !== null && image !== entry.doc.image) return;
  const lines = ed.document.getText().split('\n');
  const top = ed.visibleRanges.length ? ed.visibleRanges[0].start.line : 0;
  const section = V.sourceSection(lines, top);
  const addr = V.sourceAddrAt(lines, top, section);
  if (addr === null) return;
  scrollSync.until = Date.now() + SYNC_QUIET_MS;
  entry.panel.webview.postMessage({
    type: 'sync', section, addr });
}

function activate(context) {
  const provider = new Provider(context);
  activeProvider = provider;
  context.subscriptions.push(
    { dispose: () => backend.dispose() },
    vscode.commands.registerCommand('cubinSass.cancelTasks', () => {
      const count = backend.cancelAll();
      vscode.window.showInformationMessage(`已取消 ${count} 个后台任务。`);
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      backend.cancelKey(`source:${doc.uri.toString()}`);
      backend.cancelKey(`rebase:${doc.uri.toString()}`);
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (event.contentChanges.length) {
        backend.cancelKey(`source:${event.document.uri.toString()}`);
        backend.cancelKey(`rebase:${event.document.uri.toString()}`);
      }
    }),
    // `.nvsass` 只活在内存里 —— 见 nvsassfs.js 开头那段。
    vscode.workspace.registerFileSystemProvider(NVSASS_SCHEME, nvsassFS,
      { isCaseSensitive: true }),

    // One source document can contain every kernel.  Folding starts on the
    // `.section .text.<kernel>` line and ends immediately before the next one,
    // mirroring the collapsible kernels in the cubin preview.
    vscode.languages.registerFoldingRangeProvider({ language: 'nvsass' }, {
      provideFoldingRanges(document) {
        const starts = [];
        for (let i = 0; i < document.lineCount; i++) {
          if (/^\s*\.section\s+\.text\S*/.test(document.lineAt(i).text)) starts.push(i);
        }
        return starts.map((start, i) => new vscode.FoldingRange(
          start,
          (i + 1 < starts.length ? starts[i + 1] : document.lineCount) - 1,
          vscode.FoldingRangeKind.Region));
      },
    }),

    vscode.window.registerCustomEditorProvider(VIEW_TYPE, provider, {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: false,
    }),
    vscode.window.registerCustomEditorProvider(HOST_VIEW_TYPE, provider, {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: false,
    }),

    vscode.commands.registerCommand('cubinSass.diff', async () => {
      const entry = provider.active();
      if (!entry) return;
      const target = await pickDiffTarget(entry);
      if (!target) return;
      entry.doc.diffAgainst = target;
      entry.refresh();
    }),

    vscode.commands.registerCommand('cubinSass.clearDiff', () => {
      const entry = provider.active();
      if (!entry) return;
      entry.doc.diffAgainst = null;
      entry.refresh();
    }),

    // 交互式改出来的东西要能喂给命令行批处理，反之亦然
    vscode.commands.registerCommand('cubinSass.exportPatch', async () => {
      const entry = provider.active();
      if (!entry) return;
      const doc = entry.doc;
      if (doc.data.equals(doc.savedData)) {
        vscode.window.showInformationMessage('没有未保存的改动可导出。');
        return;
      }
      // 跟【磁盘上的原文件】比 —— savedData 就是它，不用另找参照
      const snapshot = snapshotOf(doc);
      const res = await withTempCubin(snapshot.savedData, (tmp) =>
        runScript(doc.uri, [doc.uri.fsPath, '--stdin', '--diff', tmp, '--export-patch',
          ...(snapshot.image !== null ? ['--image', String(snapshot.image)] : [])], snapshot.data));
      if (!res.ok) {
        vscode.window.showErrorMessage(`导出 patch 失败：${res.error}`);
        return;
      }
      const dest = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(doc.uri.fsPath.replace(/\.cubin$/, '') + '.patch.json'),
        filters: { 'JSON patch': ['json'] },
      });
      if (!dest) return;
      await vscode.workspace.fs.writeFile(dest, Buffer.from(JSON.stringify(res, null, 2)));
      vscode.window.showInformationMessage(`已导出 ${res.count} 条改动到 ${path.basename(dest.fsPath)}`);
    }),

    vscode.commands.registerCommand('cubinSass.applyPatch', async () => {
      const entry = provider.active();
      if (!entry) return;
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false, openLabel: '应用这份 patch',
        filters: { 'JSON patch / 扫描记录': ['json', 'jsonl'] },
      });
      if (!picked || !picked[0]) return;
      const snapshot = snapshotOf(entry.doc);
      const res = await runScript(entry.doc.uri, [entry.doc.uri.fsPath, '--stdin',
        '--apply-patch', picked[0].fsPath,
        ...(entry.doc.image !== null
          ? ['--image', String(entry.doc.image)] : [])], snapshot.data);
      if (res.error) {
        vscode.window.showErrorMessage(`应用 patch 失败：${res.error}`);
        return;
      }
      // 默认 all-or-nothing —— 有一条没打成就一条都不落进缓冲区，
      // 免得撤销栈上留下半份改动。要半份得显式选。
      const bad = (res.results || []).filter((r) => !r.ok);
      if (bad.length) {
        const pick = await vscode.window.showWarningMessage(
          `${bad.length}/${res.results.length} 条没打上，整份已回滚。`,
          { modal: true, detail: bad.slice(0, 4).map((r) => `+0x${
            Number(r.file_off || 0).toString(16)}: ${r.error}`).join('\n') },
          '只打上能打的那 ' + res.applied + ' 条');
        if (!pick) return;
      }
      if (!isCurrent(entry.doc, snapshot)) {
        vscode.window.showErrorMessage('cubin 在应用 patch 期间已改变，未应用过期结果，请重试。');
        return;
      }
      // 逐条登记成可撤销的编辑，而不是整块换掉 —— 撤销栈上看得见每一条
      for (const r of res.results || []) {
        if (r.ok) {
          entry.doc.applyEdit(r.file_off, Buffer.from(r.bytes, 'hex'),
                              `patch: ${r.sass} @ +0x${r.file_off.toString(16)}`);
        }
      }
      vscode.window.showInformationMessage(
        `打上 ${res.applied} 条改动${bad.length ? `（${bad.length} 条跳过）` : ''}。`);
    }),

    vscode.commands.registerCommand('cubinSass.openSource', async () => {
      const entry = provider.active();
      if (entry) {
        // 以**缓冲区**为准：它就是这个 cubin 当前的真相，webview 的 preview
        // 和这份源码是它的两个视图。汇编也拿同一份字节当基底，所以未保存的
        // 格子改动会原样出现在源码里，`.base` 也自然对得上。
        await openSourceFor(entry.doc.uri, entry.doc.data, entry.doc.image);
        return;
      }
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false, openLabel: '以 SASS 源码打开',
        filters: { cubin: ['cubin'] },
      });
      if (!picked || !picked[0]) return;
      const data = Buffer.from(await vscode.workspace.fs.readFile(picked[0]));
      await openSourceFor(picked[0], data);
    }),

    diagnostics,

    // Virtual sources assemble before their filesystem save completes; real
    // source files are already durable here and assemble after the text save.
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId !== 'nvsass') return;
      if (doc.uri.scheme === NVSASS_SCHEME) {
        // The transaction already succeeded in writeFile(). Notify after the
        // save completes so VS Code can reload the rebound .base and anchors.
        if (!doc.isDirty) {
          const entry = nvsassFS.entries.get(doc.uri.toString());
          if (entry) nvsassFS.replace(doc.uri, entry.content.toString('utf8'));
        }
        return;
      }
      await assembleSourceDoc(doc, { silent: true });
    }),

    vscode.commands.registerCommand('cubinSass.assembleSource', async () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed || ed.document.languageId !== 'nvsass') {
        vscode.window.showInformationMessage('先打开一份 .nvsass 源码。');
        return;
      }
      await assembleSourceDoc(ed.document);
    }),

    vscode.window.onDidChangeTextEditorVisibleRanges(
      (e) => syncPreviewFromSource(provider, e.textEditor)),

    vscode.commands.registerCommand('cubinSass.reopenWith', async () => {
      const uri = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.uri;
      if (uri) await vscode.commands.executeCommand('vscode.openWith', uri, VIEW_TYPE);
    }),

    // Host executables usually have no useful suffix, so a filename selector
    // cannot register them without hijacking every file type.  An explicit
    // picker keeps normal editors untouched and lets the Python side verify
    // that the selected ELF really contains one editable sm_90 cubin.
    vscode.commands.registerCommand('cubinSass.openHostExecutable', async (resource) => {
      let uri = resource && resource.scheme === 'file' ? resource : null;
      if (!uri) {
        const picked = await vscode.window.showOpenDialog({
          canSelectMany: false,
          openLabel: '打开其中的 sm_90 SASS',
          title: '选择 CUDA 可执行文件、共享库或目标文件',
        });
        if (!picked || !picked[0]) return;
        uri = picked[0];
      }
      await vscode.commands.executeCommand('vscode.openWith', uri, HOST_VIEW_TYPE);
    }),
  );
}

module.exports = { activate, deactivate: () => backend.dispose() };
