'use strict';
// `.nvsass` 的内存文件系统（scheme `nvsass:`）。
//
// 源码**不落盘**：它只是 cubin 的一个可编辑视图，唯一的真相始终是 cubin 本身。
// 早先的做法是往基底旁边写一个真实的 `<cubin>.<section>.nvsass`，还靠文件名把
// 源码认回基底 —— 工作区里凭空多出文件、谁都不负责删，而且那份文件和 cubin
// 一旦不同步就成了第二份真相。现在改成 FileSystemProvider：
//
//   * document 还是**真正的 TextDocument**，撤销/重做、搜索、多光标、诊断、
//     语法高亮全是 VS Code 原生的（这是当初选文本文档而不是 Webview
//     textarea 的理由，不能丢）；
//   * 内容只在内存里，Ctrl+S 的 `writeFile()` 等汇编事务成功才完成；失败时
//     VS Code 保留 dirty 状态和草稿备份，工作区不产生额外源码文件。
//
// 「源码 -> 基底 cubin」的绑定写在 uri 的 query 里（base、section 和可选 image），
// 不在文件名上：section 名自己带点造成的文件名坑（
// `base..text.f.nvsass` 那个回归）在这条路上根本不存在，而且 uri 自带身份 ——
// 窗口重载后 VS Code 重新打开这个 tab 时，provider 能照着它把源码从 cubin 里
// 重新导一遍（`rehydrate`），不至于变成一个打不开的死 tab。磁盘上真实存在的
// `.nvsass` 仍按老的文件名约定认。

const vscode = require('vscode');
const path = require('path');
const { baseHash, declaredBase } = require('./basehash.js');

const SCHEME = 'nvsass';
const ALL_TEXT_SECTIONS = '__all_text_sections__';

/** uri 里带着「基底 + section」，所以身份不依赖任何一张会丢的表。 */
function uriFor(baseFsPath, section, image = null) {
  if (image !== null && (!Number.isSafeInteger(image) || image < 0)) {
    throw new Error('image 必须是非负整数。');
  }
  const stem = path.basename(baseFsPath).replace(/\.cubin$/, '');
  const shown = section === ALL_TEXT_SECTIONS ? 'all' : section.replace(/^\./, '');
  const name = `${stem}${image === null ? '' : `.image-${image}`}.${shown}.nvsass`;
  return vscode.Uri.from({
    scheme: SCHEME,
    path: `/${name}`,
    query: `base=${encodeURIComponent(baseFsPath)}`
      + `&section=${encodeURIComponent(section)}`
      + (image === null ? '' : `&image=${image}`),
  });
}

/** 从 uri 反解出「基底 + section」；不是这条 scheme 就回 null。 */
function bindingOf(uri) {
  if (!uri || uri.scheme !== SCHEME) return null;
  const q = new Map(uri.query.split('&').filter(Boolean).map((kv) => {
    const i = kv.indexOf('=');
    return [kv.slice(0, i), decodeURIComponent(kv.slice(i + 1))];
  }));
  const base = q.get('base');
  const section = q.get('section');
  const rawImage = q.get('image');
  const image = rawImage === undefined ? null : Number(rawImage);
  if (rawImage !== undefined && (!/^\d+$/.test(rawImage) || !Number.isSafeInteger(image))) return null;
  return base && section ? { base, section, image } : null;
}

class NvsassFS {
  /**
   * @param {(baseUri: vscode.Uri, section: string, image: number|null) => Promise<string|null>} rehydrate
   *   窗口重载之后内存是空的，但 uri 自带「基底 + section」—— 用它把源码从
   *   cubin 里重新导一遍。导不出来就按「文件不存在」处理。
   */
  constructor(rehydrate = null, save = null) {
    this.entries = new Map();          // uri.toString() -> {content, ctime, mtime}
    this._pending = new Map();         // uri.toString() -> current recovery job
    this.rehydrate = rehydrate;
    this.save = save;
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeFile = this._emitter.event;
  }

  // --- 对外：开一份源码 ----------------------------------------------------

  /** 建立/更新「基底 cubin + section」对应的虚拟文档，返回它的 uri。 */
  set(baseUri, section, text, image = null) {
    const uri = uriFor(baseUri.fsPath, section, image);
    const key = uri.toString();
    const old = this.entries.get(key);
    const now = old ? Math.max(Date.now(), old.mtime + 1) : Date.now();
    this._pending.delete(key);
    this.entries.set(key, {
      content: Buffer.from(text, 'utf8'),
      ctime: old ? old.ctime : now,
      mtime: now,
    });
    this._emitter.fire([{
      type: old ? vscode.FileChangeType.Changed : vscode.FileChangeType.Created,
      uri,
    }]);
    return uri;
  }

  /**
   * 汇编成功之后把重绑过的源码换进缓冲区。这不是用户的编辑，所以走 provider
   * 而不是 WorkspaceEdit —— 文档不会因此变脏，也不会往撤销栈里塞一步。
   */
  replace(uri, text) {
    const e = this.entries.get(uri.toString());
    if (!e) return;
    this._pending.delete(uri.toString());
    e.content = Buffer.from(text, 'utf8');
    e.mtime = Math.max(Date.now(), e.mtime + 1);
    this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]);
  }

  /** 这份源码的基底 cubin；不是虚拟文档就回 null。 */
  baseOf(uri) {
    const b = bindingOf(uri);
    return b ? vscode.Uri.file(b.base) : null;
  }

  /** 这份源码是哪个 section；不是虚拟文档就回 null。 */
  sectionOf(uri) {
    const b = bindingOf(uri);
    return b ? b.section : null;
  }

  imageOf(uri) {
    const b = bindingOf(uri);
    return b ? b.image : null;
  }

  // --- FileSystemProvider --------------------------------------------------

  watch() {
    return new vscode.Disposable(() => {});
  }

  async stat(uri) {
    const e = await this._get(uri);
    return {
      type: vscode.FileType.File,
      ctime: e.ctime,
      mtime: e.mtime,
      size: e.content.length,
    };
  }

  readDirectory() {
    return [];
  }

  createDirectory() {}

  async readFile(uri) {
    return (await this._get(uri)).content;
  }

  async writeFile(uri, content) {
    // Rejecting this promise keeps the TextDocument dirty, including when
    // assembly fails. Never acknowledge a save before the cubin accepts it.
    const saved = this.save ? await this.save(uri, Buffer.from(content).toString('utf8')) : null;
    const key = uri.toString();
    const old = this.entries.get(key);
    const now = old ? Math.max(Date.now(), old.mtime + 1) : Date.now();
    this._pending.delete(key);
    this.entries.set(key, {
      content: saved === null || saved === undefined ? Buffer.from(content) : Buffer.from(saved),
      ctime: old ? old.ctime : now,
      mtime: now,
    });
    this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]);
  }

  /** Drop a closed document without reporting a file deletion to VS Code. */
  forget(uri) {
    const key = uri.toString();
    this.entries.delete(key);
    this._pending.delete(key);
  }

  delete(uri) {
    if (!this.entries.has(uri.toString())) {
      throw vscode.FileSystemError.FileNotFound(uri);
    }
    this.forget(uri);
    this._emitter.fire([{ type: vscode.FileChangeType.Deleted, uri }]);
  }

  rename() {
    // 改名毫无意义：绑定关系在 uri 里，不在文件名上。
    throw vscode.FileSystemError.NoPermissions(
      '.nvsass 是 cubin 的内存视图，不能改名；要留一份就「另存为」到磁盘。');
  }

  async _get(uri) {
    const key = uri.toString();
    const e = this.entries.get(key);
    if (e) return e;
    const pending = this._pending.get(key);
    if (pending) return pending.promise;
    const b = bindingOf(uri);
    if (!b || !this.rehydrate) throw vscode.FileSystemError.FileNotFound(uri);
    const job = {};
    this._pending.set(key, job);
    // Defer the callback so concurrent stat/readFile calls see the same job,
    // including when rehydrate throws synchronously.
    job.promise = Promise.resolve().then(async () => {
      try {
        const text = await this.rehydrate(vscode.Uri.file(b.base), b.section, b.image);
        const current = this.entries.get(key);
        if (current) return current;
        // Closing, deleting or reopening the document invalidates this job.
        if (this._pending.get(key) !== job || text === null || text === undefined) {
          throw vscode.FileSystemError.FileNotFound(uri);
        }
        const now = Date.now();
        const entry = { content: Buffer.from(text, 'utf8'), ctime: now, mtime: now };
        this.entries.set(key, entry);
        return entry;
      } finally {
        if (this._pending.get(key) === job) this._pending.delete(key);
      }
    });
    return job.promise;
  }
}

module.exports = { NvsassFS, SCHEME, ALL_TEXT_SECTIONS, uriFor, bindingOf,
                   baseHash, declaredBase };
