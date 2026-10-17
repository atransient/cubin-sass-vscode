'use strict';
// `nvsassfs.js`：`.nvsass` 的内存文件系统。要钉住的三件事 ——
//   1. 源码不落盘，同一个（cubin, section）永远是同一个缓冲区；
//   2. 「源码 -> 基底」的绑定在 uri 里，文件名怎么写都不影响（老的文件名切分
//      在 section 名自带点时会认错基底，见 view.test.js 那组回归）；
//   3. 内存空了（窗口重载）能照着 uri 把源码从 cubin 重新导出来。
//
// 扩展宿主跑不起来，所以用一个最小的 `vscode` 桩把模块加载进来。

const test = require('node:test');
const assert = require('node:assert');
const Module = require('node:module');

const stub = {
  Uri: {
    from: ({ scheme, path, query }) => mkUri(scheme, path, query || ''),
    file: (p) => mkUri('file', p, ''),
    parse: (s) => {
      const m = /^([^:]+):([^?]*)(?:\?(.*))?$/.exec(s);
      return mkUri(m[1], m[2], m[3] || '');
    },
  },
  EventEmitter: class {
    constructor() { this.listeners = []; this.event = (f) => this.listeners.push(f); }
    fire(e) { for (const f of this.listeners) f(e); }
  },
  Disposable: class { constructor(f) { this.dispose = f; } },
  FileType: { File: 1 },
  FileChangeType: { Changed: 1, Created: 2, Deleted: 3 },
  FileSystemError: {
    FileNotFound: (u) => new Error(`FileNotFound: ${u}`),
    NoPermissions: (m) => new Error(`NoPermissions: ${m}`),
  },
};

function mkUri(scheme, p, query) {
  return {
    scheme,
    path: p,
    query,
    fsPath: p,
    toString: () => `${scheme}:${p}${query ? `?${query}` : ''}`,
  };
}

const load = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'vscode') return stub;
  return load.call(this, request, ...rest);
};
const { ALL_TEXT_SECTIONS, NvsassFS, bindingOf } = require('../nvsassfs.js');
Module._load = load;
const { baseHash, declaredBase } = require('../basehash.js');

const BASE = stub.Uri.file('/o/hand/base.cubin');
const SEC = '.text._Z10fma_kernelPfS_S_';

test('源码只在内存里，同一个 (cubin, section) 复用同一个 uri', async () => {
  const fs = new NvsassFS();
  const a = fs.set(BASE, SEC, 'one\n');
  const b = fs.set(BASE, SEC, 'two\n');
  assert.equal(a.toString(), b.toString());
  assert.equal(String(await fs.readFile(a)), 'two\n');
  // 文件名只是给 tab 看的；换个 section 就是另一份文档
  assert.match(a.path, /base\.text\._Z10fma_kernelPfS_S_\.nvsass$/);
  assert.notEqual(fs.set(BASE, '.text.other', 'x').toString(), a.toString());
});

test('全部 kernel 的虚拟文档使用简短 tab 名并保留绑定', () => {
  const fs = new NvsassFS();
  const uri = fs.set(BASE, ALL_TEXT_SECTIONS, '.arch sm_90\n');
  assert.match(uri.path, /base\.all\.nvsass$/);
  assert.equal(fs.sectionOf(uri), ALL_TEXT_SECTIONS);
});

test('基底绑定在 uri 里，不靠文件名切分', () => {
  const fs = new NvsassFS();
  const uri = fs.set(BASE, SEC, '');
  assert.equal(fs.baseOf(uri).fsPath, '/o/hand/base.cubin');
  assert.equal(fs.sectionOf(uri), SEC);
  // 同名 cubin 在不同目录下不会串
  const other = fs.set(stub.Uri.file('/o/x/base.cubin'), SEC, '');
  assert.notEqual(other.toString(), uri.toString());
  assert.equal(fs.baseOf(other).fsPath, '/o/x/base.cubin');
  // 磁盘上的普通文件不归它管
  assert.equal(fs.baseOf(stub.Uri.file('/o/base.text.f.nvsass')), null);
  assert.equal(bindingOf(stub.Uri.file('/o/a.nvsass')), null);
});

test('同一宿主相同 section 的不同 image 有独立源码身份，重载后保留选择', async () => {
  const asked = [];
  const fs = new NvsassFS(async (base, section, image) => {
    asked.push([base.fsPath, section, image]);
    return `image ${image}`;
  });
  const zero = fs.set(BASE, SEC, 'first', 0);
  const one = fs.set(BASE, SEC, 'second', 1);
  assert.notEqual(zero.toString(), one.toString());
  assert.match(one.path, /image-1/);
  assert.equal(fs.imageOf(zero), 0);
  assert.equal(fs.imageOf(one), 1);
  assert.equal(fs.imageOf(fs.set(BASE, SEC, 'legacy')), null);
  fs.entries.clear();
  assert.equal(String(await fs.readFile(one)), 'image 1');
  assert.deepEqual(asked, [[BASE.fsPath, SEC, 1]]);
  for (const value of ['', '-1', 'NaN', '1.5', '9007199254740992']) {
    assert.equal(bindingOf({ scheme: 'nvsass', query: `base=x&section=y&image=${value}` }), null);
  }
});

test('Ctrl+S 写进内存，随后能原样读回来', async () => {
  const fs = new NvsassFS();
  const uri = fs.set(BASE, SEC, 'old\n');
  const seen = [];
  fs.onDidChangeFile((evs) => seen.push(evs[0].type));
  await fs.writeFile(uri, Buffer.from('new\n', 'utf8'));
  assert.equal(String(await fs.readFile(uri)), 'new\n');
  assert.equal((await fs.stat(uri)).size, 4);
  assert.deepEqual(seen, [stub.FileChangeType.Changed]);
});

test('保存等待汇编，失败时不接受源码也不发送成功变更事件', async () => {
  let reject;
  const pending = new Promise((_resolve, fail) => { reject = fail; });
  const fs = new NvsassFS(null, async () => pending);
  const uri = fs.set(BASE, SEC, 'old\n');
  const seen = [];
  fs.onDidChangeFile((evs) => seen.push(evs));
  const save = fs.writeFile(uri, Buffer.from('invalid\n'));
  const failure = assert.rejects(save, /assembly failed/);
  assert.equal(String(await fs.readFile(uri)), 'old\n');
  reject(new Error('assembly failed'));
  await failure;
  assert.equal(String(await fs.readFile(uri)), 'old\n');
  assert.equal(seen.length, 0);
});

test('同长度源码连续重绑仍推进 mtime，让保存后的 .base 更新能被重新加载', async () => {
  const fs = new NvsassFS();
  const uri = fs.set(BASE, SEC, 'base A');
  fs.entries.get(uri.toString()).mtime = Date.now() + 1000;
  const before = (await fs.stat(uri)).mtime;
  fs.replace(uri, 'base B');
  const replaced = (await fs.stat(uri)).mtime;
  assert.ok(replaced > before);
  await fs.writeFile(uri, Buffer.from('base C'));
  assert.ok((await fs.stat(uri)).mtime > replaced);
});

test('内存空了就照着 uri 从 cubin 重新导一遍', async () => {
  const asked = [];
  const fs = new NvsassFS(async (baseUri, section) => {
    asked.push([baseUri.fsPath, section]);
    return '.arch sm_90\n';
  });
  const uri = fs.set(BASE, SEC, 'x\n');
  fs.entries.clear();                       // 模拟窗口重载
  assert.equal(String(await fs.readFile(uri)), '.arch sm_90\n');
  assert.deepEqual(asked, [['/o/hand/base.cubin', SEC]]);
  await fs.readFile(uri);
  assert.equal(asked.length, 1, '导出过一次就该进缓存');
});

test('导不出来（cubin 没了）就是文件不存在，不是空文档', async () => {
  const fs = new NvsassFS(async () => null);
  const uri = fs.set(BASE, SEC, 'x\n');
  fs.entries.clear();
  await assert.rejects(() => fs.readFile(uri), /FileNotFound/);
});

// --- `.base` 一致性：源码头里的 hash 必须等于磁盘上基底的 hash ---------------
// 「第一次能存、第二次报基底对不上」就是这条不变量破了。前端靠它判断「这份源码
// 是不是已经对着磁盘上这一份了」，所以定义必须和后端一字不差（同一个 sha256
// 前 16 位）—— 由 tests/test_view_contract.py 钉住两边。

test('baseHash 就是 sha256 的前 16 位十六进制', () => {
  assert.equal(baseHash(Buffer.from('')),
               require('crypto').createHash('sha256').update('')
                 .digest('hex').slice(0, 16));
  assert.equal(baseHash(Buffer.from('abc')).length, 16);
  assert.notEqual(baseHash(Buffer.from('a')), baseHash(Buffer.from('b')));
});

test('declaredBase 只认头部那条 .base 指令', () => {
  const src = '.arch sm_90\n.section .text.f\n.base a61d97ed35b237e7\n\n'
    + '[B------:R-:W-:-:S01] NOP;    // @0x0000\n';
  assert.equal(declaredBase(src), 'a61d97ed35b237e7');
  assert.equal(declaredBase('.arch sm_90\n'), '');
  // 指令行里出现 `.base` 字样不算（行首才算）
  assert.equal(declaredBase('[B------:R-:W-:-:S01] NOP;  // .base deadbeef\n'), '');
});
