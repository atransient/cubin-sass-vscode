'use strict';
// 把 webview 那三个脚本按**真实方式**跑起来（三个独立 classic script，共用一个
// 全局作用域），点一下、敲个值、看发出去的是什么。
//
// 为什么值得单独一份：`view.js`/`bits.js` 的纯函数各自都测得好好的，
// 「点了没反应」却发生在它们之间的接线上 —— 格子有没有 `edit` class、点击派给
// 谁、提交回来的位怎么写。控制段那一格就是这么掉的：它没有 `editable`，点下去
// 掉进 enumEdit 开出一个空下拉，看着就是死的，而同样这几位上面那排 chip 和
// `.nvsass` 源码都改得动。
//
// jsdom 是开发依赖，npm ci 后可运行完整 Webview 行为测试。

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { JSDOM } = require('jsdom');

const MEDIA = path.join(__dirname, '..', 'media');
const skip = false;

/** 一条 LDC 的最小 payload：字段表 + 一条指令（含控制段那一格）。 */
function payload() {
  return {
    revision: 7,
    ok: true, have_nvdisasm: true, name: 'base.cubin', fields: [
      { name: 'stall', block: 'scheduling', lo: 105, hi: 108, width: 4, kind: 'int', note: '' },
      { name: 'yield', block: 'scheduling', lo: 109, hi: 109, width: 1, kind: 'int', note: '' },
    ],
    sections: [{
      name: '.text.f', offset: 1024, size: 16, insns: [{
        addr: 0, file_off: 1024, enc: '000008000000000a', diff: false,
        bytes: '827b01ff000a00000008000000f00f00',
        sass: 'LDC R1, c[0x0][0x28] ;', key: 'LDC_R_cARI',
        ctrl: { stall: { raw: 8, effect: '' }, yield: { raw: 1, effect: '' } },
        cells: [
          { lo: 16, hi: 23, kind: 'operand', raw: 1, tag: 'R', label: 'R1', editable: true },
          { lo: 105, hi: 121, kind: 'ctrl', raw: 2040, tag: '', label: '0x7f8', editable: true },
        ],
      }],
    }],
  };
}

/** 起一页 webview，返回 {window, document, posted}。 */
function page(data = payload()) {
  const scripts = ['bits.js', 'view.js', 'main.js']
    .map((f) => `<script>${fs.readFileSync(path.join(MEDIA, f), 'utf8')}</script>`).join('\n');
  const dom = new JSDOM(`<!doctype html><html><body>
<header><span id="title"></span><input id="filter"><input type="checkbox" id="tCtrl" checked>
<input type="checkbox" id="tBytes" checked><input type="checkbox" id="tCells" checked>
<input type="checkbox" id="tDiffOnly"></header>
<div id="banner" hidden></div><main id="out"></main><div id="hint"></div>
<script>window.__posted = [];
window.acquireVsCodeApi = () => ({ postMessage: (m) => window.__posted.push(m) });
Object.defineProperty(document, 'scrollingElement', { value: document.documentElement });</script>
${scripts}</body></html>`, { runScripts: 'dangerously', pretendToBeVisual: true });
  const w = dom.window;
  for (const id of ['tCtrl', 'tBytes', 'tCells']) {
    w.document.getElementById(id).dispatchEvent(new w.Event('change'));
  }
  w.dispatchEvent(new w.MessageEvent('message', { data: { type: 'data', data } }));
  return { w, doc: w.document, posted: w.__posted };
}

test('取消后台解析后可以再次请求格子分析', () => {
  const data = payload();
  data.cells_loaded = false;
  const { w, doc, posted } = page(data);
  const toggle = doc.getElementById('tCells');
  const request = () => {
    toggle.checked = true;
    toggle.dispatchEvent(new w.Event('change'));
  };
  request();
  w.dispatchEvent(new w.MessageEvent('message', { data: { type: 'backendCancelled' } }));
  request();
  assert.equal(posted.filter((m) => m.type === 'loadCells').length, 2);
  assert.match(doc.getElementById('banner').textContent, /正在按需分析/);
  w.close();
});

/** 点开某个元素、填值、回车；返回发给宿主的那条 edit 消息。 */
function typeInto(w, el, value) {
  el.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  const input = w.document.querySelector('input.inline');
  assert.ok(input, '点下去没开出输入框');
  input.value = value;
  input.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
  return w.__posted.filter((m) => m.type === 'edit').pop();
}

test('控制段的 chip 点得开、改得动', { skip }, () => {
  const { w, doc } = page();
  const chip = [...doc.querySelectorAll('.chip.edit')].find((c) => c.dataset.field === 'stall');
  assert.ok(chip, '没渲染出 stall chip');
  const msg = typeInto(w, chip, '5');
  assert.equal(msg.revision, 7);
  assert.equal(msg.fileOff, 1024);
  // 只动 105:108：f0 -> ea
  assert.equal(msg.bytes, '827b01ff000a00000008000000ea0f00');
  assert.match(msg.label, /^stall = 5 @/);
});

test('控制段那一格也点得开（回归：过去它是死的）', { skip }, () => {
  const { w, doc } = page();
  const cell = [...doc.querySelectorAll('.cell')]
    .find((c) => c.dataset.lo === '105' && c.dataset.off === '1024');
  assert.ok(cell, '没渲染出控制段格子');
  assert.match(cell.className, /\bedit\b/);      // 有 edit 才有指针和点击派发
  const msg = typeInto(w, cell, '0x7f9');
  assert.equal(msg.bytes, '827b01ff000a00000008000000f20f00');   // stall 8 -> 9
  assert.match(msg.label, /bit 105:121 = 2041/);  // 不是 105+106+…+121
});

test('operand 格没被这条改动带偏', { skip }, () => {
  const { w, doc } = page();
  const cell = [...doc.querySelectorAll('.cell')]
    .find((c) => c.dataset.lo === '16' && c.dataset.off === '1024');
  const msg = typeInto(w, cell, 'R7');
  assert.equal(msg.bytes, '827b07ff000a00000008000000f00f00');
});

test('轻量首屏在用户勾选格子时才向宿主请求完整分析', { skip }, () => {
  const data = payload();
  data.cells_loaded = false;
  delete data.sections[0].insns[0].key;
  delete data.sections[0].insns[0].cells;
  const { w, doc, posted } = page(data);
  const toggle = doc.getElementById('tCells');
  toggle.checked = false;
  toggle.dispatchEvent(new w.Event('change'));
  toggle.checked = true;
  toggle.dispatchEvent(new w.Event('change'));
  assert.equal(posted.filter((m) => m.type === 'loadCells').length, 1);
});

test('大段首屏只渲染 300 条，点继续显示再追加下一页', { skip }, () => {
  const data = payload();
  const base = data.sections[0].insns[0];
  data.sections[0].insns = Array.from({ length: 305 }, (_, n) => ({
    ...base, addr: n * 16, file_off: 1024 + n * 16,
  }));
  data.sections[0].size = 305 * 16;
  const { w, doc } = page(data);
  assert.equal(doc.querySelectorAll('tr.insn').length, 300);
  assert.match(doc.querySelector('.load-more').textContent, /300 \/ 305/);
  doc.querySelector('.load-more-btn').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.equal(doc.querySelectorAll('tr.insn').length, 305);
  assert.equal(doc.querySelector('.load-more'), null);
});

test('多 kernel 默认只展开第一个，点击摘要再按需渲染另一个', { skip }, () => {
  const data = payload();
  const second = structuredClone(data.sections[0]);
  second.name = '.text.second';
  second.offset = 2048;
  second.insns[0].file_off = 2048;
  second.insns[0].sass = 'NOP ;';
  data.sections.push(second);
  const { w, doc } = page(data);

  const kernels = doc.querySelectorAll('details.kernel');
  assert.equal(kernels.length, 2);
  assert.equal(kernels[0].open, true);
  assert.equal(kernels[1].open, false);
  assert.equal(doc.querySelectorAll('tr.insn').length, 1);

  kernels[1].querySelector('summary').dispatchEvent(
    new w.MouseEvent('click', { bubbles: true, cancelable: true }));
  assert.equal(doc.querySelectorAll('details.kernel')[1].open, true);
  assert.equal(doc.querySelectorAll('tr.insn').length, 2);
});

test('过滤时自动展开有命中的 kernel，并隐藏无命中的摘要', { skip }, async () => {
  const data = payload();
  const second = structuredClone(data.sections[0]);
  second.name = '.text.second';
  second.offset = 2048;
  second.insns[0].file_off = 2048;
  second.insns[0].sass = 'NOP ;';
  data.sections.push(second);
  const { w, doc } = page(data);
  const filter = doc.getElementById('filter');
  filter.value = 'NOP';
  filter.dispatchEvent(new w.Event('input', { bubbles: true }));
  await new Promise((resolve) => w.setTimeout(resolve, 140));

  const kernels = doc.querySelectorAll('details.kernel');
  assert.equal(kernels.length, 1);
  assert.equal(kernels[0].dataset.sec, '.text.second');
  assert.equal(kernels[0].open, true);
  assert.equal(doc.querySelectorAll('tr.insn').length, 1);
});
