'use strict';
// `basehistory.js`：每个 cubin 最近几份字节快照。要钉住的是那条「Ctrl+Z 之后
// 汇编失败、cubin 缓冲区一个字节没动」的回归 —— 源码正文（连同头里的 `.base`）
// 被撤销回上一版时，那一版的基底字节必须还找得回来。

const test = require('node:test');
const assert = require('node:assert');
const { BaseHistory } = require('../basehistory.js');
const { baseHash, declaredBase } = require('../basehash.js');

const KEY = '/o/hand/base.cubin';
const v = (n) => Buffer.alloc(64, n);

test('存过的那一版，按 hash 找得回来', () => {
  const h = new BaseHistory();
  const hash = h.remember(KEY, v(1));
  assert.equal(hash, baseHash(v(1)));
  assert.ok(h.get(KEY, hash).equals(v(1)));
  // 快照是拷贝：外面再改那块 buffer 也污染不了历史
  const buf = Buffer.alloc(64, 3);
  const hb = h.remember(KEY, buf);
  buf.fill(9);
  assert.ok(h.get(KEY, hb).equals(Buffer.alloc(64, 3)));
});

test('没见过的 hash 回 null —— 真·外部修改仍该撞冲突闸', () => {
  const h = new BaseHistory();
  h.remember(KEY, v(1));
  assert.equal(h.get(KEY, baseHash(v(2))), null);
  assert.equal(h.get('/o/x/other.cubin', baseHash(v(1))), null);  // 不同 cubin 不串
  assert.equal(h.get(KEY, ''), null);
});

test('撤销回上一版：源码声明的旧基底还在，能拿它重编', () => {
  const h = new BaseHistory();
  const v0 = v(0), v1 = v(1);
  // 打开源码（基底 v0）-> 存一次（缓冲区变成 v1，源码重绑到 v1）
  h.remember(KEY, v0);
  h.remember(KEY, v1);
  // 用户在源码里按 Ctrl+Z：正文退回上一版，头里的 `.base` 也跟着退回 v0
  const undone = `.base ${baseHash(v0)}\n[----:B------:R-:W-:-:S01] NOP;    // @0x0000\n`;
  const want = declaredBase(undone);
  assert.notEqual(want, baseHash(v1));            // 与缓冲区对不上
  assert.ok(h.get(KEY, want).equals(v0));         // 但那一版基底还在
});

test('只留最近 N 份，老的淘汰掉', () => {
  const h = new BaseHistory(3);
  const hashes = [1, 2, 3, 4].map((n) => h.remember(KEY, v(n)));
  assert.equal(h.get(KEY, hashes[0]), null);
  for (const hash of hashes.slice(1)) assert.ok(h.get(KEY, hash));
  // get 算「最近用过」：再塞一份被淘汰的是没碰过的那个
  h.get(KEY, hashes[1]);
  const fresh = h.remember(KEY, v(5));
  assert.equal(h.get(KEY, hashes[2]), null);
  assert.ok(h.get(KEY, hashes[1]));
  assert.ok(h.get(KEY, fresh));
});

test('cubin 关掉就丢掉它的快照', () => {
  const h = new BaseHistory();
  const hash = h.remember(KEY, v(1));
  h.forget(KEY);
  assert.equal(h.get(KEY, hash), null);
});

test('host fatbin 可按内嵌 cubin 的已知 hash 保存整份宿主快照', () => {
  const h = new BaseHistory();
  const host = Buffer.from('host-elf-with-cubin');
  h.remember('/o/app', host, 'innercubin123456');
  assert.deepEqual(h.get('/o/app', 'innercubin123456'), host);
  assert.equal(h.get('/o/app', baseHash(host)), null);
});

test('相同 payload hash 在不同 image 上的宿主历史独立，关闭时一起清理', () => {
  const h = new BaseHistory();
  h.remember('/o/app', Buffer.from('first host'), 'same-payload-hash', 0);
  h.remember('/o/app', Buffer.from('second host'), 'same-payload-hash', 1);
  assert.equal(h.get('/o/app', 'same-payload-hash', 0).toString(), 'first host');
  assert.equal(h.get('/o/app', 'same-payload-hash', 1).toString(), 'second host');
  assert.equal(h.get('/o/app', 'same-payload-hash'), null);
  h.forget('/o/app');
  assert.equal(h.get('/o/app', 'same-payload-hash', 1), null);
});
