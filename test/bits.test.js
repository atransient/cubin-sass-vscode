'use strict';
/* `media/bits.js` 的行为测试。
 *
 *     node --test test/
 *
 * pytest 里有一条 `tests/test_bigint_operand.py::test_node_bits_suite` 会把它
 * 带起来，所以跑全仓库测试就已经覆盖到了。
 */
const test = require('node:test');
const assert = require('node:assert');
const B = require('../media/bits.js');

// --- 严格输入解析：非法尾缀不能「读到哪算哪」---------------------------------

test('带非法尾缀的输入一律拒绝', () => {
  for (const s of ['0x10junk', '12abc', '0b1012', '0x', '0b', '', ' ', '1.5',
                   '0x1 0', '1e3', 'RZ8', '--1', '+-1', '0xg']) {
    assert.strictEqual(B.parseInteger(s), null, s);
  }
});

test('三种写法都完整匹配才接受', () => {
  assert.strictEqual(B.parseInteger('0x10'), 16n);
  assert.strictEqual(B.parseInteger('0X10'), 16n);
  assert.strictEqual(B.parseInteger('0b1010'), 10n);
  assert.strictEqual(B.parseInteger('12'), 12n);
  assert.strictEqual(B.parseInteger('-0x10'), -16n);
  assert.strictEqual(B.parseInteger(' 42 '), 42n);
  assert.strictEqual(B.parseInteger('1010'), 1010n);              // 默认按十进制
  assert.strictEqual(B.parseInteger('1010', { bareBinary: true }), 10n);
});

// --- 大位宽：81 / 64 / 56 位都不能掉精度 -------------------------------------

test('81 位槽（WARPSYNC_R_II，段表里最宽的）', () => {
  const v = (1n << 81n) - 1n;
  assert.strictEqual(B.parseOperand('II', '0x' + v.toString(16), 81), v);
  assert.strictEqual(B.parseOperand('II', '0x' + (1n << 81n).toString(16), 81), null);
});

test('64 位地址不掉精度', () => {
  const v = 0xdeadbeefcafef00dn;                 // > 2^53，double 会改值
  assert.strictEqual(B.parseOperand('II', '0xdeadbeefcafef00d', 64), v);
  assert.notStrictEqual(BigInt(Number(v)), v);   // 说明这个数确实在 double 的坑里
});

test('56 位分支偏移的二补码边界', () => {
  const w = 56;
  const span = 1n << 56n;
  assert.strictEqual(B.parseOperand('II', '-1', w), span - 1n);
  assert.strictEqual(B.parseOperand('II', '-' + (span >> 1n).toString(), w), span >> 1n);
  assert.strictEqual(B.parseOperand('II', '-' + ((span >> 1n) + 1n).toString(), w), null);
  assert.strictEqual(B.parseOperand('II', (span - 1n).toString(), w), span - 1n);
  assert.strictEqual(B.parseOperand('II', span.toString(), w), null);
});

// --- 散写回 128 位：不能经过 32 位位运算 --------------------------------------

test('setBits 把 81 位值散进不连续的位', () => {
  const zero = new Array(16).fill(0);
  const bl = [];
  for (let i = 32; i < 113; i++) bl.push(i);       // 81 位，跨过 32/64 位边界
  const v = (1n << 80n) | 1n;
  const bytes = B.setBits(zero, bl, v);
  let back = 0n;
  bl.forEach((bit, i) => {
    back |= BigInt((bytes[bit >> 3] >> (bit & 7)) & 1) << BigInt(i);
  });
  assert.strictEqual(back, v);
});

test('setBits 接受 Number 也接受 BigInt', () => {
  const zero = new Array(16).fill(0);
  assert.deepStrictEqual(B.setBits(zero, [0, 1, 2], 5), B.setBits(zero, [0, 1, 2], 5n));
});

test('cellRaw 宽格读 raw_str，窄格读 raw', () => {
  const wide = (1n << 60n) + 3n;
  // JSON.parse 已经把 raw 改坏了 —— raw_str 才是原值
  assert.strictEqual(B.cellRaw({ raw: Number(wide), raw_str: wide.toString() }), wide);
  assert.strictEqual(B.cellRaw({ raw: 7 }), 7n);
});

// --- 名字型的槽（寄存器/谓词）------------------------------------------------

test('寄存器与谓词槽认名字，认不出就拒绝', () => {
  assert.strictEqual(B.parseOperand('R', 'RZ', 8), 255n);
  assert.strictEqual(B.parseOperand('R', 'R12', 8), 12n);
  assert.strictEqual(B.parseOperand('R', 'R256', 8), null);      // 放不进 8 位
  assert.strictEqual(B.parseOperand('R', 'R12x', 8), null);
  assert.strictEqual(B.parseOperand('P.Guard', '!P0', 4), 8n);
  assert.strictEqual(B.parseOperand('P.Guard', 'PT', 4), 7n);
  assert.strictEqual(B.parseOperand('P.Guard', 'P9', 4), null);   // P7 就是 PT
  assert.strictEqual(B.parseOperand('P.Guard', 'P6', 4), 6n);
});

test('uniform 寄存器槽：URZ 是 UR63，6 位放不下 R 系的 255', () => {
  for (const tag of ['UR', 'UR.Addr', 'UR.CBank', 'UR.Desc']) {
    assert.strictEqual(B.parseOperand(tag, 'URZ', 6), 63n, tag);
    assert.strictEqual(B.parseOperand(tag, 'ur4', 6), 4n, tag);
    assert.strictEqual(B.parseOperand(tag, '0x4', 6), 4n, tag);   // 原始值写法照旧
    assert.strictEqual(B.parseOperand(tag, 'UR64', 6), null, tag);
    assert.strictEqual(B.parseOperand(tag, 'R4', 6), null, tag);  // 不是同一个寄存器堆
  }
  assert.strictEqual(B.parseOperand('R', 'URZ', 8), null);
  assert.strictEqual(B.parseOperand('R.Addr', 'RZ', 8), 255n);
});

test('P 与 UP 谓词槽互不混用', () => {
  assert.strictEqual(B.parseOperand('UP', 'UPT', 3), 7n);
  assert.strictEqual(B.parseOperand('UP', 'UP2', 3), 2n);
  assert.strictEqual(B.parseOperand('UP', 'P2', 3), null);
  assert.strictEqual(B.parseOperand('P', 'UP2', 3), null);
  assert.strictEqual(B.parseOperand('P', 'PT', 3), 7n);
});

test('parseValue：reg / mask / int 三种 kind', () => {
  assert.strictEqual(B.parseValue('reg', 'RZ', 8), 255n);
  assert.strictEqual(B.parseValue('mask', '000101', 6), 5n);     // 纯 0/1 串按二进制
  assert.strictEqual(B.parseValue('mask', '0b000101', 6), 5n);
  assert.strictEqual(B.parseValue('int', '0x4', 4), 4n);
  assert.strictEqual(B.parseValue('int', '0x10junk', 8), null);
  assert.strictEqual(B.parseValue('int', '16', 4), null);        // 4 位放不下
});
