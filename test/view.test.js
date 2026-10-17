'use strict';
/* `media/view.js` 的行为测试。
 *
 *     node --test test/
 *
 * pytest 里有一条 `tests/test_view_contract.py::test_node_view_suite` 会把它带
 * 起来，跑全仓库测试就覆盖到了。
 *
 * 覆盖 点名的那几处交互：INVALID 警示、thin/borrowed 提示、operand 输入、
 * 取消、非法编码提示、撤销提示、插入/删除 失败反馈。
 */
const test = require('node:test');
const assert = require('node:assert');
const V = require('../media/view.js');

const cell = (o) => Object.assign({ lo: 10, hi: 12, kind: 'enum', label: 'x',
                                    raw: 1, values: {}, illegal: [] }, o);

// --- INVALID 警示------------------------------------------------

test('token 是 INVALID* 的档在下拉里带 ⚠ 前缀和一句话解释', () => {
  const opts = V.enumOptions(cell({ raw: 0, values: { 0: 'F32', 1: 'INVALID1' } }));
  const bad = opts.find((o) => o.value === '1');
  assert.ok(bad.label.startsWith('⚠ '), bad.label);
  assert.match(bad.label, /读得出但不是有意义的指令/);
  assert.ok(!opts.find((o) => o.value === '0').label.startsWith('⚠ '));
});

test('dubious 的格子在 tooltip 和 class 上都标出来', () => {
  const c = cell({ dubious: true });
  assert.match(V.cellTip(c), /解得出 ≠ 合法/);
  assert.match(V.cellTip(c), /INVALID\* 占位/);
  assert.ok(V.cellClasses(c).split(' ').includes('dubious'));
});

test('段表的非法档要列出来但标清楚 nvdisasm 读不出', () => {
  const c = cell({ raw: 6, values: { 0: 'SB0' }, illegal: ['6'] });
  const o = V.enumOptions(c).find((x) => x.value === '6');
  assert.match(o.label, /非法，nvdisasm 读不出/);
  assert.ok(o.selected, '当前值就是非法档时下拉要选中它');
  assert.ok(V.isIllegal(c) && V.cellClasses(c).split(' ').includes('bad'));
  assert.match(V.cellTip(c), /这个取值 nvdisasm 读不出来（非法编码）/);
});

test('位宽放得下但没标定过的当前值也进下拉，标「未标定」', () => {
  const opts = V.enumOptions(cell({ raw: 5, values: { 0: 'A' }, illegal: ['1'] }));
  assert.match(opts.find((o) => o.value === '5').label, /未标定/);
  const custom = opts[opts.length - 1];
  assert.strictEqual(custom.value, 'custom');
  assert.match(custom.label, /0\.\.7/);            // 3 位 → 上界 7
});

// --- thin / borrowed 可信度提示----------------------------------

test('thin：样本数进文案，class 上也留标记', () => {
  const c = cell({ trust: 'thin', samples: 3 });
  assert.match(V.trustNote(c), /只有 3 条样本/);
  assert.match(V.trustNote(c), /样本里恒定/);
  assert.match(V.cellTip(c), /只有 3 条样本/);
  assert.ok(V.cellClasses(c).split(' ').includes('weak-thin'));
});

test('borrowed：说清楚不是本行的直接证据', () => {
  const c = cell({ trust: 'borrowed' });
  assert.match(V.trustNote(c), /从别的 key 借来的/);
  assert.ok(V.cellClasses(c).split(' ').includes('weak-borrowed'));
});

test('证据充足的格子不出提示', () => {
  assert.strictEqual(V.trustNote(cell({ trust: 'measured' })), '');
  assert.strictEqual(V.trustNote(null), '');
});

// --- operand 输入------------------------------------------------

test('operand 收下寄存器名和三种数字写法', () => {
  const c = cell({ kind: 'operand', tag: 'R', bit_list: [16, 17, 18, 19, 20, 21, 22, 23] });
  assert.strictEqual(V.commitOperand(c, 'R5').value, 5n);
  assert.strictEqual(V.commitOperand(c, 'RZ').value, 255n);
  const imm = cell({ kind: 'operand', tag: 'II', bit_list: [32, 33, 34, 35] });
  assert.strictEqual(V.commitOperand(imm, '0xf').value, 15n);
  assert.strictEqual(V.commitOperand(imm, '-1').value, 15n);   // 二补码
});

test('放不下的值被拒，错误里带 tag、位号和位宽', () => {
  const c = cell({ kind: 'operand', tag: 'II', bit_list: [32, 33, 34, 35] });
  const r = V.commitOperand(c, '0x10');
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /II/);
  assert.match(r.error, /32\+33\+34\+35/);
  assert.match(r.error, /4 位/);
  assert.strictEqual(V.commitOperand(c, '3junk').ok, false);   // 严格解析
});

test('PC 相对的格子拒绝就地改，并指路 分支目标处理', () => {
  const r = V.commitOperand(cell({ kind: 'operand', pc_relative: true, target: 0x1230 }), '0x10');
  assert.strictEqual(r.ok, false);
  assert.ok(r.blocked);
  assert.match(r.error, /0x1230/);
  assert.match(r.error, /整条重敲/);
});

test('enum 的「自定义…」走同一套严格解析', () => {
  const c = cell({ bit_list: [10, 11, 12] });
  assert.strictEqual(V.commitEnumCustom(c, '0b101').value, 5n);
  const r = V.commitEnumCustom(c, '8');
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /放不下/);
  assert.match(r.error, /3 位/);
});

test('控制段字段和 16 字节字面量的校验', () => {
  const f = { name: 'stall', kind: 'int', width: 4 };
  assert.strictEqual(V.commitField(f, '15').value, 15n);
  assert.match(V.commitField(f, '16').error, /不是 4 位能放下的值/);
  assert.strictEqual(V.fieldInitial({ kind: 'reg' }, 255), 'RZ');
  assert.strictEqual(V.fieldInitial({ kind: 'reg' }, 7), 'R7');
  assert.strictEqual(V.commitHex(' 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff ').hex.length, 32);
  assert.match(V.commitHex('0011').error, /需要 16 个字节/);
});

// --- 取消 ------------------------------------------------------------------

test('Esc/失焦取消：一次 onCancel，绝不提交', () => {
  const seen = [];
  const s = V.editSession({ onCommit: (v) => seen.push(['commit', v]),
                            onCancel: () => seen.push(['cancel']) });
  assert.strictEqual(s.finish(false), true);
  assert.strictEqual(s.finish(false), false);       // blur 再来一次，不重复
  assert.strictEqual(s.finish(true, 'R5'), false);  // 取消之后不许再提交
  assert.deepStrictEqual(seen, [['cancel']]);
});

test('回车提交后紧跟的 blur 不会再提交一次', () => {
  const seen = [];
  const s = V.editSession({ onCommit: (v) => seen.push(v), onCancel: () => seen.push('cancel') });
  s.finish(true, 'R5');
  s.finish(false);
  assert.deepStrictEqual(seen, ['R5'], '提交两次会往撤销栈里压两条一样的编辑');
  assert.ok(s.settled);
});

test('整条 SASS：空输入和一字不差都不往后端跑', () => {
  const insn = { sass: 'IMAD R2, R3, R4, RZ' };
  assert.ok(V.commitSass(insn, '').noop);
  assert.ok(V.commitSass(insn, '   ').noop);
  assert.ok(V.commitSass(insn, 'IMAD R2, R3, R4, RZ ;').noop);
  assert.strictEqual(V.commitSass(insn, 'IMAD R2, R3, R4, R9').ok, true);
});

// --- 非法编码提示 / 撤销 ----------------------------------------------------

test('改完 nvdisasm 解不出这条时报警，并告诉用户 Ctrl+Z 能撤', () => {
  const m = V.illegalEncodingMessage({ fileOff: 16, what: 'bit 12 = 3' },
                                     { file_off: 16, sass: '' });
  assert.strictEqual(m.kind, 'error');
  assert.match(m.text, /bit 12 = 3/);
  assert.match(m.text, /nvdisasm 解不出这条了/);
  assert.match(m.text, /Ctrl\+Z 可撤销/);
});

test('解得出就不报警；没有上一次编辑也不报警', () => {
  assert.strictEqual(V.illegalEncodingMessage({ what: 'x' }, { sass: 'NOP' }), null);
  assert.strictEqual(V.illegalEncodingMessage(null, { sass: '' }), null);
});

// --- 插入/删除 的插入/删除反馈 -----------------------------------------------------

test('插入/删除 失败只报错，不假装做成了', () => {
  const m = V.reflowMessage({ op: 'insert', res: { ok: false, error: '尾部没有可吃的 NOP' } });
  assert.strictEqual(m.kind, 'error');
  assert.strictEqual(m.text, '尾部没有可吃的 NOP');
  assert.match(V.reflowMessage({ op: 'delete', res: { ok: false } }).text, /没做成/);
});

test('插入/删除 成功报出挪了几条、重定位了几处', () => {
  const m = V.reflowMessage({ op: 'insert',
    res: { ok: true, sass: 'NOP', moved: 12, relocated: [1, 2] } });
  assert.strictEqual(m.kind, 'info');
  assert.match(m.text, /后面 12 条下移一格/);
  assert.match(m.text, /分支重定位 2 处/);
  assert.match(V.reflowMessage({ op: 'delete', res: { ok: true, moved: 3, relocated: [] } }).text,
               /上移一格.*重定位 0 处/);
});

test('整条重敲：失败报错，成功且控制段继承时说清楚模板来源', () => {
  assert.strictEqual(V.assembleMessage({ res: { ok: false, error: '回环不符' } }).text, '回环不符');
  const m = V.assembleMessage({ res: { ok: true, ctrl_inherited: true,
                                       sass: 'MUFU.RCP R5, R7', template: '段表构造（MUFU_R_R）' } });
  assert.strictEqual(m.kind, 'info');
  assert.match(m.text, /段表构造（MUFU_R_R）/);
  assert.match(m.text, /控制段沿用原指令/);
});

// --- 杂项：转义与过滤 -------------------------------------------------------

test('tooltip / 标签都过转义，段表里的文字不会当 HTML 用', () => {
  assert.strictEqual(V.esc('<b>&"'), '&lt;b&gt;&amp;&quot;');
  assert.match(V.color('IMAD R2, R3, R4, RZ'), /class="mn">IMAD</);
  assert.match(V.color('IMAD R2, R3, R4, RZ'), /class="reg">R2</);
});

test('过滤同时认 sass / key / 字节 / 地址 / 文件偏移', () => {
  const i = { sass: 'IMAD R2, R3, R4, RZ', key: 'IMAD_R_R_R_R',
              bytes: '00112233445566778899aabbccddeeff', addr: 0x30, file_off: 0x230 };
  assert.ok(V.match(i, 'imad'));
  assert.ok(V.match(i, '8899aa'));
  assert.ok(V.match(i, '0x0030'));
  assert.ok(V.match(i, '0x230'));
  assert.ok(V.match(i, ''));
  assert.ok(!V.match(i, 'ffma'));
});

// --- 源码栏 <-> preview 的滚动同步锚点 --------------------------------------

const SRC = [
  '.arch sm_90',
  '.section .text._Z3fmaPf',
  '.base 0123456789abcdef',
  '',
  '.L_0010:',
  '[B------:R-:W1:-:S01] FFMA R9, R2, R5, R9;    // @0x0000',
  '[B------:R-:W-:-:S01] FFMA R4, R2, R5, R9;    // @0x0010',
  '[B------:R-:W-:Y:S00] EXIT;    // @0x0020',
];

test('sourceSection 读得出 .section', () => {
  assert.equal(V.sourceSection(SRC), '.text._Z3fmaPf');
  assert.equal(V.sourceSection(['nothing']), null);
});

test('sourceAddrAt 命中指令行', () => {
  assert.equal(V.sourceAddrAt(SRC, 6), 0x10);
  assert.equal(V.sourceAddrAt(SRC, 7), 0x20);
});

test('sourceAddrAt 在头部/标号行上取最近的一条', () => {
  assert.equal(V.sourceAddrAt(SRC, 4), 0x00);   // 标号行 -> 紧邻的下一条
  assert.equal(V.sourceAddrAt(SRC, 0), 0x00);
  assert.equal(V.sourceAddrAt(['// 没有锚点'], 0), null);
});

test('sourceAddrAt 对手敲的新行（没有 @ 注释）取最近的一条', () => {
  const lines = SRC.slice(0, 6).concat(['[B------:R-:W-:-:S01] MOV R0, R1;'], SRC.slice(6));
  assert.equal(V.sourceAddrAt(lines, 6), 0x00);
});

test('sourceLineFor 反向找行', () => {
  assert.equal(V.sourceLineFor(SRC, 0x10), 6);
  assert.equal(V.sourceLineFor(SRC, 0x20), 7);
  assert.equal(V.sourceLineFor(SRC, 0x18), 6);   // 落在两条之间取最近
  assert.equal(V.sourceLineFor(['x'], 0x10), -1);
});

test('多 section 的相同段内地址按 kernel 区分', () => {
  const lines = SRC.concat([
    '',
    '.section .text.second',
    '[B------:R-:W-:Y:S00] NOP;    // @0x0000',
    '[B------:R-:W-:Y:S00] EXIT;   // @0x0010',
  ]);
  assert.equal(V.sourceSection(lines, lines.length - 1), '.text.second');
  assert.equal(V.sourceLineFor(lines, 0x00, '.text.second'), lines.length - 2);
  assert.equal(V.sourceAddrAt(lines, lines.length - 1, '.text.second'), 0x10);
  assert.equal(V.sourceLineFor(lines, 0x00, '.text._Z3fmaPf'), 5);
});

// --- `.nvsass` -> 基底 cubin 的文件名切分 ------------------------------------
// 回归：原来的 `^(.*)\.[^.]*\.nvsass$` 只剥最后一段，而 section 名自己带点，
// `base.text.f.nvsass` 被剥成 `base.text.cubin` —— 基底找不着，滚动同步和
// 「汇编回 cubin」都会静悄悄失灵。

test('baseCubinCandidates 按 .text 分界', () => {
  assert.equal(V.baseCubinCandidates('/o/base.text.f.nvsass')[0], '/o/base.cubin');
  assert.equal(
    V.baseCubinCandidates('/o/fma.text._Z10fma_kernelPfS_S_.nvsass')[0],
    '/o/fma.cubin');
  assert.equal(V.baseCubinCandidates('/o/y.text.nvsass')[0], '/o/y.cubin');
});

test('baseCubinCandidates 认得旧版多一个点的文件名', () => {
  assert.equal(V.baseCubinCandidates('/o/base..text.f.nvsass')[0], '/o/base.cubin');
});

test('baseCubinCandidates 带点的基底名也切得对', () => {
  assert.equal(V.baseCubinCandidates('/o/a.b.c.text.f.nvsass')[0], '/o/a.b.c.cubin');
});

test('baseCubinCandidates 给出兜底候选', () => {
  const c = V.baseCubinCandidates('/o/base.text.f.nvsass');
  assert.ok(c.includes('/o/base.text.cubin'));   // 老规则的结果留作兜底
  assert.ok(c.length > 1);
});

test('baseCubinCandidates 只认 .nvsass', () => {
  assert.deepEqual(V.baseCubinCandidates('/o/base.cubin'), []);
});

// ---- 控制段：yield 与 stall 是一个 5 位码 --------------------------------
// 「只改了个 stall 就再也保存不了」的回归：页面上两个独立 chip，nvdisasm 那边
// 是一张 32 项的表，yield=1 时只有 stall 1..11 有定义。

const ctrlInsn = (stall, y, sass = '') => ({
  sass, ctrl: { stall: { raw: stall }, yield: { raw: y } },
});

test('ctrlHint 点名 yield：yield=1 时 stall 0 / >=12 无定义', () => {
  for (const s of [0, 12, 15]) {
    assert.match(V.ctrlHint(ctrlInsn(s, 1)), /yield=1.*stall 只有 1\.\.11/);
    assert.match(V.ctrlHint(ctrlInsn(s, 1)), new RegExp(`现在是 ${s}`));
  }
});

test('ctrlHint 对合法组合与 yield=0 闭嘴', () => {
  for (const s of [1, 6, 11]) assert.equal(V.ctrlHint(ctrlInsn(s, 1)), '');
  for (const s of [0, 12, 15]) assert.equal(V.ctrlHint(ctrlInsn(s, 0)), '');
  assert.equal(V.ctrlHint({}), '');                       // 没有 ctrl 也不能炸
  assert.equal(V.ctrlHint(null), '');
});

test('解不出来时把这句挂在提示后面，解得出就不提', () => {
  const edit = { fileOff: 0, what: 'stall = 0' };
  const msg = V.illegalEncodingMessage(edit, ctrlInsn(0, 1));
  assert.equal(msg.kind, 'error');
  assert.match(msg.text, /Ctrl\+Z 可撤销/);
  assert.match(msg.text, /stall 只有 1\.\.11/);
  // 还解得出来的指令根本不该报
  assert.equal(V.illegalEncodingMessage(edit, ctrlInsn(0, 1, 'NOP ;')), null);
  // 解不出来但不是这个原因：只说通用那句
  assert.doesNotMatch(V.illegalEncodingMessage(edit, ctrlInsn(4, 1)).text, /1\.\.11/);
});

// ---- 控制段那一格 --------------------------------------------------------
// 它过去没有 `editable`，页面上却和别的格子长得一样：点下去什么都不发生，而同样
// 这几位上面那排 chip 和 `.nvsass` 改得动。现在它按「填原始值」编辑。

test('bitsLabel 连续位段写成 lo:hi，散的才用 +', () => {
  assert.equal(V.bitsLabel([105, 106, 107]), '105:107');
  assert.equal(V.bitsLabel([76, 80]), '76+80');
  assert.equal(V.bitsLabel([12]), '12');
  assert.equal(V.bitsLabel([]), '');
});

test('ctrl 格的 tooltip 指路到 chip，并说清怎么改', () => {
  const tip = V.cellTip({ lo: 105, hi: 121, kind: 'ctrl', raw: 2040, editable: true });
  assert.match(tip, /stall\/yield\/wr\/rd\/wait/);
  assert.match(tip, /上面那排 chip/);
  assert.match(tip, /按整段的原始值改/);
  assert.match(V.cellClasses({ lo: 105, hi: 121, kind: 'ctrl', raw: 2040, editable: true }),
               /\bedit\b/);
});

test('ctrl 格按原始值提交，错误文案说的是 ctrl 不是 operand', () => {
  const cell = { lo: 105, hi: 121, kind: 'ctrl', raw: 2040, editable: true };
  const ok = V.commitOperand(cell, '0x7f9');
  assert.ok(ok.ok && ok.value === 2041n && ok.bits.length === 17);
  const bad = V.commitOperand(cell, '0x1ffff0');
  assert.ok(!bad.ok);
  assert.match(bad.error, /^ctrl bit/);
});

test('复制的 xxd 命令把文件名按字面量引起来', () => {
  assert.strictEqual(V.xxdCommand(0x520, 'fma.sm_90.cubin'),
    "xxd -s $((0x520)) -l 16 'fma.sm_90.cubin'");
  // 空格、命令替换、单引号都不能被 shell 解释
  assert.strictEqual(V.shellQuote('a b $(id) `x`.cubin'), "'a b $(id) `x`.cubin'");
  assert.strictEqual(V.shellQuote("it's.cubin"), "'it'\\''s.cubin'");
});
