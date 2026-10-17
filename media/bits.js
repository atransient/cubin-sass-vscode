'use strict';
/* 位运算 + 输入解析。
 *
 * 单独摆一个文件是因为这几个函数是**纯的**（不碰 DOM、不碰 vscode API），
 * 于是 node 能直接 require 进来测（`test/bits.test.js`）。
 *
 * 全程 **BigInt**：段表里最宽的 operand 槽 81 位（`WARPSYNC_R_II`），还有
 * 64 位地址、56 位分支偏移。JS 的 `<<`/`|`/`>>>` 是 32 位运算，`Number` 只有
 * 53 位尾数 —— 两条路都会把宽字段悄悄改值，所以这里一位 32 位运算都不用。
 * JSON 传输同理：Python 侧宽过 32 位的格子会额外下发 `raw_str`（十进制字符串），
 * 因为 `JSON.parse` 会把大整数变成 double。
 */

/** 16 字节就是小端的 128 位整数：bit i 落在 byte (i>>3) 的第 (i&7) 位。 */
function bytesToArr(hex) {
  return (String(hex).match(/.{2}/g) || []).map((h) => parseInt(h, 16));
}

/** 连续位段 [f.lo, f.hi] 的取值。控制段字段都很窄，返回 Number。 */
function getField(bytes, f) {
  let v = 0n;
  for (let i = f.hi; i >= f.lo; i--) {
    v = (v << 1n) | BigInt((bytes[i >> 3] >> (i & 7)) & 1);
  }
  return Number(v);
}

/** 按 bit_list 的顺序（低位在前）把取值散写回去 —— 字段可以不连续，
 *  例如 FFMA 的 .FMZ/.FTZ 是 bit 76 与 bit 80 组成的 2 位字段。 */
function setBits(bytes, bitList, value) {
  const b = bytes.slice();
  const v = BigInt(value);
  bitList.forEach((bit, i) => {
    const on = (v >> BigInt(i)) & 1n;
    const idx = bit >> 3;
    const mask = 1 << (bit & 7);
    b[idx] = on ? (b[idx] | mask) : (b[idx] & ~mask);
  });
  return b;
}

function setField(bytes, f, value) {
  const bl = [];
  for (let i = f.lo; i <= f.hi; i++) bl.push(i);
  return setBits(bytes, bl, value);
}

/** file 里的 16 字节 -> nvdisasm 的 enc 串（低 64 位在前，各自大端打印）。 */
function bytesToEnc(bytes) {
  const half = (o) => bytes.slice(o, o + 8).reverse()
    .map((x) => x.toString(16).padStart(2, '0')).join('');
  return half(0) + half(8);
}

/** 一格的原始值。宽字段读 `raw_str`（`raw` 那个 JSON 数字已经不准了）。 */
function cellRaw(cell) {
  return BigInt(cell.raw_str !== undefined ? cell.raw_str : cell.raw);
}

// ---- 严格的数字输入 -------------------------------------------------------
//
// 只认**完整匹配**这三种写法。原来用 `parseInt()`，它读到看不懂的字符就停下
// 并把前面那截当结果：`0x10junk` -> 16、`12abc` -> 12，用户以为自己填错了会
// 被拒绝，实际上悄悄写进去一个别的值。

const HEX = /^[+-]?0[xX][0-9a-fA-F]+$/;
const BIN = /^[+-]?0[bB][01]+$/;
const DEC = /^[+-]?[0-9]+$/;
const BARE_BIN = /^[01]{2,}$/;             // waitmask 那种「纯 0/1 串」的写法

/** 严格数字解析 -> BigInt。看不懂返回 null（不做任何「读到哪算哪」的兜底）。 */
function parseInteger(text, { bareBinary = false } = {}) {
  const s = String(text).trim();
  if (!s) return null;
  const neg = s[0] === '-';
  const body = /^[+-]/.test(s) ? s.slice(1) : s;
  let v;
  if (HEX.test(s)) v = BigInt(body);
  else if (BIN.test(s)) v = BigInt('0b' + body.slice(2));
  else if (bareBinary && BARE_BIN.test(s)) v = BigInt('0b' + s);
  else if (DEC.test(s)) v = BigInt(body);
  else return null;
  return neg ? -v : v;
}

/** 放进 `width` 位：负数按二补码折过去，超范围返回 null。 */
function fit(v, width) {
  if (v === null) return null;
  const span = 1n << BigInt(width);
  if (v < 0n) {
    if (v < -(span >> 1n)) return null;      // 超出二补码能表示的负半边
    v += span;
  }
  return v >= 0n && v < span ? v : null;
}

/** 用户输入 -> 字段原始值（BigInt）。认不出返回 null。 */
function parseValue(kind, text, width) {
  const s = String(text).trim();
  if (!s) return null;
  if (kind === 'reg') {
    if (/^(RZ|rz)$/.test(s)) return fit(255n, width);
    const m = /^[Rr]?(\d+)$/.exec(s);
    return m ? fit(BigInt(m[1]), width) : null;
  }
  return fit(parseInteger(s, { bareBinary: kind === 'mask' }), width);
}

/** 寄存器槽：通用寄存器 RZ = R255（8 位），uniform 寄存器 URZ = UR63（6 位）。
 *  与 `sass_parser._CONST_REG` 同一套规范化。 */
const REG_FILES = [
  { tags: /^R(\.Addr)?$/, prefix: 'R', zero: 255n },
  { tags: /^UR(\.Addr|\.CBank|\.Desc)?$/, prefix: 'UR', zero: 63n },
];

/** 操作数文本 -> 该格的 raw 值（BigInt）。看不懂返回 null。 */
function parseOperand(tag, text, width) {
  const s = String(text).trim();
  if (!s) return null;
  if (tag === 'P.Guard' || tag === 'P' || tag === 'UP') {
    // 谓词槽：低 3 位选 P0-P6/PT，第 4 位是取反。P7 就是 PT，别的数字不是谓词；
    // UP 槽只认 UP0-UP6/UPT，P 槽不认 UP*。
    const prefix = tag === 'UP' ? 'UP' : 'P';
    const m = new RegExp(`^@?(!?)${prefix}(?:([0-6])|(T))$`, 'i').exec(s);
    if (!m) return null;
    return fit(BigInt((m[3] ? 7 : Number(m[2])) | (m[1] ? 8 : 0)), width);
  }
  const reg = REG_FILES.find((r) => r.tags.test(tag));
  if (reg) {
    if (new RegExp(`^${reg.prefix}Z$`, 'i').test(s)) return fit(reg.zero, width);
    const m = new RegExp(`^${reg.prefix}(\\d+)$`, 'i').exec(s);
    if (m) return fit(BigInt(m[1]), width);
    // 原始数字（`5`、`0x5`）照旧认，跟段表里显示的 raw 值对得上
    return fit(parseInteger(s), width);
  }
  // 负立即数按二补码塞进这一格（`asm_spec._set_composite` 是同一条规则）
  return fit(parseInteger(s), width);
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { bytesToArr, getField, setBits, setField, bytesToEnc,
                     cellRaw, parseInteger, fit, parseValue, parseOperand };
}
