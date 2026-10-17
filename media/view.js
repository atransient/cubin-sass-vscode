'use strict';
/* Webview 的**纯逻辑**。
 *
 * 这里只有「输入 → 输出」的函数：转义/着色、格子的样式与 tooltip、enum 下拉的
 * 选项表、四种提交的输入校验与错误文案、编辑会话的提交/取消状态机、以及从
 * 扩展宿主收到的消息该显示成什么。**一行 DOM 都不碰**，`main.js` 负责把它们
 * 接到元素上。分出来的理由：INVALID 警示、thin/borrowed 可信度、非法编码提醒
 * 这些提示原先只能靠人眼在 webview 里看，没有一条测试能钉住它们还在不在 ——
 * 现在 `node --test test/` 能测。
 *
 * 浏览器里当普通脚本加载（要排在 `bits.js` 之后、`main.js` 之前），node 里
 * `require('../media/view.js')`。
 */

const B = (typeof module !== 'undefined' && module.exports)
  ? require('./bits.js')
  /* eslint-disable no-undef */
  : { cellRaw, parseValue, parseOperand };
  /* eslint-enable no-undef */

// ---- 渲染 ---------------------------------------------------------------

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

/** 给 POSIX shell 用的单引号转义：文件名里的空格、`$(...)`、反引号都按字面量。 */
function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** 复制给用户粘贴到终端的那条 xxd 命令。 */
function xxdCommand(fileOff, name) {
  return `xxd -s $((0x${fileOff.toString(16)})) -l 16 ${shellQuote(name)}`;
}

/** SASS 着色。故意保守：只认寄存器/立即数/谓词，认不出的原样输出。 */
function color(sass) {
  if (!sass) return '';
  let first = true;
  return esc(sass).replace(
    /(@!?P\d|\bU?R(?:Z|\d+)\b|\bP[T\d]\b|\b0x[0-9a-f]+\b|-?\b\d+\b|[A-Z][A-Z0-9._]{1,})/g,
    (tok) => {
      if (/^@/.test(tok)) return `<span class="pred">${tok}</span>`;
      if (/^U?R(Z|\d+)$|^P[T\d]$/.test(tok)) return `<span class="reg">${tok}</span>`;
      if (/^-?(0x[0-9a-f]+|\d+)$/.test(tok)) return `<span class="imm">${tok}</span>`;
      if (first) { first = false; return `<span class="mn">${tok}</span>`; }
      return tok;
    });
}

/** 格子可信度文案：查看时进 tooltip，编辑时进控件旁的提示。 */
function trustNote(c) {
  if (!c) return '';
  if (c.trust === 'thin') {
    return `⚠ 这个 key 只有 ${c.samples} 条样本，这一格是「样本里恒定」推出来的。`
      + '\n样本少时恒定可能纯属偶然 —— 实测有 const 格其实是操作数槽。';
  }
  if (c.trust === 'borrowed') {
    return '⚠ 这一格是从别的 key 借来的，不是本行的直接证据';
  }
  return '';
}

/** 这一格的取值在段表的非法档里 —— nvdisasm 根本读不出来。 */
function isIllegal(c) {
  return (c.illegal || []).includes(String(B.cellRaw(c)));
}

function bitSpan(c) {
  return c.lo === c.hi ? `${c.lo}` : `${c.lo}:${c.hi}`;
}

/** 一串位号写成人看的样子：连续的写 `105:121`，散的才逐个用 `+` 连。
 *  （控制段那一格 17 位，`105+106+…+121` 会把撤销栏那一行撑爆。） */
function bitsLabel(bitList) {
  const bl = bitList || [];
  if (bl.length <= 1) return String(bl[0] === undefined ? '' : bl[0]);
  const contiguous = bl.every((b, k) => !k || b === bl[k - 1] + 1);
  return contiguous ? `${bl[0]}:${bl[bl.length - 1]}` : bl.join('+');
}

/** 格子的 class 串（不含 `cell` 本身），main.js 直接拼进 HTML。 */
function cellClasses(c) {
  const raw = B.cellRaw(c);
  const dim = !raw && (c.kind === 'enum' || c.kind === 'dc_safe'
                      || c.kind === 'dontcare' || c.kind === 'modifier');
  return [`k-${c.kind}`,
          c.editable ? 'edit' : '',
          (c.trust === 'thin' || c.trust === 'borrowed') ? `weak-${c.trust}` : '',
          isIllegal(c) ? 'bad' : '',
          c.dubious ? 'dubious' : '',
          c.unresolved ? 'unresolved' : '',
          dim ? 'dim' : ''].filter(Boolean).join(' ');
}

/** 格子的 tooltip。所有「这一格别当真」的话都在这里，逐条对应一个来源。 */
function cellTip(c) {
  const bits = c.bit_list && c.bit_list.length > 1
    && c.bit_list.some((b, k) => k && b !== c.bit_list[k - 1] + 1)
    ? `bit ${c.bit_list.join('+')}（低位在前）` : `bit ${bitSpan(c)}`;
  return `${c.kind}${c.tag ? ' ' + c.tag : ''} — ${bits}, raw ${B.cellRaw(c)}`
    + (c.pc_relative ? `\nPC 相对：编码里存的是「相对下一条指令的偏移/`
      + `${c.offset >= 0 ? '+' : ''}${c.offset}」，不是目标地址本身。`
      + '要改目标就点上面的 SASS 文本整条重敲（目标填绝对地址）' : '')
    + (isIllegal(c) ? '\n这个取值 nvdisasm 读不出来（非法编码）' : '')
    + (c.dubious ? '\n⚠ 解得出 ≠ 合法：nvdisasm 读得出、也打印了，但 token 本身'
               + '就是 INVALID* 占位——这不是一条有意义的指令' : '')
    + (c.kind === 'opcode_sel'
      ? '\nopcode 位：改它是换成另一条指令，不是给这条加后缀' : '')
    + (c.unresolved
      ? '\n这个 key 有多张 mode 子表，选择条件未解出 —— 名字未必适用' : '')
    + (trustNote(c) ? `\n${trustNote(c)}` : '')
    + (c.kind === 'ctrl'
      ? '\n整个控制段（stall/yield/wr/rd/wait）挤在这一格里 —— '
        + '要按字段改就点上面那排 chip，那里有字段名' : '')
    + (c.editable ? (c.kind === 'operand'
      ? '\n点一下直接改（寄存器认 RZ/R5，立即数认 0x../0b../十进制，负数按二补码）'
      : c.kind === 'ctrl'
        ? '\n点一下按整段的原始值改（0x../0b../十进制）'
        : '\n点一下从实测取值里选') : '');
}

/** enum 格下拉的选项表：`[{value, label, selected}]`。
 *
 * 四类档次都要能一眼分开：实测取值、**token 本身是 `INVALID*`** 的
 * （dubious：读得出但不是有意义的指令，加 ⚠ 前缀 —— 原生 `<option>`
 * 的样式在 webview 里不可靠，所以标记走文字不走 CSS）、段表的非法档（nvdisasm
 * 读不出）、以及位宽放得下但没标定过的当前值。最后一项是「自定义…」。
 */
function enumOptions(cell) {
  const bl = cellBits(cell);
  const cur = String(B.cellRaw(cell));
  const illegal = (cell.illegal || []).map(String);
  const opts = [];
  const add = (value, label) => opts.push({ value, label, selected: value === cur });
  for (const [raw, name] of Object.entries(cell.values || {})) {
    const bad = String(name).includes('INVALID');
    add(String(raw), `${bad ? '⚠ ' : ''}${name}  (${raw})`
      + (bad ? '，读得出但不是有意义的指令' : ''));
  }
  for (const raw of illegal) add(String(raw), `${raw}  (非法，nvdisasm 读不出)`);
  if (!(cur in (cell.values || {})) && !illegal.includes(cur)) {
    add(cur, `${cur}  (未标定)`);
  }
  opts.push({ value: 'custom', selected: false,
              label: `自定义…  (0..${(1n << BigInt(bl.length)) - 1n})` });
  return opts;
}

/** 格子占的位（低位在前）。段表把一个操作数劈成几段时后端已经并好了。 */
function cellBits(c) {
  return c.bit_list || Array.from({ length: c.hi - c.lo + 1 }, (_, k) => c.lo + k);
}

// ---- 提交前的校验（错误文案就是用户看到的那句） ---------------------------

/** enum 的「自定义…」输入。`{ok, value}` 或 `{ok:false, error}`。 */
function commitEnumCustom(cell, text) {
  const bl = cellBits(cell);
  const v = B.parseValue('int', text, bl.length);
  if (v === null) {
    return { ok: false, error: `bit ${bl.join('+')} 放不下「${text}」（${bl.length} 位）` };
  }
  return { ok: true, value: v, bits: bl };
}

/** operand 格的就地输入。PC 相对的格子在这里被挡住（改分支目标要整条重敲 SASS）。 */
function commitOperand(cell, text) {
  const bl = cellBits(cell);
  if (cell.pc_relative) {
    return { ok: false, blocked: true,
             error: '分支目标是 PC 相对编码，这一格不给直接改 —— 点上面的 SASS 文本'
               + `整条重敲（填绝对地址，现在指向 ${cell.target !== undefined
                   ? '0x' + cell.target.toString(16) : '未知'}）` };
  }
  const tag = cell.tag || '';
  const v = B.parseOperand(tag, text, bl.length);
  if (v === null) {
    return { ok: false,
             error: `${tag || cell.kind || 'operand'} bit ${bl.join('+')}：「${text}」不是 `
               + `${bl.length} 位能放下的值` };
  }
  return { ok: true, value: v, bits: bl };
}

/** 控制段 chip 的输入（`asm.py:FIELDS` 那 12 个字段）。 */
function commitField(field, text) {
  const v = B.parseValue(field.kind, text, field.width);
  if (v === null) {
    return { ok: false, error: `${field.name}: 「${text}」不是 ${field.width} 位能放下的值` };
  }
  return { ok: true, value: v };
}

/** 16 字节字面量。 */
function commitHex(text) {
  const hex = String(text).replace(/[\s,]/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) {
    return { ok: false,
             error: `需要 16 个字节（32 个十六进制字符），收到 ${hex.length / 2} 个字节` };
  }
  return { ok: true, hex };
}

/** 整条 SASS 重敲：空输入和「跟原文一字不差」都不必往后端跑一趟。 */
function commitSass(insn, text) {
  if (!String(text).trim()) return { ok: false, noop: true };
  const same = String(text).trim().replace(/;$/, '').trim() === ((insn && insn.sass) || '');
  if (same) return { ok: false, noop: true };
  return { ok: true, text };
}

/** chip 里现在显示的值该怎么填进输入框。 */
function fieldInitial(field, raw) {
  return field.kind === 'reg' ? (raw === 255 ? 'RZ' : `R${raw}`) : String(raw);
}

// ---- 编辑会话：提交 / 取消 ------------------------------------------------

/** 就地编辑控件的状态机（`inlineEdit`/`enumEdit` 共用）。
 *
 * 只做一件事但必须做对：**提交和取消都只生效一次**。控件是靠 blur 收回的，
 * 回车提交会先触发 commit 再触发 blur，取消路径不许把已提交的值再走一遍，
 * 更不许把值提交两次（那会往撤销栈里压两条一样的编辑）。
 */
function editSession({ onCommit, onCancel }) {
  let done = false;
  return {
    get settled() { return done; },
    finish(commit, value) {
      if (done) return false;
      done = true;
      if (commit) { if (onCommit) onCommit(value); } else if (onCancel) onCancel();
      return true;
    },
  };
}

// ---- 宿主消息 -> 横幅文案 --------------------------------------------------

/** 插入/删除一条指令的结果。失败时**只报错**，不假装做成了。 */
function reflowMessage(m) {
  const res = m.res || {};
  if (!res.ok) return { kind: 'error', text: res.error || '插入/删除没做成' };
  const n = res.moved;
  const reloc = (res.relocated || []).length;
  return { kind: 'info', text: m.op === 'insert'
    ? `插入 ${res.sass}：后面 ${n} 条下移一格，分支重定位 ${reloc} 处`
    : `删掉一条：后面 ${n} 条上移一格，分支重定位 ${reloc} 处` };
}

/** 整条重敲的结果。 */
function assembleMessage(m) {
  const res = m.res || {};
  if (!res.ok) return { kind: 'error', text: res.error };
  if (res.ctrl_inherited) {
    return { kind: 'info',
             text: `已换成 ${res.sass}（模板取自 ${res.template}，控制段沿用原指令）` };
  }
  return null;
}

/** 改完之后 nvdisasm 解不出这条了 —— 编码非法。
 *
 * 不回滚：造非法编码去探边界本来就是这个工具的用途，改动留在缓冲区里。
 * 但**必须说清楚两件事**：这条现在读不出来了，以及 Ctrl+Z 能撤。真正的闸在
 * 保存那一步（`check_save()`：改动过的指令解不出就不许普通保存），前端这句
 * 只是提示，绕不过去也不该绕。
 */
function illegalEncodingMessage(lastEdit, insn) {
  if (!lastEdit || !insn || insn.sass) return null;
  const hint = ctrlHint(insn);
  return { kind: 'error',
           text: `${lastEdit.what} 之后 nvdisasm 解不出这条了 —— `
             + '编码可能非法。改动仍在缓冲区里，Ctrl+Z 可撤销。'
             + (hint ? ` ${hint}` : '') };
}

/** 控制段踩中已知无定义组合时的那句解释（后端 `check_save()` 里有同一条）。
 *
 * yield 和 stall 在页面上是两个独立的 chip，nvdisasm 那边却是**一个 5 位码**：
 * `yield<<4 | stall` 去查 `TABLES_opex_0`，yield=1（不切走）时只有 stall 1..11
 * 有定义（实测 stall 字段只在 1..11 线性）。所以「只改了个 stall
 * 就再也存不进去」是最容易踩的一个洞，报错必须点名另一个字段，否则没人猜得到。
 */
function ctrlHint(insn) {
  const raw = (n) => (insn && insn.ctrl && insn.ctrl[n] ? insn.ctrl[n].raw : undefined);
  const stall = raw('stall');
  if (raw('yield') !== 1 || typeof stall !== 'number') return '';
  if (stall >= 1 && stall <= 11) return '';
  return `yield=1（不切走）时 stall 只有 1..11 有定义，现在是 ${stall}：`
    + 'nvdisasm 把 yield+stall 当一个 5 位码查表，这个组合查不到，'
    + '普通保存也会被保存安全闸挡下。要停这么久就把 yield 也改成 0。';
}

// ---- 过滤 ---------------------------------------------------------------

function match(i, f) {
  if (!f) return true;
  return (i.sass || '').toLowerCase().includes(f)
      || (i.key || '').toLowerCase().includes(f)
      || i.bytes.includes(f.replace(/\s+/g, ''))
      || `0x${i.addr.toString(16).padStart(4, '0')}`.includes(f)
      || `0x${i.file_off.toString(16)}`.includes(f);
}


// ---- 源码 <-> 预览 的滚动同步（`.nvsass` 行 <-> 指令地址）-----------------
// 锚点是 emit_source 写在行尾的 `// @0x0070`（这一行在基底里的原地址，见
// nvisa/model/sass_source.py）。手敲的新行没有这个注释，就往上/往下找最近的
// 一条 —— 同步只要「滚到差不多的地方」，不需要精确到新插入的那一行。

const SRC_ADDR = /\/\/\s*@(0x[0-9a-fA-F]+)/;

/** 源码第 `line` 行（0 基）对应的段内地址；可限制在一个 section 内。 */
function sourceAddrAt(lines, line, section = null) {
  for (let d = 0; d < lines.length; d++) {
    for (const j of (d === 0 ? [line] : [line - d, line + d])) {
      if (j < 0 || j >= lines.length) continue;
      if (section && sourceSection(lines, j) !== section) continue;
      const m = SRC_ADDR.exec(lines[j] || '');
      if (m) return parseInt(m[1], 16);
    }
  }
  return null;
}

/** 段内地址 `addr` 对应的源码行号（0 基）；可限制在一个 section 内。 */
function sourceLineFor(lines, addr, section = null) {
  let best = -1;
  let bestDelta = Infinity;
  for (let i = 0; i < lines.length; i++) {
    if (section && sourceSection(lines, i) !== section) continue;
    const m = SRC_ADDR.exec(lines[i] || '');
    if (!m) continue;
    const d = Math.abs(parseInt(m[1], 16) - addr);
    if (d < bestDelta) { bestDelta = d; best = i; }
    if (d === 0) break;
  }
  return best;
}

/** 某行所属的 `.section <name>`；不传行号时保持旧行为，返回第一个 section。 */
function sourceSection(lines, line = null) {
  if (line === null || line === undefined) {
    for (const l of lines) {
      const m = /^\s*\.section\s+(\S+)/.exec(l || '');
      if (m) return m[1];
    }
    return null;
  }
  for (let i = Math.min(line, lines.length - 1); i >= 0; i--) {
    const m = /^\s*\.section\s+(\S+)/.exec(lines[i] || '');
    if (m) return m[1];
  }
  return null;
}

/** `.nvsass` 文件名 -> 可能的基底 cubin 路径（按可信度排序）。
 *
 * 文件名的约定是 `<cubin 去掉 .cubin>.<section>.nvsass`，而 **section 名自己带
 * 点**（`.text.f`、`.text._Z10fma_kernelPfS_S_`），所以「剥掉最后一段」是错的：
 * `base.text.f.nvsass` 会被剥成 `base.text.cubin`。真正的分界是 `.text` 那一段，
 * 它之前才是基底名。旧版导出的文件名多一个双点（`base..text.f.nvsass`），这里
 * 一并认。后面几个候选是兜底（万一 section 不叫 .text*），调用方挑第一个真实
 * 存在的。
 */
function baseCubinCandidates(fsPath) {
  if (!/\.nvsass$/.test(fsPath)) return [];
  const stem = fsPath.slice(0, -'.nvsass'.length);
  const out = [];
  const push = (p) => { if (!out.includes(p)) out.push(p); };
  const m = /^(.*?)\.\.?text(?:\.|$)/.exec(stem);
  if (m) push(m[1] + '.cubin');
  // 兜底：从最后一个点往前逐段试。
  for (let i = stem.length - 1; i > 0; i--) {
    if (stem[i] === '.') push(stem.slice(0, i) + '.cubin');
  }
  return out;
}

const API = { esc, shellQuote, xxdCommand, color, trustNote, isIllegal, bitSpan, bitsLabel, cellBits,
              cellClasses, cellTip, enumOptions, commitEnumCustom,
              commitOperand, commitField, commitHex, commitSass,
              fieldInitial, editSession, reflowMessage, assembleMessage,
              illegalEncodingMessage, ctrlHint, match,
              sourceAddrAt, sourceLineFor, sourceSection,
              baseCubinCandidates };

if (typeof module !== 'undefined' && module.exports) {
  module.exports = API;
} else {
  // 浏览器里挂成一个命名空间而不是一堆全局函数：`commitField` 这些名字
  // `main.js` 自己也有（它那份管 DOM 和消息），撞名字会静默覆盖。
  globalThis.V = API;
}
