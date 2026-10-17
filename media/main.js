'use strict';
/* eslint-env browser */
const vscode = acquireVsCodeApi();

const $ = (id) => document.getElementById(id);
const out = $('out');
const banner = $('banner');

let state = {
  data: null, showBytes: true, showCtrl: true, showCells: false,
  diffOnly: false, filter: '',
  openSections: new Set(), renderLimits: new Map(), cellsLoading: false,
  fields: [],   // python 下发的字段位置表，前端不硬编码任何 bit
};
const PAGE_SIZE = 300;

function postMutation(message) {
  vscode.postMessage({ ...message, revision: state.data.revision });
}

// ---- 位运算 / 输入解析 / 纯逻辑 ------------------------------------------
// 位运算在 media/bits.js（bytesToArr / getField / setBits / setField /
// bytesToEnc / cellRaw / parseValue / parseOperand），全程 BigInt —— 段表里最宽
// 的 operand 槽 81 位，32 位位运算和 double 都放不下。
// 渲染文案、格子样式/tooltip、下拉选项、提交校验、编辑会话、宿主消息的文案
// 在 media/view.js。两边都是纯函数，`node --test` 直接测；这个文件里
// 只剩 DOM 和消息收发。

/* eslint-disable no-undef */   // bits.js / view.js 是同一页里先加载的脚本
// view.js is loaded as a classic script and its helper declarations remain
// global. Alias the imports here so they do not collide with those declarations
// (`const esc = ...` would make the whole webview fail before rendering).
const { esc: viewEsc, color: viewColor, cellClasses: viewCellClasses,
        cellTip: viewCellTip, bitSpan: viewBitSpan, trustNote: viewTrustNote } = V;

// ---- 渲染 ---------------------------------------------------------------

const IDLE = { wrbar: 7, rdbar: 7, waitmask: 0, yield: 1 };

function chips(i) {
  const bytes = bytesToArr(i.bytes);
  return state.fields.map((f) => {
    const raw = getField(bytes, f);
    const shown = f.name.startsWith('reuse.') ? (raw ? f.name.slice(-1) : '-') : raw;
    const idle = IDLE[f.name] === raw || (f.name.startsWith('reuse.') && !raw);
    const eff = (i.ctrl[f.name] && i.ctrl[f.name].effect) || f.note || '';
    return `<span class="chip edit ${idle ? 'idle' : ''}"`
      + ` data-off="${i.file_off}" data-field="${viewEsc(f.name)}"`
      + ` title="${viewEsc(eff)}\nbit ${f.lo}:${f.hi} — 点一下改">`
      + `${viewEsc(f.name)}=${viewEsc(shown)}</span>`;
  }).join('');
}

function cellsRow(i) {
  if (!i.cells) {
    return '<div class="cells none">segtable 认不出这条的 InsKey —— '
      + '上面的控制段解码仍然有效（那部分是通用骨架，不依赖 key）。</div>';
  }
  const items = i.cells.map((c) =>
    `<span class="cell ${viewCellClasses(c)}"`
    + ` data-off="${i.file_off}" data-lo="${c.lo}" data-hi="${c.hi}"`
    + ` title="${viewEsc(viewCellTip(c))}"><b>${viewBitSpan(c)}</b> ${viewEsc(c.label || '·')}</span>`);
  return `<div class="cells">${items.join('')}</div>`;
}

function bytesRow(i) {
  // 按 nvdisasm 的两个 64 位半字分组（低 64 位在前）
  const b = i.bytes.match(/.{2}/g) || [];
  return `<span class="hex edit" data-off="${i.file_off}" title="点一下直接改这 16 个字节">`
    + `${b.slice(0, 8).join(' ')}  ${b.slice(8).join(' ')}</span>`;
}

function render() {
  const d = state.data;
  if (!d) return;

  $('title').innerHTML = viewEsc(d.name)
    + (d.dirty ? '<span class="dirty" title="有未保存的修改，Ctrl+S 落盘">●</span>' : '')
    + (d.experimental ? '<span class="experimental" title="上次落盘走的是实验性保存：'
        + '文件里有 nvdisasm 解不出来的编码">实验性</span>' : '')
    + (d.diffName ? `<span class="diff-tag">对比 ${viewEsc(d.diffName)}（高亮=字节不同）</span>` : '');

  if (!d.ok) {
    banner.hidden = false;
    banner.className = '';
    banner.textContent = d.error + (d.hint ? `\n\n${d.hint}` : '');
    out.innerHTML = '';
    return;
  }
  if (!d.have_nvdisasm) {
    banner.hidden = false;
    banner.className = 'info';
    banner.textContent = 'nvdisasm 没跑出结果（不在 PATH，或这个 cubin 的 arch 它不认）——'
      + '下面只有字节和控制段解码。';
  } else {
    banner.hidden = true;
  }

  const f = state.filter.trim().toLowerCase();
  const parts = [];

  for (const sec of d.sections) {
    const visible = sec.insns.filter((i) => {
      if (state.diffOnly && !i.diff) return false;
      return V.match(i, f);
    });
    if (!visible.length) continue;

    // 搜索和“只看差异”是临时视图：自动展开命中的 kernel，但不污染用户原来
    // 手动展开/收起的状态。普通视图默认只展开第一个 kernel。
    const open = state.openSections.has(sec.name) || Boolean(f) || state.diffOnly;
    const rows = [];
    const limit = state.renderLimits.get(sec.name) || PAGE_SIZE;
    if (open) {
      for (const i of visible.slice(0, limit)) {
        const addr = `0x${i.addr.toString(16).padStart(4, '0')}`;
        rows.push(
          `<tr class="insn ${i.diff ? 'diff' : ''}"`
          + ` data-addr="${i.addr}" data-sec="${viewEsc(sec.name)}">`
          + `<td class="addr" data-xxd="${viewEsc(V.xxdCommand(i.file_off, d.name))}"`
          + ` title="点一下复制 xxd 命令">/*${addr}*/</td>`
          + `<td class="off">+0x${i.file_off.toString(16)}`
          // 整行的插入/删除。段大小不变 —— 插入吃掉尾部一条填充 NOP，
          // 删除在末尾补一条；分支目标与 .nv.info 的指令偏移由 python 侧重定位。
          + `<span class="reflow"><b class="ins" data-off="${i.file_off}"`
          + ` title="在这一行插入一条指令（后面整体下移一格，吃掉尾部一条 NOP）">+</b>`
          + `<b class="del" data-off="${i.file_off}"`
          + ` title="删掉这一行（后面整体上移一格，末尾补 NOP）">−</b></span></td>`
          + `<td class="sass ${i.sass ? '' : 'empty'}" data-off="${i.file_off}"
               title="点击编辑整条 SASS；回车提交，Esc 取消">`
          + `${i.sass ? viewColor(i.sass) : '(未反汇编)'}`
          + (i.key ? `<span class="inskey" title="segtable 认出的 InsKey">${viewEsc(i.key)}</span>` : '')
          + `</td>`
          + `</tr>`);
        if (state.showBytes || state.showCtrl || state.showCells) {
          rows.push(
            `<tr class="detail ${i.diff ? 'diff' : ''}"><td></td><td></td><td>`
            + (state.showBytes ? `<div class="bytes">${bytesRow(i)}</div>` : '')
            + (state.showCtrl ? `<div class="ctrl">${chips(i)}</div>` : '')
            + (state.showCells ? cellsRow(i) : '')
            + `</td></tr>`);
        }
      }
    }

    const count = visible.length === sec.insns.length
      ? `${sec.insns.length} 条`
      : `${visible.length} / ${sec.insns.length} 条`;
    const more = open && rows.length && visible.length > limit
      ? `<div class="load-more"><button class="load-more-btn" data-sec="${viewEsc(sec.name)}">继续显示</button>`
        + `<span>已显示 ${Math.min(limit, visible.length)} / ${visible.length} 条</span></div>`
      : '';
    parts.push(
      `<details class="kernel" data-sec="${viewEsc(sec.name)}"${open ? ' open' : ''}>`
      + `<summary class="kernel-summary" title="${viewEsc(sec.name)}">`
      + `<span class="kernel-name">${viewEsc(sec.name)}</span>`
      + `<span class="meta">文件偏移 0x${sec.offset.toString(16)}`
      + `　大小 0x${sec.size.toString(16)}　${count}</span></summary>`
      + (open ? `<table>${rows.join('')}</table>${more}` : '')
      + `</details>`);
  }

  out.innerHTML = parts.join('')
    || `<div class="empty-note">${state.diffOnly && f === ''
        ? '两个 cubin 逐字节相同。'
        : '没有匹配的指令。'}</div>`;
}

// ---- 编辑 ---------------------------------------------------------------

function insnAt(fileOff) {
  for (const sec of state.data.sections) {
    for (const i of sec.insns) if (i.file_off === fileOff) return i;
  }
  return null;
}

/** 证据不足的格子（trust=thin/borrowed）在编辑时把可信度文案摆到
 * 输入框/下拉框旁边。不阻塞操作，只是提醒「这一格的位置/宽度是弱证据推出来的，
 * 编辑结果可能不是你以为的那个字段」—— 查看时这句话在 tooltip 里，但编辑时
 * 控件已经把格子替换掉了，tooltip 也就跟着没了，正是最需要看到它的时候。
 * 返回一个撤下提示的函数（控件收回时调用）。 */
function attachTrustHint(ctrl, cell) {
  const note = cell ? viewTrustNote(cell) : '';
  if (!note) return () => {};
  const tip = document.createElement('span');
  tip.className = 'trust-hint';
  tip.textContent = note.replace(/\n/g, ' ');
  tip.title = note;
  ctrl.after(tip);
  return () => tip.remove();
}

/** 就地开一个输入框，回车提交、Esc 取消。 */
function inlineEdit(el, initial, onCommit, cell, options = {}) {
  const input = document.createElement('input');
  input.className = 'inline';
  input.value = initial;
  input.size = Math.max(initial.length + 1, 4);
  // SASS lives in a table cell. Replacing the whole <td> with an <input>
  // leaves an invalid <tr><input>...</tr> tree, and Chromium may move/remove
  // that input instead of displaying it. Keep the cell and replace only its
  // contents; ordinary inline chips can still be replaced as before.
  const tableCell = String(el.tagName || '').toLowerCase() === 'td';
  const keepOnCommit = Boolean(options.keepOnCommit);
  const oldHTML = tableCell ? el.innerHTML : null;
  if (tableCell) {
    el.textContent = '';
    el.appendChild(input);
  } else {
    el.replaceWith(input);
  }
  // The table uses delegated click handling. Without stopping propagation,
  // clicking inside this newly-created input reaches the table handler again,
  // recreates the input, and resets the caret/selection instead of placing the
  // mouse cursor where the user clicked.
  input.addEventListener('click', (e) => e.stopPropagation());
  const dropHint = attachTrustHint(input, cell);
  input.focus();
  input.select();
  const session = V.editSession({
    onCommit: (v) => onCommit(v),
    onCancel: () => render(),      // 取消：控件收回、什么都不提交、重画回原样
  });
  const finish = (commit) => {
    const v = input.value;
    if (session.settled) return;
    dropHint();
    // For a whole-SASS edit the host must assemble asynchronously. Keep the
    // input in place until the host confirms success; otherwise a failed
    // assembly looks exactly like an edit that was ignored.
    if (!(commit && keepOnCommit)) {
      if (tableCell) el.innerHTML = oldHTML;
      else input.replaceWith(el);
    }
    session.finish(commit, v);
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') finish(true);
    else if (e.key === 'Escape') finish(false);
  });
  input.addEventListener('blur', () => finish(false));
}

/** enum 格：就地开一个 select，选项来自段表枚举出的取值。 */
function enumEdit(el, fileOff, lo, hi) {
  const insn = insnAt(fileOff);
  const cell = (insn.cells || []).find((c) => c.lo === lo && c.hi === hi);
  if (!cell) return;
  const sel = document.createElement('select');
  sel.className = 'inline';
  // 选项表（实测取值 / ⚠ INVALID 档 / 非法档 / 未标定 / 自定义…）在 view.js
  for (const o of V.enumOptions(cell)) {
    const opt = document.createElement('option');
    opt.value = o.value;
    opt.textContent = o.label;
    opt.selected = o.selected;
    sel.appendChild(opt);
  }
  const cur = String(cellRaw(cell));

  el.replaceWith(sel);
  sel.addEventListener('click', (e) => e.stopPropagation());
  const dropHint = attachTrustHint(sel, cell);
  sel.focus();
  let mouseSelection = false;
  const session = V.editSession({
    onCommit: (picked) => {
      if (picked === 'custom') {
        inlineEdit(el, cur, (txt) => {
          const r = V.commitEnumCustom(cell, txt);       // 严格解析
          if (!r.ok) { flash(r.error); render(); return; }
          commitCell(fileOff, r.bits, r.value);
        }, cell);
        return;
      }
      commitCell(fileOff, V.cellBits(cell), BigInt(picked));
    },
    onCancel: () => render(),
  });
  const finish = (commit) => {
    const picked = sel.value;
    if (session.settled) return;
    dropHint();
    sel.replaceWith(el);
    session.finish(commit, picked);
  };
  // Native <select> controls may emit blur before change when an option is
  // chosen with the mouse. Mark the selection and let change win; otherwise
  // the dropdown disappears and the click appears to do nothing.
  sel.addEventListener('mousedown', () => { mouseSelection = true; });
  sel.addEventListener('change', () => finish(true));
  sel.addEventListener('keydown', (e) => { if (e.key === 'Escape') finish(false); });
  sel.addEventListener('blur', () => {
    setTimeout(() => {
      if (!session.settled && !mouseSelection) finish(false);
      mouseSelection = false;
    }, 0);
  });
}

/** operand 格：就地开一个输入框。
 *
 * 和 enum 格不一样，操作数没有「实测取值表」可选 —— 位宽能放下的值都是合法
 * 输入，所以给的是输入框而不是下拉。寄存器/谓词槽认名字（`RZ`/`R5`/`!P0`），
 * 其余按数字读（`0x..`/`0b..`/十进制，负数按二补码塞进这一格的位宽）。
 * 段表把一个操作数劈成几段时后端已经并成一格（`bit_list` 低位在前），
 * 这里不用管拼接。
 */
function operandEdit(el, fileOff, lo, hi) {
  const insn = insnAt(fileOff);
  const cell = (insn.cells || []).find((c) => c.lo === lo && c.hi === hi);
  if (!cell) return;
  if (cell.pc_relative) {
    // 这一格存的是「偏移/scale」的两补码，不是目标地址；scale、符号位、
    // 位散布都在 slot_facts 里，不是这一格的 bit_list 能表达的。改目标要整条重敲 SASS。
    flash(V.commitOperand(cell, '').error);
    return;
  }
  inlineEdit(el, cell.label || String(cellRaw(cell)), (txt) => {
    const r = V.commitOperand(cell, txt);
    if (!r.ok) { flash(r.error); render(); return; }
    commitCell(fileOff, r.bits, r.value);
  }, cell);
}

function commitCell(fileOff, bitList, value) {
  const insn = insnAt(fileOff);
  if (!insn) return;
  const bytes = setBits(bytesToArr(insn.bytes), bitList, value);
  const span = V.bitsLabel(bitList);
  lastEdit = { fileOff, what: `bit ${span} = ${value}` };
  postMutation({
    type: 'edit',
    fileOff,
    bytes: bytes.map((x) => x.toString(16).padStart(2, '0')).join(''),
    label: `bit ${span} = ${value} @ 0x${insn.addr.toString(16)}`,
  });
}

let lastEdit = null;

function commitField(fileOff, fieldName, text) {
  const f = state.fields.find((x) => x.name === fieldName);
  const insn = insnAt(fileOff);
  if (!f || !insn) return;
  const r = V.commitField(f, text);
  if (!r.ok) { flash(r.error); render(); return; }
  const bytes = setField(bytesToArr(insn.bytes), f, r.value);
  postMutation({
    type: 'edit',
    fileOff,
    bytes: bytes.map((x) => x.toString(16).padStart(2, '0')).join(''),
    label: `${fieldName} = ${text} @ 0x${insn.addr.toString(16)}`,
  });
}

function commitHex(fileOff, text) {
  const r = V.commitHex(text);
  if (!r.ok) { flash(r.error); render(); return; }
  const insn = insnAt(fileOff);
  postMutation({
    type: 'edit',
    fileOff,
    bytes: r.hex,
    label: `字节 @ 0x${insn ? insn.addr.toString(16) : fileOff.toString(16)}`,
  });
}

let pendingSassEdit = null;

function commitSass(fileOff, text) {
  const r = V.commitSass(insnAt(fileOff), text);
  if (!r.ok) {
    if (r.noop) {
      render();
    } else {
      flash('SASS 不能为空');
      render();
    }
    return;
  }
  // The cell is restored immediately after Enter. Keep the draft around so a
  // failed backend assembly can put the input back instead of silently
  // making the user retype it.
  pendingSassEdit = { fileOff, text: r.text };
  postMutation({ type: 'assemble', fileOff, text: r.text });
}

/** view.js 给的 `{kind, text}`（`null` = 没什么好说的）落到横幅上。 */
function show(msg) {
  if (!msg) return;
  flash(msg.text);
  if (msg.kind === 'info') banner.className = 'info';
}

function flash(msg) {
  banner.hidden = false;
  banner.className = '';
  banner.textContent = msg;
  setTimeout(() => { if (banner.textContent === msg) banner.hidden = true; }, 4000);
}

// ---- 事件 ---------------------------------------------------------------

function editSassCell(sass, initial = null) {
  if (!sass || !sass.dataset.off) return false;
  const fileOff = Number(sass.dataset.off);
  const insn = insnAt(fileOff);
  if (!insn) return false;
  inlineEdit(sass, initial === null ? (insn.sass || '') : initial,
    (v) => commitSass(fileOff, v), null, { keepOnCommit: true });
  return true;
}

function restoreFailedSassEdit() {
  if (!pendingSassEdit) return;
  const sass = out.querySelector(`td.sass[data-off="${pendingSassEdit.fileOff}"]`);
  const draft = pendingSassEdit.text;
  pendingSassEdit = null;
  // Normally the input is still present while assembly is pending. This
  // fallback covers a render that happened between the request and failure.
  if (sass && sass.querySelector('input.inline')) {
    const input = sass.querySelector('input.inline');
    input.focus();
    input.select();
    return;
  }
  if (editSassCell(sass, draft)) {
    const input = sass && sass.querySelector('input.inline');
    if (input) { input.focus(); input.select(); }
  }
}

out.addEventListener('click', (e) => {
  const summary = e.target.closest('.kernel-summary');
  if (summary) {
    // 控制 open 状态并重画：收起时直接从 DOM 移除几千条隐藏指令，展开时才
    // 生成当前页。只依赖原生 details 的视觉折叠仍会让大 cubin 占用大量 DOM。
    e.preventDefault();
    const name = summary.closest('.kernel').dataset.sec;
    if (state.openSections.has(name)) state.openSections.delete(name);
    else state.openSections.add(name);
    render();
    return;
  }
  const more = e.target.closest('.load-more-btn');
  if (more) {
    const name = more.dataset.sec;
    state.renderLimits.set(name, (state.renderLimits.get(name) || PAGE_SIZE) + PAGE_SIZE);
    render();
    return;
  }
  const addr = e.target.closest('td.addr');
  if (addr) {
    vscode.postMessage({ type: 'copy', text: addr.dataset.xxd });
    return;
  }
  const ins = e.target.closest('.reflow .ins');
  if (ins) {
    const off = Number(ins.dataset.off);
    // 插入的那条先拿本行的文本当草稿 —— 多数时候是照着邻居改一改
    const row = out.querySelector(`td.sass[data-off="${off}"]`);
    inlineEdit(row, (insnAt(off).sass || '').trim(),
      (text) => postMutation({ type: 'reflow', op: 'insert', fileOff: off, text }));
    return;
  }
  const del = e.target.closest('.reflow .del');
  if (del) {
    postMutation({ type: 'reflow', op: 'delete', fileOff: Number(del.dataset.off) });
    return;
  }
  const cell = e.target.closest('.cell.edit');
  if (cell) {
    // 控制段那一格没有取值表可选，跟 operand 一样是「填个原始值」——
    // 过去它掉进 enumEdit，开出来一个空下拉，看着就是「点了没反应」。
    const raw = cell.classList.contains('k-operand') || cell.classList.contains('k-ctrl');
    const edit = raw ? operandEdit : enumEdit;
    edit(cell, Number(cell.dataset.off), Number(cell.dataset.lo), Number(cell.dataset.hi));
    return;
  }
  const chip = e.target.closest('.chip.edit');
  if (chip) {
    const f = state.fields.find((x) => x.name === chip.dataset.field);
    const insn = insnAt(Number(chip.dataset.off));
    const cur = getField(bytesToArr(insn.bytes), f);
    inlineEdit(chip, V.fieldInitial(f, cur),
      (v) => commitField(Number(chip.dataset.off), chip.dataset.field, v));
    return;
  }
  const sass = e.target.closest('td.sass');
  if (editSassCell(sass)) {
    return;
  }
  const hex = e.target.closest('.hex.edit');
  if (hex) {
    const insn = insnAt(Number(hex.dataset.off));
    inlineEdit(hex, (insn.bytes.match(/.{2}/g) || []).join(' '),
      (v) => commitHex(Number(hex.dataset.off), v));
  }
});

// Double-click is also an explicit affordance for users who expect editor-like
// text editing rather than a clickable table cell.
out.addEventListener('dblclick', (e) => {
  const sass = e.target.closest('td.sass');
  editSassCell(sass);
});

let filterTimer = null;
$('filter').addEventListener('input', (e) => {
  state.filter = e.target.value;
  state.renderLimits = new Map();
  clearTimeout(filterTimer);
  filterTimer = setTimeout(render, 120);
});

for (const [id, key] of [['tBytes', 'showBytes'], ['tCtrl', 'showCtrl'],
                         ['tCells', 'showCells'], ['tDiffOnly', 'diffOnly']]) {
  $(id).addEventListener('change', (e) => {
    state[key] = e.target.checked;
    if (id === 'tDiffOnly') state.renderLimits = new Map();
    if (id === 'tCells' && e.target.checked && state.data
        && state.data.cells_loaded === false) {
      if (!state.cellsLoading) {
        state.cellsLoading = true;
        show({ kind: 'info', text: '正在按需分析 InsKey 和格子…' });
        vscode.postMessage({ type: 'loadCells' });
      }
      return;
    }
    render();
  });
}

window.addEventListener('message', (e) => {
  const m = e.data;
  if (m.type === 'defaults') {
    state.showBytes = m.showBytes;
    state.showCtrl = m.showCtrl;
    $('tBytes').checked = m.showBytes;
    $('tCtrl').checked = m.showCtrl;
  } else if (m.type === 'loading') {
    if (!state.data) out.innerHTML = '<div class="empty-note">解析中…</div>';
  } else if (m.type === 'backendCancelled') {
    state.cellsLoading = false;
    if (!state.data) out.innerHTML = '<div class="empty-note">解析已取消，重新打开预览可重试。</div>';
    show({ kind: 'info', text: '后台解析已取消。' });
  } else if (m.type === 'sync') {
    scrollToAddr(m.section, m.addr);
  } else if (m.type === 'reflowed') {
    show(V.reflowMessage(m));
  } else if (m.type === 'assembled') {
    if (m.res && !m.res.ok) {
      // Keep the failed text editable and make the actual assembler error
      // visible. This is especially useful for syntax/template mismatches.
      show(V.assembleMessage(m));
      restoreFailedSassEdit();
    } else {
      pendingSassEdit = null;
      show(V.assembleMessage(m));
    }
  } else if (m.type === 'data') {
    const keep = out.scrollTop;
    const oldPath = state.data && state.data.path;
    state.data = m.data;
    state.cellsLoading = false;
    if (!oldPath || oldPath !== m.data.path) {
      state.renderLimits = new Map();
      state.openSections = new Set(
        m.data.sections && m.data.sections.length ? [m.data.sections[0].name] : []);
    } else if (m.data.sections) {
      const names = new Set(m.data.sections.map((sec) => sec.name));
      state.openSections = new Set([...state.openSections].filter((name) => names.has(name)));
    }
    if (m.data.fields) state.fields = m.data.fields;
    $('tDiffOnly').disabled = !m.data.diffName;
    if (!m.data.diffName) { state.diffOnly = false; $('tDiffOnly').checked = false; }
    if (lastEdit) {
      show(V.illegalEncodingMessage(lastEdit, insnAt(lastEdit.fileOff)));
      lastEdit = null;
    }
    render();
    // 改一个字段不该把页面滚回顶上
    document.scrollingElement.scrollTop = keep || document.scrollingElement.scrollTop;
  }
});

// ---- 与 `.nvsass` 源码的滚动同步 ----------------------------------------
// 跟 markdown 的编辑器/预览联动一个意思：源码栏滚到哪一条，这边就滚到哪一条，
// 反过来也一样。两边共用一个 250ms 的抑制窗（宿主侧也有一份），谁在滚谁说了
// 算，不会互相推着走。锚点是指令的段内地址，不是行号 —— 源码里插删过指令、
// 或者这边开了过滤/只看差异时行号根本对不上。

let syncSuppress = 0;
let syncTimer = null;

function headerBottom() {
  const h = document.querySelector('header');
  return h ? h.getBoundingClientRect().bottom : 0;
}

/** 视口顶部（表头下面）第一条完整可见的指令行。 */
function topInsnRow() {
  const top = headerBottom();
  for (const r of out.querySelectorAll('tr.insn')) {
    if (r.getBoundingClientRect().bottom > top + 1) return r;
  }
  return null;
}

function scrollToAddr(section, addr) {
  let row = null;
  for (const r of out.querySelectorAll(`tr.insn[data-addr="${addr}"]`)) {
    if (!section || r.dataset.sec === section) { row = r; break; }
  }
  // 目标 kernel 可能收起，或分页后目标尚未进入 DOM。只展开目标 kernel 并扩到
  // 包含目标的下一页；不要为了同步一次滚动就把整个大 cubin 全量渲染出来。
  if (!row && state.data) {
    const f = state.filter.trim().toLowerCase();
    let found = null;
    let pos = 0;
    for (const sec of state.data.sections) {
      let sectionPos = 0;
      for (const i of sec.insns) {
        if (state.diffOnly && !i.diff) continue;
        if (!V.match(i, f)) continue;
        sectionPos++;
        if ((!section || sec.name === section) && i.addr === addr) {
          found = sec;
          pos = sectionPos;
          break;
        }
      }
      if (found) break;
    }
    if (found) {
      state.openSections.add(found.name);
      const limit = state.renderLimits.get(found.name) || PAGE_SIZE;
      if (pos > limit) {
        state.renderLimits.set(found.name, Math.ceil(pos / PAGE_SIZE) * PAGE_SIZE);
      }
      render();
      for (const r of out.querySelectorAll(`tr.insn[data-addr="${addr}"]`)) {
        if (!section || r.dataset.sec === section) { row = r; break; }
      }
    }
  }
  if (!row) return;
  syncSuppress = Date.now() + 250;
  const el = document.scrollingElement;
  el.scrollTop += row.getBoundingClientRect().top - headerBottom();
  savedScroll = el.scrollTop;
}

// 编辑后页面会整篇重画，滚动位置单独留一下
let savedScroll = 0;
window.addEventListener('scroll', () => {
  savedScroll = document.scrollingElement.scrollTop;
  if (Date.now() < syncSuppress) return;
  clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    if (Date.now() < syncSuppress) return;
    const row = topInsnRow();
    if (!row) return;
    vscode.postMessage({ type: 'scrolled', section: row.dataset.sec,
                         addr: Number(row.dataset.addr) });
  }, 80);
});
window.addEventListener('message', () => {
  requestAnimationFrame(() => {
    if (savedScroll) document.scrollingElement.scrollTop = savedScroll;
  });
});

vscode.postMessage({ type: 'ready' });
