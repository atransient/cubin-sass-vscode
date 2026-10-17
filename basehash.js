'use strict';
// `.base` —— 「这份 `.nvsass` 源码对着哪一份基底 cubin」的唯一判据。
//
// 后端保存时拿源码头里的 `.base` 跟**磁盘上**基底的 hash 比，对不上就按「导出
// 之后基底被外部改过」拒绝写回（`nvisa/model/sass_save.py:save_source()`）。
// 扩展这边要判断「开着的源码是不是已经对着磁盘上这一份了」，用的必须是同一个
// 定义，否则就会出现「第一次能存、第二次报基底对不上」。
//
// 故意不 require('vscode')：这样它能被 node 直接测，也能被
// tests/test_view_contract.py 拉去跟 Python 那份逐字比。
const crypto = require('crypto');

/** 与 `nvisa/model/sass_source.py:base_hash()` 同一个定义：sha256 前 16 位。 */
function baseHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);
}

/** 源码头里声明的基底 hash（行首的 `.base <hash>`）；没有就回 ''。 */
function declaredBase(text) {
  const m = /^[ \t]*\.base[ \t]+(\S+)/m.exec(text);
  return m ? m[1] : '';
}

module.exports = { baseHash, declaredBase };
