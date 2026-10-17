'use strict';
// 每个 cubin 最近若干份**字节快照**，按 `baseHash()` 索引。
//
// 为什么需要它：`.nvsass` 源码头里的 `.base` 是文档正文的一部分，所以它跟着
// VS Code 的**撤销栈**走 —— 保存成功后我们把源码重绑到新字节（`.base` 换成新
// hash），用户一按 Ctrl+Z，正文连同这一行一起退回上一版，`.base` 又变回了旧
// hash。此时 cubin 缓冲区还停在新字节上，冲突闸一比就报「基底对不上 …… 基底在
// 导出之后被改过」——可那根本不是外部改动，是我们自己两个视图之一被撤销了。
//
// 不能简单地对虚拟文档关掉这道闸：撤销退回去的不只是 `.base`，还有行尾的
// `// @0x....`（每行在**那一版基底**里的原地址）。拿旧地址去索引新字节，
// 「这行没改过」的快速路径就会沿用错的位 —— 无声地编出错的指令，比报错糟得多。
//
// 所以正确的做法是**连基底一起退回去**：源码声明的那份字节我们刚才见过，
// 留着它，汇编时就拿它当基底。结果照常 `applyWhole()` 回 cubin document
// （一次可撤销的编辑），于是「撤销源码」自然地把 cubin 缓冲区也带了回去。
//
// 故意不 require('vscode')：能被 node 直接测。

const { baseHash } = require('./basehash.js');

/** 每个 cubin 留几份快照。够覆盖「存几次再一路撤销」，又不至于把大 cubin 攒满内存。 */
const DEFAULT_LIMIT = 8;

class BaseHistory {
  constructor(limit = DEFAULT_LIMIT) {
    this.limit = limit;
    this._byCubin = new Map();          // cubin key -> Map([image, hash] -> Buffer)
  }

  /** 记下 `key`（一般是 cubin 的 fsPath）这份 cubin 的一版字节。 */
  remember(key, data, knownHash = '', image = null) {
    if (!key || !data || !data.length) return '';
    const hash = knownHash || baseHash(data);
    let snaps = this._byCubin.get(key);
    if (!snaps) this._byCubin.set(key, (snaps = new Map()));
    // 重新 set 一次把它挪到 Map 末尾 —— 最近用过的最后被淘汰。
    const version = JSON.stringify([image, hash]);
    snaps.delete(version);
    snaps.set(version, Buffer.from(data));
    while (snaps.size > this.limit) snaps.delete(snaps.keys().next().value);
    return hash;
  }

  /** 这份 cubin 的某个 hash 版本还在吗？在就回那份字节，不在回 null。 */
  get(key, hash, image = null) {
    const snaps = this._byCubin.get(key);
    if (!snaps || !hash) return null;
    const version = JSON.stringify([image, hash]);
    const data = snaps.get(version);
    if (!data) return null;
    snaps.delete(version);              // 用到就算「最近」
    snaps.set(version, data);
    return data;
  }

  /** cubin 关掉了就把它的快照一起丢掉，别攒着。 */
  forget(key) {
    this._byCubin.delete(key);
  }
}

module.exports = { BaseHistory, DEFAULT_LIMIT };
