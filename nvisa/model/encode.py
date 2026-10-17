"""从 spec 反向生成编码。

`asm.py` 是「模板 + 补丁」：opcode 与修饰符从一条现成指令继承，只改 12 个硬编码
位域，所以立即数、常量 bank、地址形式一概不支持。这里换一条路：**编码的每一位
都从段表 + fieldscan 现查**，不需要模板。

    编码 ──decode_spec()──→ 语义值 ──encode_spec()──→ 编码'
                                                        │
                            nvdisasm(编码) == nvdisasm(编码')  ← 往返验收

**未被 spec 覆盖的位一律填 0**（`dontcare` / `dc_safe` / `assumed` / `unknown`）。
这是故意的：如果填 0 之后 nvdisasm 读回的文本仍然一模一样，就说明 spec 抓住了
这条指令的全部**语义**位；文本一变，说明有承载语义的位还没进 spec ——
往返率因此是 spec 完整性的直接度量，而不是「把原样的位抄回去」的自欺。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from nvisa.oracle.cubin import get_bits, set_bits

#: 编码时可以填 0 的位。**只有 `dontcare` 一类** —— 它是唯一有正面证据的：
#: `kind_adjudicate.py` 逐位翻过，翻了 nvdisasm 文本不变。其余几类过去也被当成
#: 「可以丢」，实测**全是错的**：
#:
#:   `dc_safe`  「填 0 安全」说的是**正确性**（硬件不拒绝），不是文本不变 ——
#:              `.reuse`(122:124) 与 `LEA.HI.SX32` 的修饰符位都栽在这上面
#:   `unknown`  段表没分出类，不等于不承重 —— 实测 5 个 key 各丢 1 位 `unknown`
#:              就换成了另一条指令（`F2I` -> `BREV`，`REDG` -> `STG`）
#:   `unused` / `assumed`   同理，从没被证明与文本无关
ZEROABLE = ("dontcare",)

#: 真正被 spec **解释**了的位（有结构、有名字）。其余的只是**照搬**——
#: 往返成功不代表理解，所以覆盖率要和往返率分开报。
EXPLAINED = ("const", "operand", "enum", "modifier", "ctrl", "opcode_sel")

#: 控制段起点。段表把已标定的 105:124 分类为 `ctrl`（含
#: stall / yield / wr / rd_bar / wait / reuse）；125:127 没有同等的结构化证据。
#: 往返仍逐位带回整个控制段：它并不把调度参数或 `.reuse` 当成可填零位，避免
#: 从同一条指令的兼容性位推出独立编码的虚假成功。
NCODE = 105


def _cells(key: str):
    from cubin_sass import segtable
    return segtable()[key]["cells"]


def _fs_fields(key: str, enc: str):
    from cubin_sass import fs_enum_fields
    return fs_enum_fields(key, enc)


def decode_spec(enc: str, key: str) -> dict:
    """按 spec 把一条编码拆成语义值。

    返回 `{"cells": {(lo,hi): raw}, "mods": {(bit_list): raw}}` —— 只收 spec
    **建模了**的位；`UNMODELED` 那几类不收，正是要看丢掉它们之后文本变不变。
    """
    cells, mods = {}, {}
    covered = set()
    for f in _fs_fields(key, enc):
        bl = tuple(f["bit_list"])
        mods[bl] = sum((get_bits(enc, b, b) & 1) << i for i, b in enumerate(bl))
        covered |= set(bl)
    for c in _cells(key):
        lo, hi = c["bits"]
        if c["kind"] in ZEROABLE and lo < NCODE:
            continue
        if set(range(lo, hi)) <= covered:
            continue                      # 整段已由 fieldscan 的字段接管
        cells[(lo, hi)] = get_bits(enc, lo, hi - 1)
    return {"cells": cells, "mods": mods}


def encode_spec(key: str, values: dict) -> str:
    """从语义值造回 128 bit。`values` 就是 `decode_spec()` 的产出。

    起点是全 0，不是某条模板 —— 这正是与 `asm.py` 的分界。
    """
    enc = "0" * 32
    for (lo, hi), v in values["cells"].items():
        enc = set_bits(enc, lo, hi - 1, v)
    for bl, v in values["mods"].items():
        for i, b in enumerate(bl):
            enc = set_bits(enc, b, b, (v >> i) & 1)
    return enc


def spec_bit_coverage(key: str) -> tuple[int, int, int]:
    """(被解释的位, 只是照搬的位, 可填 0 的位) —— 三者相加 = 128。

    **往返成功 ≠ 理解**：照搬的那些位往返照样对得上，但 spec 说不出它们是什么。
    这两个数必须分开看。
    """
    exp = carried = zero = 0
    for c in _cells(key):
        lo, hi = c["bits"]
        n = hi - lo
        if c["kind"] in EXPLAINED:
            exp += n
        elif c["kind"] in ZEROABLE and lo < NCODE:
            zero += n
        else:
            carried += n
    return exp, carried, zero
