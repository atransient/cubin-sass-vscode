"""模板汇编器：从 SASS 文本造出 128 bit 编码，并用 nvdisasm 验证。

这是 `model/` 的第一块：**用规则预测编码，与 oracle 比对**。

**它不是汇编器，是「模板 + 补丁」的正向包装。** opcode 位从一条同助记符的模板指令
继承（模板来自当前 cubin 或 `corpus/`），只有本项目**已标定的字段**会被改写：
寄存器号、谓词、控制段。
其余位（opcode、修饰符、立即数）原样保留 —— 想换 opcode 就换模板，
而模板可以用 inline PTX 逼 ptxas 生成。

## 为什么值得包一层

回环校验：

    文本 ──assemble()──→ 编码 ──nvdisasm──→ 文本'   且断言 文本' == 文本

nvdisasm 是 NVIDIA 自己的解码器。**如果它把我们造的编码读回成一模一样的文本，
那这条编码就确实是我们想要的那条。** 相当于把官方解码器变成我们汇编器的验证器。

⚠️ 回环只保证「编码 = 我想写的指令」，**不保证实验设计对**。
链有没有接上、参考档合不合法、GPU 是否独占，那些是 `checks.py` 的事。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from nvisa.oracle import discache
from nvisa.oracle.cubin import Cubin, get_bits, set_bits

RZ = 255          # 零寄存器：读它不占 RF 读端口（实测）
PT = 7            # 真谓词：@PT = 无条件执行

#: 已标定的位域。**只有这里列出的字段能被改写** —— 其余位从模板继承。
FIELDS: dict[str, tuple[int, int]] = {
    # 寄存器
    "rd": (16, 23), "ra": (24, 31), "rb": (32, 39), "rc": (64, 71),
    # 谓词：3 bit 选 P0-P6/PT + 1 bit 取反
    "pred": (12, 14), "pred_not": (15, 15),
    # 控制段
    "stall": (105, 108), "yield": (109, 109), "wr": (110, 112),
    "rd_bar": (113, 115), "wait": (116, 121), "reuse": (122, 124),
}

# `reuse` is a control-code field too.  It is deliberately not part of
# `oracle.guard.CONTROL_BITS`: changing it cannot create a runaway kernel in
# the way scheduling fields can.  The segment-table builder, on the other
# hand, needs the complete calibrated control-code layout so these bits are
# counted as explained rather than as payload copied from a carrier encoding.
CONTROL_FIELDS = ("stall", "yield", "wr", "rd_bar", "wait", "reuse")
CONTROL_BITS = frozenset(
    bit for name in CONTROL_FIELDS
    for bit in range(FIELDS[name][0], FIELDS[name][1] + 1)
)

_SLOT_ORDER = ("ra", "rb", "rc")          # 源操作数从左到右对应的字段
_REG = re.compile(r"^(-?)(RZ|R(\d+))(\.reuse)?$", re.I)
_PRED = re.compile(r"^@(!?)(PT|P([0-7]))$", re.I)


class AsmError(RuntimeError):
    pass


@dataclass
class Parsed:
    mnemonic: str
    fields: dict[str, int]

    def render(self) -> str:
        """按 nvdisasm 的写法重新渲染 —— 用来和反汇编逐字比对。"""
        f = self.fields
        out = ""
        if f.get("pred", PT) != PT or f.get("pred_not"):
            out += f"@{'!' if f.get('pred_not') else ''}P{f['pred']} " \
                if f.get("pred", PT) != PT else f"@{'!' if f.get('pred_not') else ''}PT "
        out += self.mnemonic
        ops = [_reg(f["rd"])] if "rd" in f else []
        for i, slot in enumerate(_SLOT_ORDER):
            if slot not in f:
                continue
            ops.append(_reg(f[slot]) + (".reuse" if (f.get("reuse", 0) >> i) & 1 else ""))
        return (out + " " + ", ".join(ops)).strip()


def _reg(n: int) -> str:
    return "RZ" if n == RZ else f"R{n}"


def parse(text: str) -> Parsed:
    """把一条 SASS 文本拆成字段值。只认已标定的形式，别的直接报错。"""
    text = text.strip().rstrip(";").strip()
    fields: dict[str, int] = {}
    toks = text.split()
    if toks and toks[0].startswith("@"):
        m = _PRED.match(toks.pop(0))
        if not m:
            raise AsmError(f"看不懂的谓词：{text!r}")
        fields["pred_not"] = 1 if m.group(1) else 0
        fields["pred"] = PT if m.group(2).upper() == "PT" else int(m.group(3))
    if not toks:
        raise AsmError(f"没有助记符：{text!r}")
    mnemonic = toks.pop(0)
    ops = [p.strip() for p in " ".join(toks).split(",") if p.strip()]
    if not ops:
        return Parsed(mnemonic, fields)

    reuse = 0
    for i, op in enumerate(ops):
        m = _REG.match(op)
        if not m:
            raise AsmError(
                f"操作数 {op!r} 不是已标定的形式（只支持 R<n>/RZ，可带 .reuse）。\n"
                f"  立即数、常量 bank 引用、修饰符请换一条模板指令 —— 见模块文档。")
        if m.group(1):
            raise AsmError(f"操作数取反（{op!r}）的字段尚未标定")
        n = RZ if m.group(2).upper() == "RZ" else int(m.group(3))
        if i == 0:
            fields["rd"] = n
        else:
            if i - 1 >= len(_SLOT_ORDER):
                raise AsmError(f"源操作数超过 3 个：{text!r}")
            fields[_SLOT_ORDER[i - 1]] = n
            if m.group(4):
                reuse |= 1 << (i - 1)
    if reuse:
        fields["reuse"] = reuse
    return Parsed(mnemonic, fields)


def assemble(template: str, text: str, **ctrl: int) -> str:
    """模板编码 + 目标文本 + 控制段覆盖 → 新编码（32 hex 字符）。

    `ctrl` 接受 FIELDS 里的任何键，例如 stall=4, yield_=1, wait=0b000001。
    （`yield` 是关键字，所以也接受 `yield_`。）
    """
    p = parse(text)
    enc = template
    vals = dict(p.fields)
    if "reuse" not in vals:
        vals["reuse"] = 0                      # 文本里没写 .reuse 就显式清零
    for k, v in ctrl.items():
        key = "yield" if k == "yield_" else k
        if key not in FIELDS:
            raise AsmError(f"未标定的字段：{k}（已知：{sorted(FIELDS)}）")
        vals[key] = v
    for key, v in vals.items():
        lo, hi = FIELDS[key]
        if not 0 <= v < (1 << (hi - lo + 1)):
            raise AsmError(f"{key}={v} 放不进 {hi - lo + 1} bit")
        enc = set_bits(enc, lo, hi, v)
    return enc


def find_template(cubin: Cubin, path: Path, mnemonic: str) -> tuple[int, str]:
    """在 cubin 里找一条该助记符的指令当模板，返回 (地址, 编码)。"""
    for addr, body in sorted(discache.text_by_addr(path).items()):
        m = re.match(r"@?!?P?T?\d?\s*([A-Z0-9_.]+)", body)
        if not m or m.group(1).split(".")[0] != mnemonic.split(".")[0]:
            continue
        try:
            return addr, cubin.read(addr)
        except Exception:                                    # noqa: BLE001
            continue
    raise AsmError(f"cubin 里找不到 {mnemonic} 的模板 —— "
                   f"用 inline PTX 逼 ptxas 生成一条")


def disasm_at(path: Path, addr: int) -> str:
    got = discache.text_by_addr(path).get(addr)
    return re.sub(r"\s+", " ", got).rstrip(";").strip() if got else "<未找到>"


def verify(cubin: Cubin, addr: int, enc: str, want: str, scratch: Path) -> str:
    """回环校验：写进去 → nvdisasm 读回 → 必须与 `want` 的规范形式逐字相同。"""
    saved = cubin.read(addr)
    cubin.write(addr, enc)
    got = disasm_at(cubin.save(scratch), addr)
    cubin.write(addr, saved)                                 # 复原，不留副作用
    canon = parse(want).render()
    norm = lambda s: re.sub(r"\s+", " ", s).replace(" ,", ",").strip()
    if norm(got) != norm(canon):
        raise AsmError(
            f"回环校验失败 —— 造出来的编码不是想要的那条指令：\n"
            f"  想要（规范化）: {canon}\n"
            f"  nvdisasm 读回 : {got}\n"
            f"  可能原因：该指令有未标定的字段，或模板选错了 opcode 变体。")
    return got


def control_of(enc: str) -> dict[str, int]:
    """把一条编码的控制段读出来 —— 断言和打印用。"""
    return {k: get_bits(enc, *FIELDS[k])
            for k in ("stall", "yield", "wr", "rd_bar", "wait", "reuse")}
