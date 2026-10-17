"""`.nvsass` 整段两遍汇编 —— `nvisa/model/sass_asm.py`。

判据分三层：

* **原样往返**：`--emit-source` 出来的源码原样汇编回去，`.text` **逐字节一致**
  （验收 ①）—— 这条保证「打开源码看看」不会悄悄改写基底；
* **改了就得真改**：改寄存器 / 改控制码 / 对调两行，编码必须跟着变，且 nvdisasm
  读回的正是源码写的那条；控制码跟着**源码行**走，不按原地址继承（验收 ③）；
* **错了就得报**：缺控制码、非法控制码、标号未定义/重复、不支持的 form、寄存器
  超预算 —— 每条都精确到行/列，且整次编译失败不产出半份结果。
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import disasm_one, segtable                       # noqa: E402
from nvisa.model.sass_asm import (Diagnostic, SourceAsmError,     # noqa: E402
                                  assemble_into, assemble_source)
from nvisa.model.sass_source import emit_source                   # noqa: E402
from nvisa.oracle.cubin import Cubin, enc_to_bytes, get_bits      # noqa: E402

CUBINS = sorted((ROOT / "corpus" / "cubins").glob("*.cubin"))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins")

FMA = ROOT / "corpus" / "cubins" / "fma.sm_90.cubin"


def _src(path: Path = FMA) -> tuple[bytes, str]:
    data = path.read_bytes()
    return data, emit_source(data).text


def _replace(src: str, old: str, new: str) -> str:
    assert old in src, old
    return src.replace(old, new, 1)


# --- 原样往返 --------------------------------------------------------------

def test_emit_then_assemble_is_byte_identical():
    """验收 ①：导出后不修改直接汇编，`.text` 逐字节一致。

    这不是从零编码能白给的：段表只解释得了约 64% 的位，其余从零编码只能填默认
    值。没改过的行走 `_identity()` 沿用基底的位，所以「看一眼」不会改写基底。
    """
    data, src = _src()
    out, asm = assemble_into(data, src)
    assert out == data
    assert asm.size == len(asm.encodings) * 16


@pytest.mark.skipif(os.environ.get("NVISA_SLOW") != "1",
                    reason="全语料往返要跑一遍 nvdisasm：设 NVISA_SLOW=1 才跑")
@pytest.mark.parametrize("path", CUBINS, ids=lambda p: p.name)
def test_whole_corpus_roundtrips(path):
    data = path.read_bytes()
    out, _ = assemble_into(data, emit_source(data).text)
    assert out == data


# --- 改了就得真改 ----------------------------------------------------------

def test_editing_an_operand_reencodes_and_reads_back():
    data, src = _src()
    line = next(l for l in src.splitlines() if "IMAD R9, R9, UR4, R0" in l)
    out, asm = assemble_into(data, _replace(src, line, line.replace("R0;", "R7;")))
    assert out != data
    idx = [i for i, l in enumerate(
        [x for x in src.splitlines() if x.startswith("[B")]) if l == line][0]
    assert disasm_one(enc_to_bytes(asm.encodings[idx])) == "IMAD R9, R9, UR4, R7"


def test_control_code_comes_from_the_source_line():
    """控制码只认源码行 —— 不继承基底、不自动排程。"""
    data, src = _src()
    lines = [l for l in src.splitlines() if l.startswith("[B")]
    edited = _replace(src, lines[0], "[B01----:R2:W3:Y:S15]" + lines[0][21:])
    _out, asm = assemble_into(data, edited)
    enc = asm.encodings[0]
    assert get_bits(enc, 105, 108) == 15          # stall
    assert get_bits(enc, 109, 109) == 1           # yield
    assert get_bits(enc, 110, 112) == 3           # wr
    assert get_bits(enc, 113, 115) == 2           # rd
    assert get_bits(enc, 116, 121) == 0b000011    # wait mask B0/B1
    # 其余位一位没动：改控制码不该动指令本身
    base = Cubin(data).read(0, asm.section)
    assert [b for b in range(128) if get_bits(base, b, b) != get_bits(enc, b, b)] \
        == sorted(set(range(105, 122)) - {b for b in range(105, 122)
                                          if get_bits(base, b, b) == get_bits(enc, b, b)})


def test_control_code_travels_with_the_line_not_the_address():
    """验收 ③：对调两行，控制码跟着行走，不留在原地址上。"""
    data, src = _src()
    lines = src.splitlines()
    idx = [i for i, l in enumerate(lines) if l.startswith("[B")]
    a, b = idx[3], idx[4]                       # 两条相邻的普通指令
    lines[a], lines[b] = lines[b], lines[a]
    _out, asm = assemble_into(data, "\n".join(lines) + "\n")
    for pos, text in ((a, lines[a]), (b, lines[b])):
        n = idx.index(pos)
        enc = asm.encodings[n]
        want = int(text[text.index(":S") + 2:text.index("]")])
        assert get_bits(enc, 105, 108) == want, text


def test_branch_keeps_pointing_at_the_label_after_a_swap():
    """标号是源码层的坐标：行动了，跳转还落在同一条指令上。"""
    path = ROOT / "corpus" / "cubins" / "control.sm_90.cubin"
    if not path.exists():
        pytest.skip("需要 control.sm_90.cubin")
    data = path.read_bytes()
    src = emit_source(data)
    target = next(iter(sorted(src.labels)))
    name = src.labels[target]
    _out, asm = assemble_into(data, src.text)
    n = [i for i, l in enumerate([x for x in src.text.splitlines()
                                  if x.startswith("[B")])
         if name in l][0]
    line = [x for x in src.text.splitlines() if x.startswith("[B")][n]
    addr = n * 16
    from nvisa.model import asm_spec
    from cubin_sass import identify
    key = identify(asm.encodings[n])
    fact = asm_spec.pc_offset_fact(key)
    assert fact, line
    assert addr + fact["insn_len"] + asm_spec.read_offset(fact, asm.encodings[n]) \
        == target


# --- 错了就得报 ------------------------------------------------------------

def _fails(src: str, data: bytes | None = None) -> list[Diagnostic]:
    with pytest.raises(SourceAsmError) as e:
        assemble_source(src, data)
    return e.value.diagnostics


def test_missing_control_code_is_a_hard_error():
    data, src = _src()
    line = next(l for l in src.splitlines() if l.startswith("[B"))
    diags = _fails(_replace(src, line, line[line.index("]") + 1:].strip()), data)
    assert any("没有控制码" in d.msg for d in diags)


def test_illegal_control_code_reports_a_column():
    data, src = _src()
    line = next(l for l in src.splitlines() if l.startswith("[B"))
    diags = _fails(_replace(src, line, "[B------:R-:W-:-:S99]" + line[21:]), data)
    assert diags and diags[0].col == 0 and "stall" in diags[0].msg


def test_undefined_and_duplicate_labels():
    data, src = _src()
    lines = src.splitlines()
    i = next(i for i, l in enumerate(lines) if l.startswith("[B"))
    bad = lines[:i] + [".L_x:", ".L_x:"] + lines[i:]
    assert any("重复定义" in d.msg for d in _fails("\n".join(bad), data))

    line = next(l for l in lines if l.startswith("[B") and "BRA" not in l)
    body = "[B------:R-:W-:-:S01] BRA .L_nope;"
    assert any("没有定义" in d.msg for d in _fails(_replace(src, line, body), data))


def test_unsupported_form_is_reported_not_silently_wrong():
    """段表覆盖不到的 form 报错，不悄悄编成别的指令（当前边界 866/909）。"""
    data, src = _src()
    line = next(l for l in src.splitlines() if l.startswith("[B"))
    diags = _fails(_replace(src, line, "[B------:R-:W-:-:S01] NOTANOPCODE R0, R1;"),
                   data)
    assert diags and ("编不出来" in diags[0].msg or "解析" in diags[0].msg)


def test_register_budget_is_checked():
    data, src = _src()
    # Omitted directive inherits the base budget and keeps the automatic guard.
    src = re.sub(r"(?m)^\.regcount \d+\n", "", src, count=1)
    line = next(l for l in src.splitlines() if "IMAD R9, R9, UR4, R0" in l)
    over = _replace(src, line, line.replace("R9, R9", "R200, R9"))
    assert any("超预算" in d.msg for d in _fails(over, data))
    # 显式 `.regcount` 提高预算之后同一份源码就该编得过 —— 诊断给的建议是真的
    raised = over.replace(".base ", ".regcount 220\n.base ", 1)
    assert assemble_source(raised, data).regs_used == 201


def test_explicit_regcount_is_a_literal_expert_override():
    data, src = _src()
    m = re.search(r"(?m)^\.regcount (\d+)$", src)
    assert m
    lowered = src[:m.start(1)] + "1" + src[m.end(1):]
    # Even though the instruction text uses registers above R0, an explicit
    # value is accepted verbatim; the user owns runtime validity.
    assert assemble_source(lowered, data).regcount == 1
    invalid = src[:m.start(1)] + "256" + src[m.end(1):]
    assert any("1..255" in d.msg for d in _fails(invalid, data))


def test_base_hash_mismatch_is_treated_as_an_external_change():
    data, src = _src()
    tampered = src.replace(src.splitlines()[2], ".base 0123456789abcdef")
    assert any("基底" in d.msg for d in _fails(tampered, data))


def test_copied_line_does_not_hijack_the_address_map():
    """复制一行会连原地址注释一起复制。映射以**第一次出现**为准，副本算新指令
    —— 否则跳到旧地址的分支会被指到副本上。"""
    data, src = _src()
    line = next(l for l in src.splitlines() if l.startswith("[B"))
    out = assemble_source(_replace(src, line, line + "\n" + line), data)
    assert out.addr_map[0] == 0                 # 第一份还在 0，不是副本的 0x10
    assert len(out.encodings) == 33


def test_all_or_nothing():
    """两条坏行要一次全报出来，不是报了第一条就走人。"""
    data, src = _src()
    lines = src.splitlines()
    idx = [i for i, l in enumerate(lines) if l.startswith("[B")]
    for i in idx[:2]:
        lines[i] = lines[i][:lines[i].index("]") + 1] + " NOTANOPCODE R0;"
    assert len(_fails("\n".join(lines), data)) >= 2
