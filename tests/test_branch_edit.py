"""分支目标可编辑。

 解出的 PC 相对偏移规则（`v = (目标 - 本指令地址 - 16) / 4`，位段
散在 16:24 和 34:82 两截，两补码）存在段表的 `slot_facts` 里，
逐位复测过。分支目标处理 是把这条规则接进文本层：文本里写**目标地址**，编码里存**偏移**。

判据仍是 nvdisasm 回环，外加一条端到端的：把改过的 cubin 交给 nvdisasm 全量
反汇编，它给这个目标地址贴的标号必须正好落在我们填的那一行上。
"""
from __future__ import annotations

import glob
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import (_addr_of, assemble_at, build,         # noqa: E402
                        identify, segtable)
from nvisa.model import asm_spec                              # noqa: E402
from nvisa.model.encode import encode_spec                     # noqa: E402
from nvisa.oracle.nvdisasm import Inst, Nvdisasm                # noqa: E402

CUBINS = sorted(glob.glob(str(ROOT / "corpus/cubins/*.cubin")))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins/")


@pytest.fixture(scope="module")
def bra_site():
    """(cubin 路径, 字节, 某条 BRA 的 file_off/addr)。"""
    for path in CUBINS:
        data = Path(path).read_bytes()
        for sec in build(Path(path), None)["sections"]:
            for ins in sec.get("insns", []):
                if identify(ins["enc"]) == "BRA_II" and ins["addr"]:
                    return Path(path), data, ins["file_off"], ins["addr"]
    pytest.skip("语料里没有非零地址上的 BRA")


def test_facts_reach_the_text_layer():
    """分支目标处理 消费的就是段表里那条规则；规则没了这一整条也就没了依据。"""
    f = asm_spec.pc_offset_fact("BRA_II")
    assert f and f["scale"] == 4 and f["insn_len"] == 16
    assert f["relative_to"] == "next_insn"
    assert asm_spec.pc_offset_fact("FFMA_R_R_R_R") is None    # 绝大多数指令没有


def test_dead_offset_bits_are_not_consumed():
    """JMP 的扫描槽含无贡献位，偏移规则必须排除 dead_bits。"""
    f = {"bits": [[16, 32], [34, 85]], "dead_bits": [24, 25, 81, 82]}
    # ``bits`` follows Python's half-open [lo, hi) convention.  The second
    # source segment also includes 83:85; only 81 and 82 are dead.
    assert asm_spec._fact_bits(f) == list(range(16, 24)) + list(range(26, 32)) \
        + list(range(34, 81)) + list(range(83, 85))


def test_brx_keeps_nvdisasm_relative_offset_coordinate():
    """BRX 的第二个操作数是 signed displacement，不是绝对目标地址。"""
    key = "BRX_R_II"
    fact = asm_spec.pc_offset_fact(key)
    assert fact and fact["text_coordinate"] == "relative_offset"
    text = "BRX R18 -0x320"
    values = asm_spec.text_to_values(key, text, 0x310)
    enc = encode_spec(key, values)
    assert asm_spec.read_offset(fact, enc) == -0x320
    assert asm_spec.rebase(key, text, 0x310) == text
    raw = Inst(0x310, enc, text)
    assert Nvdisasm._rebase(raw).text == text


def test_jmxu_keeps_nvdisasm_relative_offset_coordinate():
    """JMXU 与 BRX 一样打印寄存器相对位移，不能按 PC 目标 rebasing。"""
    key = "JMXU_UR_II"
    fact = asm_spec.pc_offset_fact(key)
    assert fact and fact["text_coordinate"] == "relative_offset"
    text = "JMXU UR4 -0x320"
    values = asm_spec.text_to_values(key, text, 0x310)
    enc = encode_spec(key, values)
    assert asm_spec.read_offset(fact, enc) == -0x320
    assert asm_spec.rebase(key, text, 0x310) == text
    raw = Inst(0x310, enc, text)
    assert Nvdisasm._rebase(raw).text == text


def test_acceptance_bra_immediate_target(bra_site):
    """分支目标处理 验收：`BRA 0x1230` 这样的文本能编辑成功且回环校验通过。"""
    _, data, off, _ = bra_site
    r = assemble_at(data, off, "BRA 0x1230", [])
    assert r["ok"], r
    assert r["sass"] == "BRA 0x1230"


def test_target_is_relative_to_this_instruction(bra_site):
    """同一个目标地址摆在不同地址上编出来的偏移必须不同 —— 如果哪天退化成
    「把文本里的数直接当偏移填」，这条会红。"""
    _, data, off, addr = bra_site
    a = assemble_at(data, off, "BRA 0x1230", [])
    b = assemble_at(data, off + 16, "BRA 0x1230", [])
    assert a["ok"] and b["ok"]
    assert a["enc"] != b["enc"], "换一行落点，偏移居然没变"
    assert _addr_of(data, off) == addr


def test_label_target_is_refused_with_a_reason(bra_site):
    """符号标号（`` BRA `(.L_x_0) ``）的地址不在指令自己身上 —— 编不了，
    但要说清楚为什么，不能悄悄编成别的目标。"""
    _, data, off, _ = bra_site
    r = assemble_at(data, off, "BRA `(.L_x_0)", [])
    assert not r["ok"]
    assert "符号标号" in r["error"], r


def test_unaligned_target_is_refused(bra_site):
    """最低两位不进编码（`scale=4`）。填个不对齐的地址要报错，不能默默截断。"""
    _, data, off, _ = bra_site
    r = assemble_at(data, off, "BRA 0x1231", [])
    assert not r["ok"]
    assert "0x4" in r["error"] or "4 的倍数" in r["error"], r


def test_end_to_end_label_lands_on_the_target_row(bra_site, tmp_path):
    """端到端：改完写回 cubin，nvdisasm 全量反汇编时贴的标号必须正好落在
    我们填的那个地址上。回环只验单条，这一条验的是它在真 cubin 坐标里也对。"""
    path, data, off, addr = bra_site
    target = addr + 0x40
    r = assemble_at(data, off, f"BRA {target:#x}", [])
    assert r["ok"], r
    buf = bytearray(data)
    buf[off:off + 16] = bytes.fromhex(r["bytes"])
    out = tmp_path / "patched.cubin"
    out.write_bytes(bytes(buf))
    try:
        text = subprocess.run(["nvdisasm", "-c", str(out)],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:      # noqa: BLE001
        pytest.skip(f"nvdisasm 跑不了：{e}")
    lines = text.splitlines()
    at = next(n for n, ln in enumerate(lines)
              if f"/*{addr:04x}*/" in ln and "BRA" in ln)
    label = lines[at].split("`(")[1].split(")")[0]
    at_label = next(n for n, ln in enumerate(lines) if ln.strip() == f"{label}:")
    assert f"/*{target:04x}*/" in lines[at_label + 1], lines[at_label:at_label + 2]


def test_rebase_leaves_ordinary_instructions_alone():
    """`rebase()` 只该动 PC 相对分支 —— 普通指令末尾的立即数不是地址。"""
    assert asm_spec.rebase("FFMA_R_R_R_R", "FFMA R9, R2, R5, 0x10", 0x100) \
        == "FFMA R9, R2, R5, 0x10"
    assert asm_spec.rebase("BRA_II", "BRA 0x10", 0x100) == "BRA 0x110"
    # `.ABS` 的目标就是绝对地址，不跟本指令地址走
    assert asm_spec.rebase("CALL_II", "CALL.ABS.NOINC 0x10", 0x100) \
        == "CALL.ABS.NOINC 0x10"
