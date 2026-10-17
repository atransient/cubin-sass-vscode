"""`assemble_at()` 走段表构造。

README「指令编辑的边界」原先列的两条限制（立即数/常量bank/地址形式写不了、
corpus 里没有的变体写不了）就是靠这里解除的，所以拿 README 举的那条反例
`LOP3.LUT ... 0x3c, !PT` 当回归用例。判据仍是 nvdisasm 回环：造出来的编码
读回必须逐字就是想写的那条。
"""
from __future__ import annotations

import glob
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import (INST_BYTES, assemble_at, build,          # noqa: E402
                        ctrl_of, segtable)
from nvisa.oracle.cubin import enc_from_bytes, get_bits          # noqa: E402

CUBINS = sorted(glob.glob(str(ROOT / "corpus/cubins/*.cubin")))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins/")


@pytest.fixture(scope="module")
def site():
    """(cubin 字节, 某条指令的文件偏移) —— 改写的落点。

    挑 `yield=1 且 stall>=1` 的落点：控制段沿用原指令，而 nvdisasm **只在
    这种控制码下才打印 `.reuse`**，否则下面的 `.reuse` 用例
    永远回环不上 —— 那是控制码的约束，不是编码造错了。
    """
    data = Path(CUBINS[0]).read_bytes()
    for sec in build(Path(CUBINS[0]), None)["sections"]:
        for ins in sec.get("insns", []):
            if not (ins.get("sass") and ins.get("file_off") is not None):
                continue
            if get_bits(ins["enc"], 109, 109) and get_bits(ins["enc"], 105, 108):
                return data, ins["file_off"]
    pytest.skip("语料里没有 yield=1 的可改写指令")


#: 模板补丁写不了、段表构造能写的形式：立即数、常量 bank、desc 地址、
#: 数据表修正 救回来的 `LEA.HI`。
SPEC_ONLY = [
    "LOP3.LUT R10, R8, R11, RZ, 0x3c, !PT",       # README 的反例
    "IADD3 R4, R5, 0x10, RZ",
    "LDG.E R2, desc[UR4][R6.64]",
    "LEA.HI R2, R4, R6, RZ, 0x2",
]


@pytest.mark.parametrize("text", SPEC_ONLY)
def test_spec_path_assembles(site, text):
    data, off = site
    r = assemble_at(data, off, text, [])
    assert r["ok"], r.get("error")
    assert r["template"].startswith("段表构造"), r["template"]
    assert " ".join(r["sass"].split()).rstrip(";").strip() == text


def test_ctrl_inherited_from_original(site):
    """控制段是 `asm.py:FIELDS` 的地盘：stall/yield/barrier 沿用原指令，
    不能被 段表构造 填的良性默认值盖掉（会悄悄毁掉时序实验）。"""
    data, off = site
    cur = ctrl_of(enc_from_bytes(data[off:off + INST_BYTES]))
    r = assemble_at(data, off, "IADD3 R4, R5, 0x10, RZ", [])
    assert r["ok"], r.get("error")
    for k in ("stall", "yield", "wrbar", "rdbar", "waitmask"):
        assert r["ctrl"][k]["raw"] == cur[k]["raw"], k


#: `.reuse` 的位对应逐 opcode 不同，所以这几条得逐个真造出来。
#: `HADD2` 第二个源用 124 位、`IMAD_R_R_R_II` 的 `rc` 操作数用 123 位 ——
#: 都是「按字段起点猜」会猜错的，靠 `probe_reuse_bits()` 问 nvdisasm 才对。
REUSE_CASES = [
    "IADD3 R4, R5.reuse, R6, RZ",
    "HADD2 R3, R2.reuse, -R5.reuse",
    "IMAD.MOV.U32 R17, RZ, RZ.reuse, 0x3f800000",
    "PRMT R5, R8.reuse, 0x4321, R9.reuse",
]


@pytest.mark.parametrize("text", REUSE_CASES)
def test_reuse_from_text(site, text):
    """`.reuse` 从文本来（122:124），不是沿用原指令。"""
    data, off = site
    r = assemble_at(data, off, text, [])
    assert r["ok"], r.get("error")
    assert " ".join(r["sass"].split()).rstrip(";").strip() == text


def test_unparseable_still_reports(site):
    """段表和模板都够不着的（符号标号，留给 分支目标处理）要报错，不能假装成功。"""
    data, off = site
    r = assemble_at(data, off, "MOV R7, 32@lo(x)", [])
    assert not r["ok"] and r["error"]
