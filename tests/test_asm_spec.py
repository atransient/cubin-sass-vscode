"""文本 ⇄ 语义值翻译层 —— `nvisa/model/asm_spec.py`。

判据同 编码往返：`text_to_values` 造出的 `values` 喂给 `encode_spec`，nvdisasm 读回的
文本必须与原文本逐字相同。这是 编码往返 往返（`test_encode.py`）的前半段接上文本层。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import identify, segtable                      # noqa: E402
from nvisa.model.asm_spec import (AsmSpecError, spec_keys,      # noqa: E402
                                  _parse, pc_offset_fact, semantic_profile,
                                  text_to_values, values_to_text)
from nvisa.model.keys import canonical_key                     # noqa: E402
from nvisa.model.encode import decode_spec, encode_spec         # noqa: E402
from nvisa.oracle.cubin import enc_to_int                      # noqa: E402
from nvisa.oracle.nvdisasm import Nvdisasm                     # noqa: E402

pytestmark = pytest.mark.skipif(not segtable(), reason="需要 data/segtable-sm90.json")

#: (编码, 文本) —— 覆盖寄存器 / 立即数 / 常量 bank / 枚举 / 取反
CASES = [
    ("0000000602027210000fe20007ffe1ff", "IADD3 R2, R2, R6, RZ"),
    ("00000a00ff017b82000fe20000000800", "LDC R1, c[0x0][0x28]"),
    ("0000000000007918000fc00000000000", "NOP"),
]


@pytest.mark.parametrize("enc,text,key", [
    ("ffffffffff067808000fca0000800000", "FSEL R6, RZ, -QNAN, P1", "FSEL_R_R_FI_P"),
    ("c1b80000ff0d7808000fe40000800000", "FSEL R13, RZ, -23, P1", "FSEL_R_R_FI_P"),
])
def test_fsel_full_float_immediate_roundtrips(enc, text, key):
    """P1-B：FSEL 的 FI 是完整 F32，不是只保留高 9 位。"""
    # 文本汇编没有“原编码”可继承，未解释的非语义位可与原样不同；判据是
    # nvdisasm 文本不变。反方向则必须精确保留原编码的完整 FI 位型。
    assert values_to_text(key, text_to_values(key, text)).replace(" ", "") == text.replace(" ", "")
    assert encode_spec(key, decode_spec(enc, key)) == enc


def test_bra_any_modifier_is_encoded():
    """P1-B：生产样本证明 BRA .ANY 在 bit 84，不能被当作默认档丢掉。"""
    values = text_to_values("BRA_II", "@P1 BRA.U.ANY -0x60")
    assert values["mods"][(84,)] == 1


def test_p2s_bpt_and_warpsync_measured_slot_boundaries_roundtrip():
    """P2-S: use the measured BPT start and WARPSYNC split PC offset."""
    bpt = [c["bits"] for c in segtable()["BPT_II"]["cells"]
           if c["kind"] == "operand" and c.get("tag") == "II"]
    assert bpt == [[34, 37]]

    want = [[16, 24], [34, 82]]
    for key, text in [
        ("WARPSYNC_II", "WARPSYNC.COLLECTIVE.ALL 0xb9a0"),
        ("WARPSYNC_R_II", "WARPSYNC.COLLECTIVE R6, 0x2210"),
    ]:
        got = [c["bits"] for c in segtable()[key]["cells"]
               if c["kind"] == "operand" and c.get("tag") == "II"]
        assert got == want
        fact = pc_offset_fact(key)
        assert fact and fact["scale"] == 4 and fact["sign_bit"] == 81
        assert values_to_text(key, text_to_values(key, text)).split() == text.split()


def test_plop3_split_lut_operand_roundtrips():
    """分裂 LUT 是一个逻辑 8 位操作数：低 3 位在 64:67，高 5 位在
    72:77。文本层不能把它预先挪成物理位值，否则 0x80 的高位会丢失。"""
    key = "PLOP3_P_P_P_P_P_II_II"
    text = "PLOP3.LUT P0, P1, P0, PT, P1, 0x80, 0xc8"
    values = text_to_values(key, text)
    assert values["cells"][(64, 67)] == 0
    assert values["cells"][(72, 77)] == 0x10
    assert values_to_text(key, values).split() == text.split()


@pytest.mark.parametrize("key,text", [
    ("F2I_R_UR", "F2I.S64.F64.TRUNC R6, UR6"),
    ("I2FP_R_R", "I2FP.F32.S32 R0, R0"),
    ("I2F_R_UR", "I2F.S64 R21, UR4"),
    ("F2F_R_R", "F2F.F32.F64 R8, R8"),
    ("LDGSTS_ARI_dARI", "LDGSTS.E [R7], desc[UR6][R2.64]"),
    ("HSET2_R_R_R_P", "HSET2.BF.GT.AND R8, R2, R5, PT"),
    ("SUST_ARI_R_UR_II", "SUST.D.BA.2D.STRONG.SM.TRAP [R8], R4, UR4, 0x0"),
])
def test_semantic_profiles_preserve_joint_type_fields(key, text):
    """P1-B：profile 由样本导出，能联动类型及无命名的修饰字段。"""
    _, _, modi, _ = _parse(text)
    assert semantic_profile(key, modi) is not None
    assert values_to_text(key, text_to_values(key, text)).replace(" ", "") == text.replace(" ", "")


@pytest.mark.parametrize("enc,text", CASES)
def test_roundtrip_text_to_encoding(enc, text):
    key = identify(enc)
    assert key, enc
    values = text_to_values(key, text)
    rendered = values_to_text(key, values)
    assert rendered.split() == text.split()
    e2 = encode_spec(key, values)
    got = Nvdisasm().disassemble_raw([enc_to_int(e2)], "SM90")[0]
    assert got is not None
    assert got.text.split() == text.split()


def test_register_slots_in_text_order():
    key = identify("0000000602027210000fe20007ffe1ff")
    v = text_to_values(key, "IADD3 R2, R6, R9, RZ")
    ra_bits = next(tuple(c["bits"]) for c in segtable()[key]["cells"]
                   if c.get("tag") == "R" and c.get("slot") == 2)
    assert v["cells"][ra_bits] == 6


def test_rz_is_register_255():
    key = identify("0000000602027210000fe20007ffe1ff")
    v = text_to_values(key, "IADD3 R2, RZ, R9, RZ")
    ra_bits = next(tuple(c["bits"]) for c in segtable()[key]["cells"]
                   if c.get("tag") == "R" and c.get("slot") == 2)
    assert v["cells"][ra_bits] == 255


def test_immediate_edit_changes_only_the_immediate():
    """落脚点：改立即数不用整条重敲，text_to_values 单独接住这一格。"""
    key = "LDC_R_cARI"
    if key not in segtable():
        pytest.skip("语料没有这个 key")
    v1 = text_to_values(key, "LDC R1, c[0x0][0x28]")
    v2 = text_to_values(key, "LDC R1, c[0x0][0x30]")
    diff = {k for k in v1["cells"] if v1["cells"][k] != v2["cells"].get(k)}
    imm_bits = next(tuple(c["bits"]) for c in segtable()[key]["cells"]
                    if c.get("tag") == "Imme.Addr")
    assert diff == {imm_bits}


def test_wrong_key_is_rejected():
    """文本描述的形态跟 key 对不上（CuAssembler 认成另一个 InsKey）要报错，
    不能悄悄套用错的 key 硬编。"""
    key = identify("0000000000007918000fc00000000000")   # NOP
    with pytest.raises(AsmSpecError):
        text_to_values(key, "IADD3 R2, R2, R6, RZ")       # 明显不是 NOP


def test_register_negation_round_trips():
    """CuAssembler 的解析器（不是这个模块自己写的正则）认得 `-R2`，
    与 `asm.py` 不同——那边确实不支持，这边靠 CuInsParser 顺手拿下。"""
    key = "IADD3_R_R_R_R"
    if key not in segtable():
        pytest.skip("语料没有这个 key")
    v = text_to_values(key, "IADD3 R2, -R2, R6, RZ")
    rendered = values_to_text(key, v)
    assert rendered.split() == "IADD3 R2, -R2, R6, RZ".split()


def test_imad_hi_uses_the_mode_that_defines_hi():
    """mode 0 把 bit 1 记为非法；`.HI` 的取值表在 mode 1。"""
    key = "IMAD_R_R_II_R"
    if key not in segtable():
        pytest.skip("语料没有这个 key")
    text = "IMAD.HI R11, R6, 0x2aaaaaab, RZ"
    v = text_to_values(key, text)
    assert v["mods"][(0,)] == 1       # mode 1 的载体位；只写 bit 1 会得到非法 0x826
    assert v["mods"][(1,)] == 1
    # P2-R extends the calibrated control word through `.reuse` (bit 124),
    # so adjacent control fields intentionally merge into one 105:125 cell.
    assert v["cells"][(105, 125)] == 0x7E0
    assert values_to_text(key, v).split() == text.split()



def test_shared_modifier_token_goes_to_the_field_that_explains_more():
    """同一个 token 出现在两个字段的取值表里时，**解释得多的那个先挑**。

    `IMAD_R_R_R_R` 的 bit 0（`.MOV`/`.WIDE`）和 bit 74+75（`.MOV`、
    `.MOV`+第 4 列取反、`.X`…）都写着 `0_MOV`。token 是边匹配边从 `modi` 里
    划掉的，按 fieldscan 的天然顺序 bit 0 先把 `0_MOV` 划走，74/75 就只剩默认
    档 —— 负号编不出来，而且**不报错**，回环之前谁也看不见。
    """
    key = "IMAD_R_R_R_R"
    if key not in segtable():
        pytest.skip("语料没有这个 key")
    text = "IMAD.MOV R6, RZ, RZ, -R4"
    v = text_to_values(key, text)
    assert v["mods"][(74, 75)] == 2          # `0_MOV` + `4_cNEG` 那一档
    assert values_to_text(key, v).split() == text.split()


# --- 分支标号归一-------------------


@pytest.mark.parametrize("text, key", [
    ("BRA `(.L_x_0)", "BRA_II"),
    ("@P0 BRA `(.L_x_0) ;", "BRA_II"),
    ("BSSY B0, `(.L_1) ;", "BSSY_B_II"),
])
def test_label_form_is_first_candidate_not_enumeration_fallback(text, key):
    """标号写法的正式 key 直接算得出来，不靠 `spec_keys` 的同助记符全枚举兜底：
    它必须是**第一个**候选，而且本身就在段表里。"""
    assert canonical_key(text) == key
    assert key in segtable()
    assert spec_keys(text)[0] == key


def test_label_and_number_agree_on_key_and_candidates():
    """同一条分支的两种写法：同 key、同候选表。"""
    assert spec_keys("BRA `(.L_x_0)") == spec_keys("BRA 0x190")


def test_text_to_values_rejects_unresolved_label():
    """`text_to_values()` 没有符号表，从单行文本得不到目标地址 —— 明确拒绝，
    不是「key 认错了」。标号得先由 `sass_asm` 的第一遍符号表换成数值。"""
    with pytest.raises(AsmSpecError, match="符号标号"):
        text_to_values("BRA_II", "BRA `(.L_x_0)")
