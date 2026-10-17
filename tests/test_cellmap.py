"""格子拆解的回归用例（R1/R3/R5 等标签见 `scripts/cubin_sass.py` 里 fieldscan 与段表不一致的说明）。

三条都是**静默错误**：页面照常渲染，只是名字是错的。所以钉在测试里。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import cubin_sass  # noqa: E402
from cubin_sass import (_LABEL_DEFAULT, _LABEL_ILLEGAL,  # noqa: E402
                        cell_map, fs_enum_fields, identify, modes,
                        pick_mode, segtable)
from nvisa.oracle.cubin import get_bits, set_bits  # noqa: E402

# real FFMA R9, R2, R5, R9 (execfma seed @0xc0), stored low-half-first
FFMA = "0000000502097223008fca0000000009"

pytestmark = pytest.mark.skipif(not segtable(), reason="需要 data/segtable-sm90.json")


def cell_at(enc: str, key: str, lo: int) -> dict:
    return next(c for c in cell_map(enc, key) if c["lo"] == lo)


def test_identify_ffma():
    assert identify(FFMA) == "FFMA_R_R_R_R"


# --- R1 字段可以不连续 ------------------------------------------------------
# .FMZ/.FTZ 是 bit 76 与 bit 80 组成的 2 位字段，低位是 76。段表只能劈成
# 76:77 与 80:81 两个连续格子，各自挂完整 4 值表 —— 于是 .FTZ 被标成 .FMZ。

@pytest.mark.parametrize("b76,b80,want", [
    (0, 0, _LABEL_DEFAULT),
    (1, 0, "0_FMZ"),
    (0, 1, "0_FTZ"),
    (1, 1, "0_INVALID3"),
])
def test_ffma_fmz_ftz_is_one_split_field(b76, b80, want):
    enc = set_bits(set_bits(FFMA, 76, 76, b76), 80, 80, b80)
    cell = cell_at(enc, "FFMA_R_R_R_R", 76)
    assert cell["bit_list"] == [76, 80]        # 低位在前
    assert cell["raw"] == b76 + 2 * b80
    assert cell["label"] == want


def test_ffma_split_field_emits_one_cell_not_two():
    cells = cell_map(FFMA, "FFMA_R_R_R_R")
    assert [c["lo"] for c in cells].count(80) == 0    # 80:81 不再单独成格
    assert sum(1 for c in cells if c.get("bit_list") == [76, 80]) == 1


# --- R3 `[]` 与 `null` 是两回事 ---------------------------------------------
# `[]` = 合法但不加后缀；`null` = nvdisasm 根本读不出来。过去一起被丢掉，
# 而 `" ".join(names) if names else "默认"` 把 None 也渲染成「默认」——语义正相反。

def test_default_and_illegal_are_distinct():
    cell = cell_at(FFMA, "FFMA_R_R_R_R", 77)         # .SAT，raw 0
    assert cell["label"] == _LABEL_DEFAULT
    assert cell["illegal"] == []

    imad = next(c for c in cell_map(FFMA, "IMAD_R_R_R_R") if c["lo"] == 1)
    assert imad["illegal"] == ["1"]                  # 读不出来，不是「默认」


def test_illegal_value_is_labelled_illegal():
    enc = set_bits(FFMA, 1, 1, 1)
    assert cell_at(enc, "IMAD_R_R_R_R", 1)["label"] == _LABEL_ILLEGAL


# --- 解得出 ≠ 合法 -------------------------------------------------------
# `token` 本身就是 `INVALID*`：nvdisasm 读得出、也打印了（跟 R3 的「读不出来」
# 完全是两回事），但这不是一条有意义的指令。过去页面上跟正常修饰符长得一样，
# 看不出区别。FFMA 的 bit76=1,bit80=1 -> `.INVALID3` 就是这种情况。

def test_invalid_token_is_flagged_dubious():
    enc = set_bits(set_bits(FFMA, 76, 76, 1), 80, 80, 1)
    cell = cell_at(enc, "FFMA_R_R_R_R", 76)
    assert cell["label"] == "0_INVALID3"
    assert cell.get("dubious") is True


@pytest.mark.parametrize("b76,b80", [(0, 0), (1, 0), (0, 1)])
def test_valid_token_is_not_flagged_dubious(b76, b80):
    enc = set_bits(set_bits(FFMA, 76, 76, b76), 80, 80, b80)
    cell = cell_at(enc, "FFMA_R_R_R_R", 76)
    assert not cell.get("dubious")


def test_illegal_value_is_not_flagged_dubious():
    # 读不出来（illegal）跟"读得出但是 INVALID token"（dubious）是两个不同的
    # 告警——illegal 已经有 .bad 样式，不需要 dubious 再标一次。
    enc = set_bits(FFMA, 1, 1, 1)
    assert not cell_at(enc, "IMAD_R_R_R_R", 1).get("dubious")


# --- R5 opcode 区不是修饰符 -------------------------------------------------
# IMAD 的 bit 1 被段表标成 enum（0_WIDE / 0_HI），而 fieldscan 的 layout 说
# 它是 {"kind": "opcode", "to": "IDP_R_R_R_R"} —— 翻它是换成另一条指令。

def test_opcode_bit_is_not_an_editable_enum():
    cell = cell_at(FFMA, "IMAD_R_R_R_R", 1)
    assert cell["kind"] == "opcode_sel"
    assert not cell.get("editable")
    assert "IDP_R_R_R_R" in cell["tag"]


def test_modifier_bit_next_to_it_stays_editable():
    cell = cell_at(FFMA, "IMAD_R_R_R_R", 0)          # bit 0 是真修饰符
    assert cell["kind"] == "enum" and cell["editable"]


def test_mode_specific_enum_is_not_inherited_into_a_measured_illegal_mode(monkeypatch):
    """mode 1 的字段不能泄漏到 mode 0 已判非法的同一位。"""
    low = sum(get_bits(FFMA, b, b) << b for b in range(9))
    carriers = [f"{low & ~1:x}", f"{low | 1:x}"]
    monkeypatch.setattr(cubin_sass, "_mode_cache", {
        "K": {"select_bits": [0], "carriers": carriers},
    })
    monkeypatch.setattr(cubin_sass, "_fs_cache", {
        "K": {
            "fields": [{"mode": 1, "bit_list": [24],
                        "values": {"0": [], "1": ["0_X"]}}],
            "mode_layouts": [
                {"mode": 0, "layout": {"24": {"kind": "illegal"}}},
                {"mode": 1, "layout": {"24": {"kind": "modifier"}}},
            ],
        },
    })
    mode0 = set_bits(FFMA, 0, 0, 0)
    mode1 = set_bits(FFMA, 0, 0, 1)
    assert fs_enum_fields("K", mode0) == []
    assert [f["bit_list"] for f in fs_enum_fields("K", mode1)] == [[24]]


# --- R2 mode：按选择位反查载体，选中正确的那张子表 -------------------------
# mode 是低 12 位 opcode 区的一个取值（载体）。同一个 InsKey 在不同载体下修饰符
# 取值表不同：ATOM 的浮点档只在浮点载体上测得到。载体编码 fieldscan 没落盘，
# 实测数据见 data/modes-sm90.json。

modes_missing = pytest.mark.skipif(not modes(), reason="需要 data/modes-sm90.json")


def with_low_bits(enc: str, value: int, nbits: int = 12) -> str:
    """把低 nbits 位换成 value —— 用来把一条编码挪到指定的模式载体上。"""
    for b in range(nbits):
        enc = set_bits(enc, b, b, (value >> b) & 1)
    return enc


@modes_missing
@pytest.mark.parametrize("key", ["IMAD_R_R_R_R", "ATOM_P_R_dARI_R"])
def test_every_carrier_is_picked_back(key):
    ent = modes()[key]
    for i, carrier in enumerate(ent["carriers"]):
        enc = with_low_bits(FFMA, int(carrier, 16) & 0xFFF)
        assert pick_mode(key, enc) == i


@modes_missing
def test_imad_mov_label_only_under_its_own_carrier():
    ent = modes()["IMAD_R_R_R_R"]
    assert ent["select_bits"] == [0, 1]
    mov = with_low_bits(FFMA, int(ent["carriers"][0], 16) & 0xFFF)
    f = next(x for x in fs_enum_fields("IMAD_R_R_R_R", mov) if x["bit_list"] == [0])
    assert f["values"][0] == "0_MOV" and not f["unresolved"]

    other = with_low_bits(FFMA, int(ent["carriers"][1], 16) & 0xFFF)
    f = next(x for x in fs_enum_fields("IMAD_R_R_R_R", other) if x["bit_list"] == [0])
    assert f["unresolved"] is True             # mode 1 没测这一位组，名字未必适用


@modes_missing
def test_atom_float_table_only_under_float_carrier():
    """整数载体给整数档（`.S32` / `.64`），浮点载体给浮点档（`.F64` / `.BF16x4`）。
    过去两张表要么只剩整数档，要么同时摆出来 —— 73 位那批位有两种划分。"""
    ent = modes()["ATOM_P_R_dARI_R"]
    tables = []
    for carrier in ent["carriers"]:
        enc = with_low_bits(FFMA, int(carrier, 16) & 0xFFF)
        fs = fs_enum_fields("ATOM_P_R_dARI_R", enc)
        at73 = [f for f in fs if f["bit_list"][0] == 73]
        assert len(at73) == 1                  # 同一批位只能有一张表
        tables.append(set(at73[0]["values"].values()))
    assert any("0_S32" in t for t in tables)
    assert any(any(n.startswith("0_F64") or "0_BF16x4" in n for n in t) for t in tables)
    assert tables[0] != tables[1]


@modes_missing
def test_single_mode_key_is_never_unresolved():
    for f in fs_enum_fields("FFMA_R_R_R_R", FFMA):
        assert f["unresolved"] is False


# ---------------------------------------------------------------------------
# operand 格子可就地编辑
# ---------------------------------------------------------------------------

#: 验收用例：`LDG.E R7, desc[UR4][R2.64+0x8]` 的地址立即数改成 0x20。
LDG = "0000080402077981000ea8000c1e1900"


def test_operand_cells_editable():
    """operand 格子要带 `bit_list`/`editable` 下发 —— 前端就地编辑靠这两个。"""
    cells = [c for c in cell_map(LDG, identify(LDG)) if c["kind"] == "operand"]
    assert cells, "LDG 应该有 operand 格"
    for c in cells:
        assert c["editable"] and c["bit_list"] and c["slot"] is not None, c


def test_split_operand_merged_into_one_cell():
    """一个操作数被段表劈成几段时要并成一格：用户想改的是那个立即数，
    不是它的低两位。合并后 `bit_list` 低位在前，逐格 raw 拼得回原值。"""
    for enc, key in [(LDG, identify(LDG)), (FFMA, "FFMA_R_R_R_R")]:
        cells = [c for c in cell_map(enc, key) if c["kind"] == "operand"]
        slots = [c["slot"] for c in cells]
        assert len(slots) == len(set(slots)), f"{key} 同一个 slot 出现了多格"
        for c in cells:
            assert c["bit_list"] == sorted(c["bit_list"])


def test_edit_address_immediate():
    """把 `[R2.64+0x8]` 的 0x8 改成 0x20，不用整条重敲。"""
    from cubin_sass import disasm_one
    from nvisa.oracle.cubin import enc_to_bytes

    key = identify(LDG)
    assert disasm_one(enc_to_bytes(LDG)) == "LDG.E R7, desc[UR4][R2.64+0x8]"
    cell = next(c for c in cell_map(LDG, key)
                if c["kind"] == "operand" and c["tag"] == "Imme.Addr")
    enc = LDG
    for i, b in enumerate(cell["bit_list"]):          # 前端 setBits() 的同款写法
        enc = set_bits(enc, b, b, (0x20 >> i) & 1)
    assert disasm_one(enc_to_bytes(enc)) == "LDG.E R7, desc[UR4][R2.64+0x20]"


# ---------------------------------------------------------------------------
# 弱证据的格子编辑时要有警示
# ---------------------------------------------------------------------------

def test_weak_trust_reaches_editable_cells():
    """`trust` 要跟到**可编辑**的格子上 —— 前端 `attachTrustHint()` 就靠
    这个字段决定编辑时摆不摆提示。查看时这句话在 tooltip 里，可编辑的格子一旦
    被输入框/下拉框替换掉，tooltip 也就没了，正是最需要它的时候。

    段表里 `thin`/`borrowed` 各有几百格，但枚举值只在逐值复测后才会生成，故不应
    人为制造“弱证据 enum”。这里钉的是两种弱证据都实际传到可编辑 operand；否则
    这个提示等于永远不出现。"""
    zero = "0" * 32
    seen = set()
    for key, ent in segtable().items():
        want = {(c["kind"], c["trust"]) for c in ent["cells"]
                if c.get("trust") in ("thin", "borrowed")
                and c["kind"] in ("operand", "enum")}
        if not want or seen >= want:
            continue
        for c in cell_map(zero, key):
            if (c["kind"] in ("operand", "enum")
                    and c.get("trust") in ("thin", "borrowed")
                    and c.get("editable", True)):
                seen.add((c["kind"], c["trust"]))
    assert {k for k, _ in seen} == {"operand"}, seen
    assert {t for _, t in seen} == {"thin", "borrowed"}, seen


@pytest.mark.parametrize("tag,raw,want", [
    ("R", 255, "RZ"), ("R.Addr", 4, "R4"),
    ("UR", 63, "URZ"), ("UR.Desc", 4, "UR4"), ("UR.CBank", 5, "UR5"),
    ("P", 7, "PT"), ("P", 3, "P3"), ("UP", 7, "UPT"), ("UP", 2, "UP2"),
    ("P.Guard", 8, "@!P0"), ("II", 16, "0x10"),
])
def test_register_cells_are_labelled_by_name(tag, raw, want):
    """格子 label 就是编辑框的初始值，必须是 `parseOperand()` 认得的写法。"""
    assert cubin_sass._cell_label({"kind": "operand", "tag": tag}, raw) == want
