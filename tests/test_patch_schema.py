"""patch 的 schema、事务性与 插入/删除 互操作。

三件事：
① **带版本的 schema**：版本/架构/模式/操作类型对不上就整份拒绝；
② **事务性**：默认 all-or-nothing，`--partial` 才允许部分成功；
③ **只表达原地替换**：布局一变（插入/删除 改了 `.nv.info`）就拒绝导出；跨 cubin 复现
   时位置按 `(section, addr)` 落、PC 相对分支目标按新地址重定位。
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import (INST_BYTES, PATCH_FORMAT, PatchError,      # noqa: E402
                        _relocate_sass, _resolve_site, apply_patch,
                        build, export_patch, insert_at, segtable)

CORPUS = ROOT / "corpus" / "cubins"
SIMPLE = CORPUS / "fma.sm_90.cubin"          # 单函数 + 尾部填充 NOP（同 插入/删除 的用例）
pytestmark = pytest.mark.skipif(not (segtable() and SIMPLE.exists()),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins/")


@pytest.fixture(scope="module")
def one_edit():
    """(路径, 原字节, 改了一条的字节, patch)。改的是控制段的 stall —— 与
    段表认不认得这个 key 无关，任何语料上都造得出来。"""
    from nvisa.model import asm
    from nvisa.oracle.cubin import enc_to_bytes, get_bits, set_bits
    base = SIMPLE.read_bytes()
    data = bytearray(base)
    for i in build(SIMPLE, None, base)["sections"][0]["insns"]:
        if not i.get("sass"):
            continue
        lo, hi = asm.FIELDS["stall"]
        enc = set_bits(i["enc"], lo, hi, (get_bits(i["enc"], lo, hi) + 1) % 16)
        data[i["file_off"]:i["file_off"] + INST_BYTES] = enc_to_bytes(enc)
        break
    else:
        pytest.skip("语料里没有解得出的指令")
    patch = export_patch(SIMPLE, bytes(data), base)
    assert patch["ok"] and patch["count"] == 1, patch
    return SIMPLE, base, bytes(data), patch


# --- ① schema ---------------------------------------------------------------

def test_export_writes_versioned_schema(one_edit):
    _src, _base, _data, p = one_edit
    assert p["format"] == PATCH_FORMAT and p["arch"] == "SM90"
    assert p["mode"] == "in-place"
    for e in p["edits"]:
        assert e["op"] == "replace"
        assert e["section"] and e["addr"] % INST_BYTES == 0
        assert e["file_off"] is not None and e["enc"] and e["before"]["enc"]


@pytest.mark.parametrize("mutate,why", [
    (lambda p: p.update(format="nv_isa-cubin-patch/99"), "版本"),
    (lambda p: p.update(format=None), "版本"),
    (lambda p: p.update(arch="SM80"), "架构"),
    (lambda p: p.update(mode="reflow"), "模式"),
    (lambda p: p["edits"][0].update(op="insert"), "操作"),
    (lambda p: p["edits"][0].update(op="rebase"), "操作"),
])
def test_bad_schema_rejected_whole(one_edit, mutate, why):
    """错误版本/架构/模式/操作类型：整份拒绝，一条都不打，不产生部分输出。"""
    src, base, _data, p = one_edit
    bad = copy.deepcopy(p)
    mutate(bad)
    res = apply_patch(src, base, bad)
    assert not res["ok"] and res["applied"] == 0 and res["data"] is None, why
    assert res["error"], why


def test_v1_patch_still_reads(one_edit):
    """v1 是历史格式：没有 arch/mode/op，按 in-place/replace 补齐后照样能打。"""
    src, base, data, p = one_edit
    old = {"format": "nv_isa-cubin-patch/1", "file": p["file"],
           "count": p["count"],
           "edits": [{k: v for k, v in e.items() if k != "op"} for e in p["edits"]]}
    res = apply_patch(src, base, old)
    assert res["ok"] and bytes.fromhex(res["data"]) == data


# --- ② 事务性 ---------------------------------------------------------------

def _two_edits(p, base):
    """一份两条的 patch：第一条打得成，第二条位置非法（必然失败）。"""
    bad = copy.deepcopy(p)
    e = copy.deepcopy(bad["edits"][0])
    e.update(file_off=8, addr=8, section=bad["edits"][0]["section"],
             origin="故意非法：不在指令边界上")
    bad["edits"].append(e)
    bad["count"] = 2
    return bad


def test_partial_failure_produces_nothing(one_edit):
    """默认 all-or-nothing：中途失败不留下改了一半的文件。"""
    src, base, _data, p = one_edit
    res = apply_patch(src, base, _two_edits(p, base))
    assert not res["ok"] and res["applied"] == 1 and res["failed"] == 1
    assert res["data"] is None, "失败了还吐字节，就会有人拿去用"


def test_partial_flag_allows_half(one_edit):
    """`--partial` 显式允许部分成功 —— 打成的那条要真的落进字节里。"""
    src, base, data, p = one_edit
    res = apply_patch(src, base, _two_edits(p, base), partial=True)
    assert not res["ok"] and res["applied"] == 1 and res["partial"]
    assert bytes.fromhex(res["data"]) == data


# --- ③ 只表达原地替换：插入/删除 互操作 --------------------------------------------

def test_export_refuses_after_reflow():
    """插入/删除 之后导出：`.nv.info` 的指令偏移变了，patch 表达不了 —— 明确拒绝。
    没动 `.nv.info` 的那种 reflow 则要能在副本上**完整复现**（验收给的两条路，
    这里逐个 cubin 认哪条走得通）。"""
    base = SIMPLE.read_bytes()
    ins = build(SIMPLE, None, base)["sections"][0]["insns"][4]
    r = insert_at(base, ins["file_off"], "IADD3 R4, R5, 0x10, RZ")
    assert r["ok"], r
    after = bytes.fromhex(r["data"])
    p = export_patch(SIMPLE, after, base)
    if not p["ok"]:
        assert "原地替换" in p["error"]
        return
    # 没被拒 -> 必须在干净副本上逐字节复现（含 .nv.info，它这次没变）
    got = apply_patch(SIMPLE, base, p)
    assert got["ok"], got
    assert bytes.fromhex(got["data"]) == after


def test_export_refuses_when_layout_changes(one_edit):
    """文件长度/段布局变了：schema 说不出这种事，拒绝导出。"""
    src, base, data, _p = one_edit
    grown = export_patch(src, data + b"\x00" * 16, base)
    assert not grown["ok"] and "长度" in grown["error"]


def test_export_refuses_changes_outside_exec(one_edit):
    """可执行段之外的字节变了（`.nv.info`、符号表……）：同样拒绝。"""
    src, base, data, _p = one_edit
    buf = bytearray(data)
    # 挑一段可执行段之外、又不在 ELF 头里的字节（改 magic 是另一回事）
    off = next(lo for lo, hi in _outside(base) if lo >= 0x40 and hi - lo >= 8)
    buf[off] ^= 0xFF
    res = export_patch(src, bytes(buf), base)
    assert not res["ok"] and "可执行段之外" in res["error"]


def _outside(data: bytes):
    from cubin_sass import _outside_exec
    return _outside_exec(data)


# --- ③ 跨 cubin：section/function 身份 + 分支重定位 --------------------------

def test_location_follows_section_not_file_offset(one_edit):
    """位置的权威是 `(section, addr)`：文件偏移记错了也要落对地方。"""
    src, base, data, p = one_edit
    moved = copy.deepcopy(p)
    moved["edits"][0]["file_off"] = 0            # 故意记成 ELF 头
    res = apply_patch(src, base, moved)
    assert res["ok"], res
    assert res["results"][0]["relocated"]
    assert bytes.fromhex(res["data"]) == data


def test_unknown_section_rejected(one_edit):
    """目标 cubin 里没有这个 section —— section 名就是函数身份，对不上就拒绝。"""
    src, base, _data, p = one_edit
    other = copy.deepcopy(p)
    other["edits"][0]["section"] = ".text._Z_not_here"
    res = apply_patch(src, base, other)
    assert not res["ok"] and res["data"] is None
    assert "section" in res["results"][0]["error"]
    # --force 才退回按文件偏移硬打
    assert apply_patch(src, base, other, force=True)["ok"]


def test_resolve_site_needs_a_location():
    with pytest.raises(PatchError):
        _resolve_site(SIMPLE.read_bytes(), {"origin": "x"}, False)


def test_branch_target_relocated_to_new_address():
    """PC 相对分支：patch 记的是源 cubin 的绝对目标，挪到别的地址要按
    「跳多远」重算 —— 新目标 = 旧目标 − 源地址 + 目标地址。"""
    e = {"sass": "BRA 0x190", "addr": 0x180, "key": "BRA_II"}
    text, comparable = _relocate_sass(e, 0x180, False)
    assert (text, comparable) == ("BRA 0x190", True)          # 没挪就不改
    text, comparable = _relocate_sass(e, 0x200, False)
    assert comparable and text == "BRA 0x210", text           # 跳距 +0x10 保住了


def test_absolute_and_label_targets_refused():
    """两类明确拒绝：符号标号（地址不在指令身上）和 `.ABS`（源 cubin 的坐标）。"""
    lab = {"sass": "BRA `(.L_x_0)", "addr": 0x180, "key": "BRA_II"}
    assert _relocate_sass(lab, 0x200, False)[1] is False       # 照抄编码可以
    with pytest.raises(PatchError, match="符号标号"):
        _relocate_sass(lab, 0x200, True)                       # 按文本重汇编不行
    ab = {"sass": "CALL.ABS.NOINC 0x0", "addr": 0x180, "key": "CALL_II"}
    with pytest.raises(PatchError, match="ABS"):
        _relocate_sass(ab, 0x200, False)


def test_non_branch_text_untouched():
    e = {"sass": "IADD3 R4, R5, 0x10, RZ", "addr": 0x180, "key": "IADD3_R_R_II_R"}
    assert _relocate_sass(e, 0x900, True) == ("IADD3 R4, R5, 0x10, RZ", True)
