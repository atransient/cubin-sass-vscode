"""插入/删除指令。

判据不看我们自己写进去的位，一律交回 nvdisasm：挪过的指令逐字不变、分支仍指向
同一条指令、`.nv.info` 记的指令偏移跟着走。做不到的场景必须**拒绝**，不能留下
半个改坏的文件 —— 这类改动一旦悄悄写错，后面所有时序实验都建在沙子上。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import (build, delete_at, insert_at,          # noqa: E402
                        segtable)
from nvisa.model.reflow import (ReflowError, Shift,           # noqa: E402
                                relocate_branches)
from nvisa.oracle import discache                             # noqa: E402

CORPUS = ROOT / "corpus" / "cubins"
#: 单函数 + 尾部有对齐填充 NOP：插入/删除都做得了
SIMPLE = CORPUS / "fma.sm_90.cubin"
#: 两个函数（kernel + helper），kernel 里有三条 CALL.REL 指向 helper
TWOFN = CORPUS / "control.sm_90.cubin"

pytestmark = pytest.mark.skipif(
    not (segtable() and SIMPLE.exists() and TWOFN.exists()),
    reason="需要 data/segtable-sm90.json 与 corpus/cubins/")

INSERTED = "IADD3 R4, R5, 0x10, RZ"


def test_relocate_refuses_jmxu_like_every_indirect_jump(monkeypatch):
    """JMXU 的目标不在 PC-relative slot，定长 reflow 必须保守拒绝。"""
    import cubin_sass
    monkeypatch.setattr(cubin_sass, "identify", lambda _enc: "JMXU_R")
    with pytest.raises(ReflowError, match="JMXU"):
        relocate_branches({0: "0" * 32}, Shift(0, 32, 16),
                          {0: "JMXU R0"})


def disasm(data: bytes, tmp_path: Path) -> dict[int, str]:
    """{地址: 文本}，问 nvdisasm。判据还是它自己的答案，只是走
    `discache`（按文件内容缓存）—— 这些测试一轮要问十几次，每次 ~0.3 秒。"""
    p = tmp_path / "x.cubin"
    p.write_bytes(data)
    got = discache.text_by_addr(p)
    if not got:
        pytest.skip("nvdisasm 跑不了")
    return got


def site(path: Path, n: int = 4) -> tuple[bytes, int, int]:
    data = path.read_bytes()
    ins = build(path, None)["sections"][0]["insns"][n]
    return data, ins["file_off"], ins["addr"]


def test_insert_shifts_everything_down_one_slot(tmp_path):
    """插入之后：这一行是新指令，原来这一行往后的每条整体下移一格且逐字不变。"""
    data, off, addr = site(SIMPLE)
    before = disasm(data, tmp_path)
    r = insert_at(data, off, INSERTED, [])
    assert r["ok"], r
    after = disasm(bytes.fromhex(r["data"]), tmp_path)

    assert after[addr] == INSERTED
    for a in sorted(before):
        if a < addr:
            assert after[a] == before[a], f"{a:#x} 上面的指令不该动"
        elif a < r["dropped"]:
            assert after[a + 16] == before[a], f"{a:#x} 挪完之后变了"
    assert len(after) == len(before)          # 段大小不变，末尾那条 NOP 被吃掉


def test_delete_shifts_up_and_pads_with_nop(tmp_path):
    """删除之后：后面的整体上移一格，窗口末尾补一条 NOP。"""
    data, off, addr = site(SIMPLE)
    before = disasm(data, tmp_path)
    r = delete_at(data, off)
    assert r["ok"], r
    after = disasm(bytes.fromhex(r["data"]), tmp_path)

    for a in sorted(before):
        if a > addr:
            assert after[a - 16] == before[a], f"{a:#x} 挪完之后变了"
    assert after[max(after)] == "NOP"


def test_insert_then_delete_is_byte_identical():
    """插进去再删掉，必须一个字节不差地回到原样 —— 包括 `.nv.info` 里那个
    指令偏移。差一个字节就说明某处的重定位不是可逆的。"""
    data, off, _ = site(SIMPLE)
    ins = insert_at(data, off, INSERTED, [])
    back = delete_at(bytes.fromhex(ins["data"]), off)
    assert bytes.fromhex(back["data"]) == data


def test_nvinfo_instruction_offsets_follow(tmp_path):
    """`EIATTR_EXIT_INSTR_OFFSETS` 直接记着 EXIT 那条在函数里的偏移 ——
    指令挪了不改，它就指到别条上去了。"""
    data, off, _ = site(SIMPLE)
    r = insert_at(data, off, INSERTED, [])
    changed = {c["attr"]: c for c in r["nvinfo"]}
    assert "EIATTR_EXIT_INSTR_OFFSETS" in changed, r["nvinfo"]
    c = changed["EIATTR_EXIT_INSTR_OFFSETS"]
    assert c["now"] == c["was"] + 16
    after = disasm(bytes.fromhex(r["data"]), tmp_path)
    assert after[c["now"]] == "EXIT"          # 改完确实还指着 EXIT


def test_branch_targets_are_relocated(tmp_path):
    """删掉一条之后，跨过删除点的 `CALL.REL` 仍要指到同一个函数上。
    `.REL` 是靠改偏移位保住的 —— 整条重新汇编反而做不到（段表把
    `CALL.REL`/`CALL.ABS` 并成了同一个 key，见 分支目标处理 的落地记录）。"""
    data = TWOFN.read_bytes()
    r = delete_at(data, 0x6B0)
    assert r["ok"], r
    assert [x["mnemonic"] for x in r["relocated"]] == ["CALL.REL.NOINC"] * 3
    assert all(x["target"] == x["new_target"] for x in r["relocated"])
    after = disasm(bytes.fromhex(r["data"]), tmp_path)
    calls = [t for t in after.values() if t.startswith("CALL")]
    assert len(calls) == 3
    assert all("$_Z6helperi" in t for t in calls), calls


def test_refuses_to_cross_a_function_boundary():
    """窗口跨到下一个函数就要改符号表和 `.debug_frame` 的加数 —— 那是「改一个
    程序」，插入/删除 不做，明确拒绝。"""
    data = TWOFN.read_bytes()
    with pytest.raises(ReflowError, match="NOP"):
        insert_at(data, 0x6B0, INSERTED, [])


def test_refuses_when_the_deleted_instruction_is_a_branch_target():
    """要删的那条正好是别人的跳转目标 —— 目标没了，拒绝。"""
    data = TWOFN.read_bytes()
    sec_off = build(TWOFN, None)["sections"][0]["insns"][0]["file_off"]
    with pytest.raises(ReflowError, match="目标"):
        delete_at(data, sec_off + 0xD40)      # 0x70 那条 BRA 指着它
