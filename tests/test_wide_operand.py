"""大位宽 operand 与严格输入解析。

后端这一半管两件事：**宽字段的 JSON 传输**（>32 位额外发 `raw_str`，因为
`JSON.parse` 把大整数变成 double）和 **PC 相对的 `II` 槽要标出来**（编码里存的
是偏移，不是目标地址）。前端那一半（BigInt 位运算、严格数字解析）在
`test/bits.test.js`，最后一条用例把它带起来。
"""
from __future__ import annotations

import glob
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import build, cell_map, segtable          # noqa: E402
from nvisa.model import asm_spec                                    # noqa: E402

CUBINS = sorted(glob.glob(str(ROOT / "corpus/cubins/*.cubin")))
pytestmark = pytest.mark.skipif(not segtable(),
                                reason="需要 data/segtable-sm90.json")

#: 段表里最宽的那几个 operand 槽（按 (slot, tag) 合并之后的位宽）。
WIDE_KEYS = ["WARPSYNC_R_II", "CALL_R_II", "BRA_II"]


def width_of(c: dict) -> int:
    """一格的位宽 —— 与 `cubin_sass._wide()` 同一条：有 `bit_list` 用它，
    没有就按 `lo..hi` 连续算。"""
    return len(c.get("bit_list") or range(c["lo"], c["hi"] + 1))


def merged_widths(key: str) -> dict[tuple, int]:
    out: dict[tuple, int] = {}
    for c in segtable()[key]["cells"]:
        if c["kind"] == "operand":
            lo, hi = c["bits"]
            out[(c.get("slot"), c.get("tag"))] = out.get((c.get("slot"), c.get("tag")), 0) \
                + hi - lo
    return out


def test_segtable_really_has_wide_slots():
    """P2-S 后仍有大槽，但 WARPSYNC 的 56 位不能再伪装成连续 81 位。"""
    widest = max(w for k in segtable() for w in merged_widths(k).values())
    assert widest >= 58, widest
    assert max(merged_widths("WARPSYNC_R_II").values()) == 56


@pytest.mark.parametrize("key", WIDE_KEYS)
def test_wide_cells_carry_raw_str(key):
    """>32 位的格子必须带 `raw_str` —— 前端只信它，不信那个 JSON 数字。"""
    if key not in segtable():
        pytest.skip(f"段表里没有 {key}")
    enc = "f" * 32                       # 全 1：每一格都取到位宽的最大值
    wide = [c for c in cell_map(enc, key) if width_of(c) > 32]
    assert wide, f"{key} 应该有超过 32 位的格子"
    for c in wide:
        assert "raw_str" in c, c
        assert int(c["raw_str"]) == c["raw"]
        assert int(c["raw_str"]) < (1 << width_of(c))
        # 就是它超出 double 的原因：>2^53 的整数在 JS 里已经不是原值了
        if width_of(c) > 53:
            assert float(int(c["raw_str"])) != int(c["raw_str"]) or c["raw"] == 0


def test_narrow_cells_have_no_raw_str():
    """窄格不补 —— 免得每格都多带一个字段。"""
    enc = "f" * 32
    for c in cell_map(enc, "FFMA_R_R_R_R") or []:
        if width_of(c) <= 32:
            assert "raw_str" not in c, c


# --- PC 相对的 II 槽 --------------------------------------------------------

def test_branch_slot_marked_pc_relative():
    """`BRA` 的 `II` 槽显示的是**绝对目标**，且明确标为不可就地编辑。"""
    if not CUBINS:
        pytest.skip("需要 corpus/cubins/")
    found = 0
    for path in map(Path, CUBINS):
        data = path.read_bytes()
        for sec in build(path, None, data)["sections"]:
            for i in sec["insns"]:
                if not (i.get("sass") or "").startswith(("BRA", "CALL", "RET")):
                    continue
                pc = [c for c in (i["cells"] or []) if c.get("pc_relative")]
                if not pc:
                    continue                       # 这个 key 没验过偏移规则
                found += 1
                for c in pc:
                    assert c["editable"] is False, c
                    assert c["label"] == f"→ {c['target']:#x}"
                    # 目标 = 本条地址 + 指令长 + 编码里的偏移，与 分支目标处理 同一条规则
                    fact = asm_spec.pc_offset_fact(i["key"])
                    assert c["target"] == i["addr"] + fact["insn_len"] \
                        + asm_spec.read_offset(fact, i["enc"])
    if not found:
        pytest.skip("语料里没有验过偏移规则的分支")


def test_pc_relative_without_addr_shows_offset():
    """不给 `addr`（单条 inspect）时退回显示相对偏移，不假装知道目标。"""
    key = "BRA_II"
    if not asm_spec.pc_offset_fact(key):
        pytest.skip("BRA_II 没有 pc_offset 规则")
    cells = [c for c in cell_map("0" * 32, key) if c.get("pc_relative")]
    assert cells and "target" not in cells[0]
    assert "相对下一条" in cells[0]["label"]


# --- 前端那一半 -------------------------------------------------------------

@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 跑前端测试")
def test_node_bits_suite():
    """`media/bits.js`：BigInt 位运算 + 严格数字解析（`0x10junk`/`12abc` 拒绝、
    56/64/81 位边界）。跑全仓库测试时顺带把它带起来。"""
    r = subprocess.run(["node", "--test",
                        str(ROOT / "test/bits.test.js")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
