"""批量编辑：导出/应用 JSON patch。

验收就是那句话：手工改几处导出 patch，在**另一个 cubin 副本**上能复现同样的
改动。两条打法各测一遍（照抄编码 / 按文本重新汇编），外加安全闸和
`probe()` 扫描记录的互喂方向。
"""
from __future__ import annotations

import glob
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import (INST_BYTES, apply_patch, assemble_at,     # noqa: E402
                        build, cell_map, disasm_one, export_patch, segtable)
from nvisa.oracle.cubin import enc_to_bytes, set_bits             # noqa: E402

CUBINS = sorted(glob.glob(str(ROOT / "corpus/cubins/*.cubin")))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins/")


@pytest.fixture(scope="module")
def edited():
    """(cubin 路径, 原字节, 改过 3 处的字节) —— 两处格子级 + 一条整条重敲。"""
    src = Path(CUBINS[0])
    base = src.read_bytes()
    data = bytearray(base)
    insns = [i for s in build(src, None, base)["sections"]
             for i in s.get("insns", []) if i.get("sass")]
    done = 0
    for i in insns[1:]:
        if done >= 2:
            break
        op = [c for c in (cell_map(i["enc"], i["key"]) or [])
              if c["kind"] == "operand" and c["tag"] in ("R", "Imme.Addr")]
        if not op:
            continue
        c = op[0]
        enc, new = i["enc"], (c["raw"] + 1) % (1 << len(c["bit_list"]))
        for j, bit in enumerate(c["bit_list"]):
            enc = set_bits(enc, bit, bit, (new >> j) & 1)
        if not disasm_one(enc_to_bytes(enc)):
            continue                       # 撞上非法编码，换下一条
        data[i["file_off"]:i["file_off"] + INST_BYTES] = enc_to_bytes(enc)
        done += 1
    if done < 2:
        pytest.skip("语料里凑不出两处可改的操作数格")
    off = insns[0]["file_off"]
    r = assemble_at(bytes(data), off, "LOP3.LUT R10, R8, R11, RZ, 0x3c, !PT", [])
    assert r["ok"], r.get("error")
    data[off:off + INST_BYTES] = bytes.fromhex(r["bytes"])
    return src, base, bytes(data)


def test_export_lists_every_change(edited):
    src, base, data = edited
    p = export_patch(src, data, base)
    assert p["count"] == 3, p
    for e in p["edits"]:
        # `enc` + `origin` 跟批量扫描工具的产出对得上
        assert e["enc"] and e["origin"] and e["sass"]
        assert e["before"]["enc"] and e["before"]["enc"] != e["enc"]


def test_apply_reproduces_on_a_copy(edited):
    """patch 打到干净副本上，结果与手改的逐字节相同。"""
    src, base, data = edited
    got = apply_patch(src, base, export_patch(src, data, base))
    assert got["ok"] and got["applied"] == 3, got
    assert bytes.fromhex(got["data"]) == data


def test_apply_by_sass_reassembles(edited):
    """`--by-sass`：不照抄编码，按文本重新汇编（走 `assemble_at()`）。文本必须一致；
    编码不一定逐字节相同——控制段沿用目标那条指令，这是**故意**的。"""
    src, base, data = edited
    patch = export_patch(src, data, base)
    got = apply_patch(src, base, patch, by_sass=True)
    assert got["ok"] and got["applied"] == 3, got
    for r, e in zip(got["results"], patch["edits"]):
        assert r["sass"].split() == e["sass"].split()


def test_before_guard(edited):
    """安全闸：目标偏移上不是 patch 记的那条就拒绝，`force` 才照打。"""
    src, base, data = edited
    patch = export_patch(src, data, base)
    blocked = apply_patch(src, data, patch)          # 打到已经改过的副本上
    assert not blocked["ok"] and blocked["applied"] == 0
    assert all("--force" in r["error"] for r in blocked["results"])
    assert apply_patch(src, data, patch, force=True)["applied"] == 3


def test_scan_records_need_a_location(edited):
    """`probe()` 的扫描记录只有 `{enc, origin}`，没有位置 —— 要 `--at`。"""
    src, base, data = edited
    rec = [{"arch": "sm_90", "enc": export_patch(src, data, base)["edits"][0]["enc"],
            "origin": "fuzz:base.cubin@0x0:scan[16:23]=10"}]
    with pytest.raises(ValueError, match="--at"):
        apply_patch(src, base, rec)
    off = export_patch(src, data, base)["edits"][0]["file_off"]
    got = apply_patch(src, base, rec, at=off)
    assert got["ok"] and got["applied"] == 1, got
