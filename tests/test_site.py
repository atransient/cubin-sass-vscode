"""写入位置校验与保存安全闸。

验收就是那两句话：
① ELF 头、非可执行 section、非 16 字节对齐的偏移，`--assemble` / `--apply-patch`
   都得拒绝，且**不改变输出**；
② 造出非法编码之后，普通保存被阻止；要留着它得走显式的实验性入口。
"""
from __future__ import annotations

import glob
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import cubin_sass                                                   # noqa: E402
from cubin_sass import (INST_BYTES, PATCH_FORMAT, SiteError,       # noqa: E402
                        apply_patch, assemble_at, build, check_save,
                        delete_at, edit_site, insert_at, segtable)
from nvisa.oracle.cubin import Cubin                 # noqa: E402

CUBINS = sorted(glob.glob(str(ROOT / "corpus/cubins/*.cubin")))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins/")


@pytest.fixture(scope="module")
def sample():
    """(路径, 字节, 一条真指令的文件偏移, 它的文本)。"""
    src = Path(CUBINS[0])
    data = src.read_bytes()
    for sec in build(src, None, data)["sections"]:
        for i in sec.get("insns", []):
            if i.get("sass"):
                return src, data, i["file_off"], i["sass"]
    pytest.skip("语料里没有解得出的指令")


def bad_offsets(data: bytes) -> dict[str, int]:
    """三类非法位置：ELF 头、非可执行 section、不在指令边界。"""
    sec = Cubin(data).sections[0]
    exec_ranges = [(s.offset, s.offset + s.size) for s in Cubin(data).sections]
    non_exec = None
    for off in range(0, len(data) - INST_BYTES, INST_BYTES):
        if not any(lo <= off < hi for lo, hi in exec_ranges):
            non_exec = off
            break
    assert non_exec is not None
    return {"ELF 头": 0, "非可执行 section": non_exec,
            "非指令边界": sec.offset + 8, "越过段末": sec.offset + sec.size}


def test_light_build_skips_inskey_and_cells(monkeypatch):
    """VS Code 首屏不该为默认隐藏的格子支付逐条 identify/cell_map 成本。"""
    src = Path(CUBINS[0])

    def should_not_run(_enc):
        raise AssertionError("轻量预览不应调用 identify")

    monkeypatch.setattr(cubin_sass, "identify", should_not_run)
    result = cubin_sass.build(src, None, include_cells=False)
    assert result["cells_loaded"] is False
    rows = [i for sec in result["sections"] for i in sec["insns"]]
    assert rows and all("key" not in i and "cells" not in i for i in rows)


def test_section_text_temp_name_does_not_use_long_symbol(monkeypatch):
    """模板 kernel 的 section 名可超过 NAME_MAX，临时文件必须用固定短名。"""
    seen = []

    section = ".text." + "x" * 500

    def fake_disasm(path):
        seen.append((path.name, path.read_bytes()))
        return {section: {0: "NOP"}}

    monkeypatch.setattr(cubin_sass, "sass_by_sections", fake_disasm)
    assert cubin_sass._section_texts_uncached(b"elf", section) == {0: "NOP"}
    assert seen == [("input.cubin", b"elf")]


# --- ① 位置校验 -------------------------------------------------------------

def test_edit_site_accepts_real_instruction(sample):
    _src, data, off, _sass = sample
    site = edit_site(data, off)
    assert site["file_off"] == off
    assert site["addr"] % INST_BYTES == 0
    assert site["section"] and site["addr"] + INST_BYTES <= site["sec_size"]


@pytest.mark.parametrize("kind", ["ELF 头", "非可执行 section", "非指令边界", "越过段末"])
def test_edit_site_rejects(sample, kind):
    _src, data, _off, _sass = sample
    with pytest.raises(SiteError):
        edit_site(data, bad_offsets(data)[kind])


def test_edit_site_rejects_negative(sample):
    _src, data, _off, _sass = sample
    with pytest.raises(SiteError):
        edit_site(data, -16)


@pytest.mark.parametrize("kind", ["ELF 头", "非可执行 section", "非指令边界"])
def test_assemble_rejects_bad_site(sample, kind):
    """`--assemble` 打到非法位置上：拒绝，且一个字节都没动。"""
    _src, data, _off, sass = sample
    off = bad_offsets(data)[kind]
    with pytest.raises(SiteError):
        assemble_at(data, off, sass, [])


@pytest.mark.parametrize("kind", ["ELF 头", "非可执行 section", "非指令边界"])
def test_apply_patch_rejects_bad_site(sample, kind):
    """`--apply-patch` 同一套判据 —— 而且 `--force` 也不放行位置。"""
    src, data, off, _sass = sample
    bad = bad_offsets(data)[kind]
    enc = build(src, None, data)["sections"][0]["insns"][0]["enc"]
    patch = {"format": PATCH_FORMAT, "arch": "SM90",
             "edits": [{"file_off": bad, "section": None, "enc": enc, "sass": ""}]}
    for force in (False, True):
        res = apply_patch(src, data, patch, force=force)
        assert not res["ok"] and res["applied"] == 0
        assert res["data"] is None            # 拒绝的那条一个字节都没写出去
        assert res["results"][0]["error"]


def test_apply_patch_records_site(sample):
    """通过的那条要记下 section 名和段内地址（保存安全闸 的「并记录」那半句）。"""
    src, data, off, sass = sample
    res = apply_patch(src, data, {"format": PATCH_FORMAT, "arch": "SM90",
                                  "edits": [{"file_off": off,
                                             "enc": build(src, None, data)
                                             ["sections"][0]["insns"][0]["enc"],
                                             "sass": ""}]})
    row = res["results"][0]
    assert row["section"] and row["addr"] % INST_BYTES == 0


@pytest.mark.parametrize("kind", ["ELF 头", "非可执行 section", "非指令边界"])
def test_reflow_rejects_bad_site(sample, kind):
    _src, data, _off, sass = sample
    off = bad_offsets(data)[kind]
    with pytest.raises(SiteError):
        insert_at(data, off, sass)
    with pytest.raises(SiteError):
        delete_at(data, off)


# --- ② 保存安全闸 -----------------------------------------------------------

def _garble(data: bytes, off: int) -> bytes:
    """把一条指令改成 nvdisasm 解不出来的编码 —— 前端的字节编辑就能造出来。"""
    from cubin_sass import disasm_one
    for pat in (b"\xff" * INST_BYTES, b"\xfe" + b"\xff" * (INST_BYTES - 1)):
        cand = data[:off] + pat + data[off + INST_BYTES:]
        if not disasm_one(pat):
            return cand
    pytest.skip("凑不出一条解不出来的编码")


def test_check_save_passes_when_unchanged(sample):
    _src, data, _off, _sass = sample
    res = check_save(data, data)
    assert res["ok"] and res["changed"] == 0 and not res["bad"]


def test_check_save_blocks_illegal_encoding(sample):
    """字节编辑造出非法编码 -> 普通保存必须被阻止，并指出是哪一条。"""
    _src, data, off, _sass = sample
    res = check_save(_garble(data, off), data)
    assert not res["ok"]
    assert [r["file_off"] for r in res["bad"]] == [off]
    assert res["bad"][0]["section"] and res["error"]


def test_check_save_ignores_untouched_illegal_bytes(sample):
    """原文件里本来就解不出的位（对齐填充/非指令数据）不该拦着用户存改动。"""
    _src, data, off, _sass = sample
    garbled = _garble(data, off)
    assert check_save(garbled, garbled)["ok"]     # 没改动 -> 不查


def test_check_save_without_nvdisasm_is_not_an_illegal_encoding(sample, monkeypatch):
    """问不了 nvdisasm 时不能把改动报成非法编码（那会引导用户走实验性保存）。"""
    from nvisa.oracle import discache
    _src, data, off, _sass = sample
    edited = data[:off] + bytes(INST_BYTES) + data[off + INST_BYTES:]
    monkeypatch.setattr(cubin_sass, "_DIS_CACHE", {})
    monkeypatch.setattr(discache, "get", lambda arch, raw: None)
    monkeypatch.setattr(cubin_sass, "_disasm_one_uncached", lambda raw: ("", False))
    res = check_save(edited, data)
    assert not res["ok"]
    assert res["infrastructureError"] is True
    assert res["bad"] == [] and "nvdisasm" in res["error"]
    assert cubin_sass._DIS_CACHE == {}            # 没回答的结果不进缓存


def _set_ctrl(raw: bytes, lo: int, hi: int, val: int) -> bytes:
    v = int.from_bytes(raw, "little")
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return ((v & ~mask) | (val << lo)).to_bytes(INST_BYTES, "little")


def test_check_save_names_the_yield_field_when_only_stall_changed(sample):
    """「只改了个 stall 就再也存不进去」—— 报错必须点名 yield。

    yield 和 stall 在页面上是两个独立 chip，nvdisasm 那边却是一个 5 位码
    （`yield<<4 | stall` 查 `TABLES_opex_0`），yield=1 时只有 stall 1..11 有定义
    （「stall 字段仅 1..11 线性」）。只说「解不出来」的话，没人猜得到
    要去动另一个字段。
    """
    from cubin_sass import disasm_one
    _src, data, off, _sass = sample
    raw = data[off:off + INST_BYTES]
    if int.from_bytes(raw, "little") >> 109 & 1 != 1:
        pytest.skip("这条本来就是 yield=0，踩不到这个组合")
    for stall in (0, 12, 13, 14, 15):
        bad = _set_ctrl(raw, 105, 108, stall)
        if disasm_one(bad):                       # 真解得出就不是这条要钉的场景
            continue
        res = check_save(data[:off] + bad + data[off + INST_BYTES:], data)
        assert not res["ok"]
        assert "yield" in res["error"] and "1..11" in res["error"]
        assert str(stall) in res["error"]
        break
    else:
        pytest.skip("这条指令的 stall 全域都解得出")


def test_check_save_error_stays_quiet_for_unrelated_illegal_encodings(sample):
    """不是控制段的锅就别硬扯上 yield。"""
    _src, data, off, _sass = sample
    res = check_save(_garble(data, off), data)
    assert not res["ok"] and "1..11" not in res["error"]
