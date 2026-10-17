"""调试信息的策略化处置 —— `nvisa/model/debug_policy.py`。

判据：

* **必须显式选**：调试 section 没有策略就报错，没有「默认保留」这条路；
* **`preserve` 要有 proof**：布局变了又引用被改范围就拒绝，布局没变或证明不引用
  才放行；
* **`rewrite` 只有 `.debug_frame`**：行号类和 `.nv.debug*` 请求 rewrite 直接拒绝，
  也不许在 rewrite 名义下悄悄剥离；
* **`strip` 连带重定位**：清空 `.debug_line` 的同时清掉 `.rela.debug_*`；
* **未知 debug 重定位类型**在 preserve/rewrite 下拒绝；
* 旧的 `strip_debug` 布尔与新请求等价，且两者不能同时给。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from nvisa.model.debug_policy import (FRAME, PRESERVE, REWRITE,   # noqa: E402
                                      STRIP, DebugPolicyError,
                                      DebugRequest, classify, plan)
from nvisa.model.elf_inspect import inspect                        # noqa: E402
from nvisa.model.elf_rewrite import (RewriteError, _sections,      # noqa: E402
                                     rewrite)

FMA = ROOT / "corpus" / "cubins" / "fma.sm_90.cubin"
pytestmark = pytest.mark.skipif(not FMA.exists(), reason="需要 corpus/cubins")


def _sec(name, **kw):
    d = {"name": name, "rela": [], "rela_types": set(), "touches_target": True}
    d.update(kw)
    return d


# --- 分类与请求 -------------------------------------------------------------

def test_classify():
    assert classify(".debug_frame") == "frame"
    assert classify(".debug_line") == "line"
    assert classify(".nv.debug_info") == "nv"
    assert classify(".text._Z3fmaPf") is None
    assert classify(".nv.callgraph") is None      # 不是调试信息，别当调试信息处置


def test_request_validates_policy_names():
    with pytest.raises(DebugPolicyError, match="未知策略"):
        DebugRequest(default="keep")
    with pytest.raises(DebugPolicyError, match="未知策略"):
        DebugRequest(per_section={".debug_line": "drop"})


def test_from_legacy_is_the_old_two_rules():
    assert DebugRequest.from_legacy(False).policy_for(FRAME) == REWRITE
    assert DebugRequest.from_legacy(False).policy_for(".debug_line") is None
    assert DebugRequest.from_legacy(True).policy_for(".debug_line") == STRIP
    assert DebugRequest.from_legacy(True).policy_for(FRAME) == REWRITE


# --- plan 的会失败的检查 -----------------------------------------------------

def test_missing_policy_is_an_error():
    with pytest.raises(DebugPolicyError, match="没有调试策略"):
        plan([_sec(".debug_line")], request=DebugRequest(), layout_changed=True)


def test_rewrite_only_for_debug_frame():
    req = DebugRequest(default=REWRITE)
    with pytest.raises(DebugPolicyError, match="不支持 rewrite"):
        plan([_sec(".debug_line")], request=req, layout_changed=True)
    with pytest.raises(DebugPolicyError, match="不支持 rewrite"):
        plan([_sec(".nv.debug_info")], request=req, layout_changed=True)
    got = plan([_sec(FRAME)], request=req, layout_changed=True)
    assert got[0].policy == REWRITE and "address_range" in got[0].reason


def test_preserve_needs_proof():
    req = DebugRequest(default=PRESERVE)
    # 布局没变：原字节即有效。
    assert plan([_sec(".debug_line")], request=req,
                layout_changed=False)[0].reason.startswith("布局没有变化")
    # 布局变了 + 引用被改范围：拒绝。
    with pytest.raises(DebugPolicyError, match="preserve 需要 proof"):
        plan([_sec(".debug_line")], request=req, layout_changed=True)
    # 布局变了但证明不引用被改范围：放行，并把 proof 写进理由。
    d = plan([_sec(".debug_line", touches_target=False)], request=req,
             layout_changed=True)[0]
    assert "没有指向被改 section 的重定位" in d.reason


def test_unknown_debug_relocation():
    bad = _sec(FRAME, rela=[".rela.debug_frame"], rela_types={2, 0x2A})
    for policy in (PRESERVE, REWRITE):
        with pytest.raises(DebugPolicyError, match="认不出的类型"):
            plan([bad], request=DebugRequest(default=policy), layout_changed=True)
    # strip 会把它一并删掉，因此不拦。
    d = plan([bad], request=DebugRequest(default=STRIP), layout_changed=True)[0]
    assert d.clears and d.relocations == [".rela.debug_frame"]


def test_strip_reason_does_not_claim_validity():
    d = plan([_sec(".debug_line")], request=DebugRequest(default=STRIP),
             layout_changed=True)[0]
    assert "不是「仍然有效」" in d.reason
    assert "strip" in d.line and ".debug_line" in d.line


def test_per_section_overrides_default():
    secs = [_sec(FRAME), _sec(".debug_line")]
    req = DebugRequest(default=STRIP, per_section={FRAME: REWRITE})
    got = {d.section: d.policy for d in
           plan(secs, request=req, layout_changed=True)}
    assert got == {FRAME: REWRITE, ".debug_line": STRIP}


# --- 接进 elf_rewrite -------------------------------------------------------

def _fake_line_debug() -> bytes:
    """把 `.debug_frame` 改名成 `.debug_line`（只改 shstrtab 字节，长度一致）。"""
    data = bytearray(FMA.read_bytes())
    secs = _sections(bytes(data))
    victim = next(s for s in secs if s.name == FRAME)
    shstr = next(s for s in secs if s.name == ".shstrtab")
    pos = shstr.offset + victim.name_off
    data[pos:pos + len(b".debug_frame")] = b".debug_line\x00"
    return bytes(data)


def _target(data: bytes):
    sec = next(s for s in _sections(data) if s.name.startswith(".text"))
    return sec, {a: a for a in range(0, sec.size + 1, 16)}


def test_rewrite_reports_decisions():
    data = FMA.read_bytes()
    sec, amap = _target(data)
    _out, rep = rewrite(data, sec.name, b"\0" * sec.size, amap,
                        debug=DebugRequest(per_section={FRAME: PRESERVE}))
    assert [d.section for d in rep.debug_decisions] == [FRAME]
    d = rep.debug_decisions[0]
    assert d.policy == PRESERVE and d.to_json()["kind"] == "frame"
    assert any(FRAME in line for line in rep.debug)


def test_strip_clears_the_associated_rela():
    data = _fake_line_debug()
    sec, amap = _target(data)
    out, rep = rewrite(data, sec.name, b"\0" * sec.size, amap,
                       debug=DebugRequest(default=STRIP))
    secs = {s.name: s for s in _sections(out)}
    assert secs[".debug_line"].size == 0
    assert secs[".rela.debug_frame"].size == 0, "关联重定位必须一起清"
    d = next(d for d in rep.debug_decisions if d.section == ".debug_line")
    assert d.relocations == [".rela.debug_frame"]


def test_rewrite_refuses_conflicting_debug_inputs():
    data = FMA.read_bytes()
    sec, amap = _target(data)
    with pytest.raises(RewriteError, match="只留一种"):
        rewrite(data, sec.name, b"\0" * sec.size, amap, strip_debug=True,
                debug=DebugRequest(default=STRIP))


def test_rewrite_refuses_line_debug_rewrite_policy():
    data = _fake_line_debug()
    sec, amap = _target(data)
    with pytest.raises(RewriteError, match="不支持 rewrite"):
        rewrite(data, sec.name, b"\0" * sec.size, amap,
                debug=DebugRequest(default=REWRITE))


def test_inspect_exposes_debug_facts():
    rep = inspect(FMA.read_bytes())
    frame = next(d for d in rep["debug_sections"] if d["name"] == FRAME)
    assert frame["kind"] == "frame" and frame["rewritable"] is True
    assert frame["rela"] == [".rela.debug_frame"]
    assert frame["unknown_rela_types"] == []
    assert any("调试策略" in u for u in rep["unverified"])
