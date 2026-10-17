"""nvdisasm 结果缓存 —— 只省进程，不改判据。

这套缓存把一次测试从 67 秒压到 8 秒（热）/ 31 秒（冷），代价是「答案可能来自
上一次运行」。所以这里钉三件事：**同样的输入给同样的答案**、**跑不起来的
nvdisasm 不会被当成答案存下来**、**换了 nvdisasm 版本就换一份缓存**。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import _DIS_CACHE, disasm_one                    # noqa: E402
from nvisa.model.translate import to_sass                        # noqa: E402
from nvisa.oracle import discache                                # noqa: E402
from nvisa.oracle.cubin import enc_to_bytes                      # noqa: E402

SIMPLE = ROOT / "corpus" / "cubins" / "fma.sm_90.cubin"


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """把缓存目录挪到 tmp_path，别动用户真正的 ~/.cache。"""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(discache, "_mem", {})
    monkeypatch.setattr(discache, "_text_mem", {})
    monkeypatch.setattr(discache, "_section_text_mem", {})
    monkeypatch.setattr(discache, "_loaded", set())
    monkeypatch.setattr(discache, "_dirty", set())
    _DIS_CACHE.clear()
    return tmp_path


def test_cached_answer_equals_uncached(isolated_cache):
    """缓存命中给出的文本，必须和真的问一次 nvdisasm 一样。"""
    from cubin_sass import _disasm_one_uncached
    raw = enc_to_bytes("000fe200078e0203" + "0000000600020a24"[:16])
    fresh, answered = _disasm_one_uncached(raw)
    if not answered:
        pytest.skip("nvdisasm 跑不了")
    assert disasm_one(raw) == fresh                      # 冷：存进去
    discache.flush()
    _DIS_CACHE.clear()
    assert disasm_one(raw) == fresh                      # 热：从盘上读回来


def test_illegal_encoding_is_a_real_answer(isolated_cache):
    """「这条解不出来」也是答案，要缓存 —— 探索非法编码时问的全是这种。"""
    bad = b"\xff" * 16
    if _needs_nvdisasm():
        pytest.skip("nvdisasm 跑不了")
    assert disasm_one(bad) == ""
    assert discache.get("SM90", bad) == ""               # 存下来了，不是 None


def _needs_nvdisasm() -> bool:
    from cubin_sass import _disasm_one_uncached
    return not _disasm_one_uncached(b"\x00" * 16)[1]


def test_missing_nvdisasm_is_not_cached(isolated_cache, monkeypatch):
    """nvdisasm 没装/超时 ≠ 这条编码解不出来 —— 那种情况一个字都不能落盘。"""
    monkeypatch.setattr("cubin_sass._disasm_one_uncached", lambda raw: ("", False))
    _DIS_CACHE.clear()
    raw = b"\x01" * 16
    assert disasm_one(raw) == ""
    assert discache.get("SM90", raw) is None


def test_text_by_addr_matches_between_cold_and_warm(isolated_cache):
    """整段那套同理：第二次从缓存来，内容必须一模一样。"""
    if not SIMPLE.exists():
        pytest.skip("需要 corpus/cubins/")
    cold = discache.text_by_addr(SIMPLE)
    if not cold:
        pytest.skip("nvdisasm 跑不了")
    discache._text_mem.clear()                            # 只清进程内那层
    assert discache.text_by_addr(SIMPLE) == cold


def test_text_cache_keys_on_content_not_path(isolated_cache, tmp_path):
    """同一个路径下一秒装的是别的内容（编辑器/插入/删除 的临时文件就是这么用的）——
    按路径缓存会串味，这里钉住它按内容走。"""
    if not SIMPLE.exists():
        pytest.skip("需要 corpus/cubins/")
    p = tmp_path / "same-name.cubin"
    p.write_bytes(SIMPLE.read_bytes())
    first = discache.text_by_addr(p)
    if not first:
        pytest.skip("nvdisasm 跑不了")
    p.write_bytes(SIMPLE.read_bytes()[:64])               # 换成别的内容
    assert discache.text_by_addr(p) != first


def test_section_parser_keeps_equal_addresses_separate():
    output = """
        .section .text.first,"ax",@progbits
        /*0000*/ BRA `(.L_x_0) ;
        .section .text.second,"ax",@progbits
        /*0000*/ NOP ;
    """
    assert discache._sections_from_output(output) == {
        ".text.first": {0: "BRA `(.L_x_0)"},
        ".text.second": {0: "NOP"},
    }


def test_text_by_sections_matches_between_cold_and_warm(isolated_cache):
    if not SIMPLE.exists():
        pytest.skip("需要 corpus/cubins/")
    cold = discache.text_by_sections(SIMPLE)
    if not cold:
        pytest.skip("nvdisasm 跑不了")
    discache._section_text_mem.clear()
    assert discache.text_by_sections(SIMPLE) == cold


def test_version_is_part_of_the_key(isolated_cache, monkeypatch):
    """换一个 CUDA 工具链就是另一套答案，不该拿旧的当数。"""
    monkeypatch.setattr(discache, "_version", "12.9")
    a = discache._file("SM90")
    monkeypatch.setattr(discache, "_version", "13.0")
    assert discache._file("SM90") != a


def test_to_sass_cached_matches(isolated_cache):
    """`translate.to_sass()` 走同一份盘上缓存，答案要跟 `disasm_one` 一致。"""
    from cubin_sass import build
    if not SIMPLE.exists():
        pytest.skip("需要 corpus/cubins/")
    ins = next(i for s in build(SIMPLE, None)["sections"]
               for i in s["insns"] if i.get("sass"))
    got = disasm_one(enc_to_bytes(ins["enc"]))
    if not got:
        pytest.skip("nvdisasm 读不出这条")
    assert to_sass(ins["enc"]).rstrip(";").strip() == got.rstrip(";").strip()
