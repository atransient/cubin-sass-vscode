"""Template text and encoding must come from the same executable section."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import cubin_sass as cs
from nvisa.oracle.cubin import Cubin, Section


def test_template_pool_keeps_equal_addresses_in_different_kernels_separate():
    sections = [Section(".text.first", 0, 16), Section(".text.second", 16, 16)]
    cub = SimpleNamespace(sections=sections, read=lambda addr, section: f"{section}:{addr}")
    rows = cs._pool_from_cubin(cub, {
        ".text.first": {0: "FMUL R2, R2, R3"},
        ".text.second": {0: "IADD3 R2, R2, R3, RZ"},
    }, lambda sec, addr: f"{sec.name}+{addr}")
    assert rows == [
        ("FMUL", ".text.first:0", ".text.first+0", 3, True),
        ("IADD3", ".text.second:0", ".text.second+0", 4, True),
    ]


def test_corpus_pool_does_not_reuse_old_flat_address_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    fixture = Path(__file__).resolve().parents[1] / "corpus/cubins/fma.sm_90.cubin"
    target = corpus / "fma.cubin"
    target.write_bytes(fixture.read_bytes())
    stamp = hashlib.sha1(f"{target.name}:{target.stat().st_mtime_ns}".encode()).hexdigest()[:16]
    cache = tmp_path / "cache/nvisa-cubin-sass"
    cache.mkdir(parents=True)
    (cache / f"templates-{stamp}.json").write_text(json.dumps([["WRONG", "encoding", "old", 0, True]]))
    section = Cubin.load(target).sections[0]
    monkeypatch.setattr(cs, "sass_by_sections", lambda _: {section.name: {0: "NOP"}})
    result = cs._corpus_pool(corpus)
    assert result == [("NOP", Cubin.load(target).read(0, section.name),
                       f"fma.cubin {section.name}+0x0", 0, True)]
    monkeypatch.setattr(cs, "sass_by_sections", lambda _: pytest.fail("warm cache should be used"))
    assert cs._corpus_pool(corpus) == result


@pytest.mark.skipif(not (shutil.which("nvcc") and shutil.which("nvdisasm")),
                    reason="needs CUDA nvcc and nvdisasm")
def test_real_multikernel_template_text_matches_its_encoding(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    source = tmp_path / "multi.cu"
    source.write_text(
        'extern "C" __global__ void add(int *x) { x[threadIdx.x] += 17; }\n'
        'extern "C" __global__ void square(float *x) { float v=x[threadIdx.x]; x[threadIdx.x]=v*v; }\n')
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    target = corpus / "multi.cubin"
    result = subprocess.run(["nvcc", "-arch=sm_90", "-cubin", str(source), "-o", str(target)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    cub = Cubin.load(target)
    by_section = cs.sass_by_sections(target)
    assert len(cub.sections) == 2 and len(by_section) == 2
    expected = [(cs._mnemonic(text), cub.read(addr, sec.name), sec.name, addr)
                for sec in cub.sections for addr, text in by_section[sec.name].items()]
    # The two functions use different opcodes at an overlapping address.
    first, second = (by_section[sec.name] for sec in cub.sections)
    assert any(cs._mnemonic(text) != cs._mnemonic(second[addr])
               for addr, text in first.items() if addr in second)
    for actual, prefix in [(cs.template_pool(target.read_bytes(), []), "本文件"),
                           (cs._corpus_pool(corpus), "multi.cubin")]:
        assert [(mn, enc, origin) for mn, enc, origin, _, _ in actual] == [
            (mn, enc, f"{prefix} {section}+0x{addr:x}") for mn, enc, section, addr in expected]
