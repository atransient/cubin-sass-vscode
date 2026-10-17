"""Source saves must assemble the stdin snapshot, including full save validation."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from nvisa.model.sass_source import base_hash, emit_all_sources, emit_source
from nvisa.oracle.cubin import Cubin

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "scripts/cubin_sass.py"
FIXTURE = ROOT / "corpus/cubins/fma.sm_90.cubin"
pytestmark = pytest.mark.skipif(not shutil.which("nvdisasm"), reason="needs CUDA nvdisasm")


def _snapshot() -> tuple[bytes, bytes, str]:
    original = FIXTURE.read_bytes()
    cubin = Cubin(original)
    section = cubin.sections[0].name
    cubin.set_section_regcount(section, 32)
    memory = bytes(cubin.data)
    assert memory != original
    return original, memory, section


@pytest.mark.parametrize("bundle", [False, True])
@pytest.mark.parametrize("destination", ["new", "in_place", "missing_base"])
def test_stdin_source_save_uses_memory_base(tmp_path, bundle, destination):
    original, memory, section = _snapshot()
    base = tmp_path / "base.cubin"
    if destination != "missing_base":
        base.write_bytes(original)
        base.chmod(0o644)
    source = tmp_path / "edited.nvsass"
    text = (emit_all_sources if bundle else emit_source)(memory).text
    source.write_text(re.sub(r"(?m)^\.regcount \d+$", ".regcount 40", text))
    target = base if destination == "in_place" else tmp_path / "output.cubin"
    result = subprocess.run([
        sys.executable, str(BACKEND), str(base), "--stdin",
        "--assemble-source", str(source), "--out", str(target),
    ], input=memory, capture_output=True, timeout=60)
    payload = json.loads(result.stdout)
    assert result.returncode == 0, payload
    assert payload["ok"] is True and payload["written"] == str(target)
    assert Cubin(target.read_bytes()).regcount_for_section(section) == 40
    assert {"readelf", "cuobjdump", "load"} <= {c["name"] for c in payload["checks"]}
    assert all(c["ok"] is not False for c in payload["checks"])
    if destination == "in_place":
        assert target.stat().st_mode & 0o7777 == 0o644
        assert f".base {base_hash(target.read_bytes())}" in source.read_text()
    elif destination == "new":
        assert base.read_bytes() == original
        assert f".base {base_hash(memory)}" in source.read_text()
    else:
        assert not base.exists()
    assert not list(tmp_path.glob(".nvsass-*"))


@pytest.mark.parametrize("bundle", [False, True])
def test_stdin_source_conflict_does_not_fall_back_to_matching_disk_base(tmp_path, bundle):
    original, memory, _section = _snapshot()
    base = tmp_path / "base.cubin"
    base.write_bytes(original)
    # This source matches the disk but conflicts with the explicit stdin base.
    source = tmp_path / "source.nvsass"
    text = (emit_all_sources if bundle else emit_source)(original).text
    source.write_text(text)
    target = tmp_path / "output.cubin"
    target.write_bytes(b"existing output")
    result = subprocess.run([
        sys.executable, str(BACKEND), str(base), "--stdin",
        "--assemble-source", str(source), "--out", str(target),
    ], input=memory, capture_output=True, timeout=60)
    response = json.loads(result.stdout)
    assert result.returncode == 1 and response["ok"] is False
    assert "基底对不上" in response["error"]
    assert "written" not in response
    assert base.read_bytes() == original
    assert target.read_bytes() == b"existing output"
    assert source.read_text() == text
