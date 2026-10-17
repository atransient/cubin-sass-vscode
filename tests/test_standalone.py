"""Standalone distribution contracts; the basic checks do not need CUDA."""
import hashlib
import json
import os
import shutil

import pytest
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_bundled_data_checksums():
    manifest = json.loads((ROOT / "data/manifest.json").read_text())
    snapshots = [f for f in manifest["files"] if f["path"].startswith("data/")]
    assert len(snapshots) == 4
    for entry in snapshots:
        assert hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]


def test_cli_runs_outside_checkout_without_pythonpath(tmp_path):
    env = {**os.environ, "PYTHONPATH": "", "XDG_CACHE_HOME": str(tmp_path / "cache")}
    result = subprocess.run([
        sys.executable, "-I", str(ROOT / "scripts/cubin_sass.py"),
        str(ROOT / "corpus/cubins/fma.sm_90.cubin"),
    ], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["sections"]
    assert any(s["insns"] for s in payload["sections"])


def test_optional_load_check_skips_unwritable_cache(monkeypatch):
    from nvisa.oracle import execute
    def unwritable():
        raise PermissionError("cache is read-only")
    monkeypatch.setattr(execute, "build_loadcheck", unwritable)
    result = execute.load_check(Path("unused.cubin"))
    assert result["ok"] is None
    assert result["stage"] == "build"


def test_cli_failure_has_json_and_nonzero_exit_status(tmp_path):
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/cubin_sass.py"), str(tmp_path / "missing.cubin"),
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False


def test_cli_argument_failure_has_nonzero_exit_status():
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/cubin_sass.py"), "unused", "--assemble", "NOP;",
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert "--at" in json.loads(result.stdout)["error"]


@pytest.mark.skipif(not shutil.which("nvdisasm"), reason="needs CUDA nvdisasm")
def test_isolated_cli_source_roundtrip(tmp_path):
    env = {**os.environ, "PYTHONPATH": "", "XDG_CACHE_HOME": str(tmp_path / "cache")}
    fixture = ROOT / "corpus/cubins/fma.sm_90.cubin"
    def invoke(*args):
        result = subprocess.run([
            sys.executable, "-I", str(ROOT / "scripts/cubin_sass.py"),
            str(fixture), *args,
        ], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr + result.stdout
        response = json.loads(result.stdout)
        assert response["ok"] is True, response
        return response
    exported = invoke("--emit-source", "--all-sections")
    source = tmp_path / "source.nvsass"
    source.write_text(exported["source"])
    output = tmp_path / "result.cubin"
    invoke("--assemble-source", str(source), "--out", str(output))
    assert output.read_bytes() == fixture.read_bytes()
