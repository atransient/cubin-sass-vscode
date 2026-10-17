"""Host ELF ``.nv_fatbin`` extraction and exact-size editing."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from nvisa.model.fatbin import (FATBIN_MAGIC, FatbinError, embedded_cubins,
                                open_cubin_image)
from nvisa.oracle.cubin import Cubin


ROOT = Path(__file__).resolve().parents[1]
CUBIN = ROOT / "corpus" / "seeds" / "fma.cubin"


def _entry(payload: bytes, kind: int = 2) -> bytes:
    header = bytearray(0x40)
    struct.pack_into("<HHIQ", header, 0, kind, 0x101, len(header), len(payload))
    return bytes(header) + payload


def _host(*payloads: bytes) -> bytes:
    entries = b"".join(_entry(p) for p in payloads)
    fat = struct.pack("<IHHQ", FATBIN_MAGIC, 1, 16, len(entries)) + entries
    names = b"\0.shstrtab\0.nv_fatbin\0"
    str_off = 0x80
    fat_off = (str_off + len(names) + 7) & ~7
    shoff = (fat_off + len(fat) + 7) & ~7
    out = bytearray(shoff + 3 * 64)
    out[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", out, 16,
                     1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 1)
    out[str_off:str_off + len(names)] = names
    out[fat_off:fat_off + len(fat)] = fat
    shstr_name = names.index(b".shstrtab")
    fat_name = names.index(b".nv_fatbin")
    struct.pack_into("<IIQQQQIIQQ", out, shoff + 64,
                     shstr_name, 3, 0, 0, str_off, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", out, shoff + 128,
                     fat_name, 1, 2, 0, fat_off, len(fat), 0, 0, 8, 0)
    return bytes(out)


@pytest.fixture(scope="module")
def cubin() -> bytes:
    if not CUBIN.is_file():
        pytest.skip("repository cubin fixture is absent")
    return CUBIN.read_bytes()


def test_standalone_cubin_is_unchanged(cubin):
    image = open_cubin_image(cubin)
    assert image.kind == "cubin"
    assert image.cubin == cubin
    assert image.replace(cubin) == cubin


def test_find_extract_and_edit_embedded_sm90(cubin):
    host = _host(cubin)
    entries = embedded_cubins(host)
    assert len(entries) == 1
    assert entries[0].arch == "sm_90"

    image = open_cubin_image(host)
    assert image.cubin == cubin
    assert image.inner_offset(image.payload_offset + 7) == 7

    inner = bytearray(image.cubin)
    sec = Cubin(inner).sections[0]
    changed_at = sec.offset
    inner[changed_at] ^= 1
    edited = image.replace(inner)
    outer_at = image.payload_offset + changed_at
    assert edited[:outer_at] == host[:outer_at]
    assert edited[outer_at] == (host[outer_at] ^ 1)
    assert edited[outer_at + 1:] == host[outer_at + 1:]
    assert open_cubin_image(edited).cubin == bytes(inner)


def test_replacement_must_preserve_fatbin_layout(cubin):
    image = open_cubin_image(_host(cubin))
    with pytest.raises(FatbinError, match="长度不能改变"):
        image.replace(cubin + b"\0")


def test_multiple_sm90_images_require_explicit_selection(cubin):
    host = _host(cubin, cubin)
    with pytest.raises(FatbinError, match="--image") as caught:
        open_cubin_image(host)
    assert len(caught.value.images) == 2
    selected = open_cubin_image(host, image=1)
    assert selected.embedded.index == 1
    assert selected.cubin == cubin


def test_non_payload_offset_is_rejected(cubin):
    image = open_cubin_image(_host(cubin))
    with pytest.raises(FatbinError, match="不在所选"):
        image.inner_offset(0)


def test_wrong_embedded_arch_reports_what_is_available(cubin):
    old = bytearray(cubin)
    flags, = struct.unpack_from("<I", old, 0x30)
    struct.pack_into("<I", old, 0x30, (flags & ~0xFF) | 52)
    with pytest.raises(FatbinError, match=r"没有 sm_90.*sm_52.*重新编译"):
        open_cubin_image(_host(bytes(old)))


@pytest.mark.parametrize("in_place", [False, True])
def test_cli_validation_failure_never_writes_host(cubin, tmp_path, monkeypatch, capsys, in_place):
    """A completed assembly with a failed verification must not reach --out."""
    import io
    import json
    import sys
    import cubin_sass
    from nvisa.model import sass_save

    host = tmp_path / "host"
    original = _host(cubin)
    host.write_bytes(original)
    output = host if in_place else tmp_path / "output"
    invalid = bytes([cubin[0] ^ 1]) + cubin[1:]
    report = sass_save.SaveReport(section=".text.f", count=1,
                                 old_size=len(cubin), new_size=len(cubin), unchanged=False,
                                 checks=[sass_save.Check("disasm", False, "forced failure")])
    monkeypatch.setattr(sass_save, "dry_run", lambda *a, **kw: (invalid, report))
    monkeypatch.setattr(sys, "argv", ["cubin_sass.py", str(host),
                                    "--assemble-source", "-", "--out", str(output)])
    monkeypatch.setattr(sys, "stdin", io.StringIO("source"))
    with pytest.raises(SystemExit) as stopped:
        cubin_sass.main()
    response = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 1
    assert response["ok"] is False and response["diagnostics"]
    assert "written" not in response and "data" not in response
    assert host.read_bytes() == original
    if not in_place:
        assert not output.exists()


def _cli(*args: str) -> dict:
    import json
    import subprocess
    import sys
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "cubin_sass.py"), *args],
                          capture_output=True, text=True, timeout=120)
    return json.loads(proc.stdout)


@pytest.mark.skipif(not __import__("shutil").which("nvdisasm"), reason="插入/删除 复核要跑 nvdisasm")
def test_payload_only_returns_the_embedded_cubin_and_out_still_writes_the_host(
        cubin, tmp_path):
    """大宿主文件不能整份 hex 回传（扩展的输出上限 64 MiB）；--out 仍是完整文件。"""
    host = tmp_path / "host"
    host.write_bytes(_host(cubin))
    image = open_cubin_image(host.read_bytes())
    at = str(image.payload_offset + Cubin(image.cubin).sections[0].offset)

    whole = _cli(str(host), "--at", at, "--delete")
    assert whole["ok"], whole
    assert "data_scope" not in whole
    payload = _cli(str(host), "--at", at, "--delete", "--payload-only",
                   "--out", str(tmp_path / "out"))
    assert payload["ok"], payload
    assert payload["data_scope"] == "payload"
    assert len(bytes.fromhex(payload["data"])) == image.embedded.payload_size
    assert image.replace(bytes.fromhex(payload["data"])).hex() == whole["data"]
    assert (tmp_path / "out").read_bytes().hex() == whole["data"]


def test_atomic_write_keeps_symlink_and_mode(tmp_path):
    import os
    import cubin_sass
    real = tmp_path / "real.cubin"
    real.write_bytes(b"old")
    os.chmod(real, 0o750)
    link = tmp_path / "link.cubin"
    link.symlink_to(real)
    cubin_sass._atomic_write(link, b"new")
    assert link.is_symlink()
    assert real.read_bytes() == b"new"
    assert real.stat().st_mode & 0o777 == 0o750
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link.cubin", "real.cubin"]
