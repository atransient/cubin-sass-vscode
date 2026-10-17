"""Bit plumbing tests -- these are where sign/endianness bugs hide.

Note 001 lost time to exactly one such bug (lo/hi halves swapped), so the
round-trip properties are asserted explicitly rather than assumed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nvisa.oracle.cubin import (
    Cubin, enc_from_bytes, enc_to_bytes, enc_to_int, flip_bit, get_bits,
    int_to_enc, set_bits,
)

ROOT = Path(__file__).resolve().parents[1]
# FFMA R9, R2, R5, R9 as harvested from corpus/seeds/execfma.cu
FFMA = "0000000502097223008fca0000000009"


def test_enc_bytes_roundtrip():
    raw = enc_to_bytes(FFMA)
    assert len(raw) == 16
    assert enc_from_bytes(raw) == FFMA


def test_low_half_is_stored_first():
    """nvdisasm prints the low 64 bits first; on disk that half comes first."""
    assert enc_to_bytes(FFMA)[:8] == bytes.fromhex("2372090205000000")


def test_bit_zero_is_the_real_lsb():
    """enc_to_int must swap halves, else every bit index is wrong."""
    assert enc_to_int(FFMA) & 0xFFFFFFFFFFFFFFFF == 0x0000000502097223


def test_enc_int_roundtrip():
    assert int_to_enc(enc_to_int(FFMA)) == FFMA


@pytest.mark.parametrize("lo,hi,expect", [(16, 23, 0x09), (24, 31, 0x02), (32, 39, 0x05)])
def test_known_register_fields(lo, hi, expect):
    """Rd=R9, Ra=R2, Rb=R5."""
    assert get_bits(FFMA, lo, hi) == expect


def test_set_bits_only_touches_the_field():
    changed = set_bits(FFMA, 16, 23, 0xFF)
    assert get_bits(changed, 16, 23) == 0xFF
    assert get_bits(changed, 24, 31) == get_bits(FFMA, 24, 31)
    assert enc_to_int(changed) ^ enc_to_int(FFMA) == 0xF6 << 16


def test_set_bits_rejects_overflow():
    with pytest.raises(ValueError):
        set_bits(FFMA, 16, 23, 256)


def test_flip_bit_is_an_involution():
    assert flip_bit(flip_bit(FFMA, 77), 77) == FFMA


def test_enc_to_bytes_rejects_wrong_length():
    with pytest.raises(ValueError):
        enc_to_bytes("dead")


# -- cubin level ----------------------------------------------------------

@pytest.fixture(scope="module")
def cubin(tmp_path_factory) -> Cubin:
    import shutil

    from nvisa.collect.harvest import compile_seed
    src = ROOT / "corpus" / "seeds" / "execfma.cu"
    out = tmp_path_factory.mktemp("cubin") / "execfma.cubin"
    try:
        # compile_seed skips nvcc when corpus/cubins/ already has a fresh build
        # (~0.22 s a run).  Copy it out: these tests write into the cubin.
        shutil.copy(compile_seed(src), out)
    except (OSError, RuntimeError) as e:                       # noqa: BLE001
        pytest.skip(f"nvcc unavailable: {str(e)[:80]}")
    return Cubin.load(out)


def test_finds_single_text_section(cubin):
    sec = cubin.section()
    assert sec.name.startswith(".text")
    assert sec.size % 16 == 0        # fixed 16-byte instructions, no padding


def test_read_write_roundtrip(cubin):
    sec = cubin.section()
    addr = sec.size - 16
    original = cubin.read(addr)
    cubin.write(addr, FFMA)
    assert cubin.read(addr) == FFMA
    cubin.write(addr, original)
    assert cubin.read(addr) == original


def test_patched_does_not_mutate_original(cubin):
    addr = 0
    before = cubin.read(addr)
    clone = cubin.patched(addr, FFMA)
    assert clone.read(addr) == FFMA
    assert cubin.read(addr) == before


def test_out_of_range_address_rejected(cubin):
    with pytest.raises(IndexError):
        cubin.read(cubin.section().size)


def test_regcount_is_readable_and_patchable(cubin):
    counts = cubin.regcounts
    assert counts and all(0 < c <= 255 for c in counts.values())
    clone = Cubin(bytes(cubin.data))
    assert clone.set_regcount(255) == len(counts)
    assert set(clone.regcounts.values()) == {255}

    section = clone.sections[0].name
    assert clone.regcount_for_section(section) == 255
    assert clone.set_section_regcount(section, 128) >= 1
    assert clone.regcount_for_section(section) == 128


def test_regcount_rejects_bad_values(cubin):
    for bad in (0, 256):
        with pytest.raises(ValueError):
            Cubin(bytes(cubin.data)).set_regcount(bad)
