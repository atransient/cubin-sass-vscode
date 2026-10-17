"""Bidirectional 128-bit codec -- see nvisa/model/codec.py.

The properties worth pinning: decode reads the skeleton fields at the positions
the notes established, encode is its inverse, and the several input spellings of
one word all parse to the same value.
"""
from __future__ import annotations

import pytest

from nvisa.model import codec
from nvisa.oracle.cubin import enc_to_int

# real FFMA R9, R2, R5, R9 (execfma seed @0xc0), stored low-half-first
FFMA = "0000000502097223008fca0000000009"


def test_decode_ffma_skeleton():
    rows = {r["field"]: r for r in codec.decode(FFMA)}
    assert rows["op"]["raw"] == 0x023
    assert rows["form"]["raw"] == 0b001
    assert rows["form"]["effect"].endswith("(R)")
    assert rows["pred"]["effect"].startswith("@PT")
    assert (rows["Rd"]["raw"], rows["Ra"]["raw"],
            rows["Rb"]["raw"], rows["Rc"]["raw"]) == (9, 2, 5, 9)
    assert rows["Rd"]["effect"] == "R9"


def test_reg_special_values():
    # RZ = R255, PT = P7 unguarded
    w = codec.encode(Rd=255, pred=7)
    rows = {r["field"]: r for r in codec.decode(w)}
    assert rows["Rd"]["effect"] == "RZ"
    assert "unguarded" in rows["pred"]["effect"]


def test_encode_roundtrip_identity():
    # overriding every skeleton slot with its own value reproduces the word
    w = enc_to_int(FFMA)
    rebuilt = codec.encode(
        op=0x023, form=0b001, pred=7, Rd=9, Ra=2, Rb=5, Rc=9,
        imm24=(w >> 40) & 0xFFFFFF, mod=(w >> 72) & 0x7FFFF,
        stall=5, waitmask=0b001000, wrbar=7, rdbar=7,
    )
    assert enc_to_int(rebuilt) == w


def test_encode_from_base_overrides_one_slot():
    out = codec.encode(base=FFMA, Rd=17)
    rows = {r["field"]: r for r in codec.decode(out)}
    assert rows["Rd"]["raw"] == 17
    assert rows["Ra"]["raw"] == 2  # untouched


def test_parse_word_forms_agree():
    w = enc_to_int(FFMA)
    assert codec.parse_word(FFMA) == w                 # 32-hex enc
    assert codec.parse_word(f"0x{w:032x}") == w        # true hex value
    assert codec.parse_word(f"0b{w:b}") == w           # binary
    assert codec.parse_word(format(w, "0128b")) == w   # bare 128-bit binary


def test_encode_rejects_overflow():
    with pytest.raises(ValueError):
        codec.encode(Rd=256)   # 8-bit field
    with pytest.raises(ValueError):
        codec.encode(form=0b1000)  # 3-bit field


def test_grid_labels_and_alignment():
    out = codec.format_grid(FFMA)
    # field labels appear in the diagram cells
    for label in ("op=0x23", "form 001", "@PT", "Rd=R9", "Ra=R2", "Rb=R5",
                  "Rc=R9", "modifiers", "stall=5", "wait=001000"):
        assert label in out
    # four 32-bit rows -> four box tops, all the same width (columns aligned)
    box_lines = [l for l in out.splitlines() if l and l[0] in "┌│└"]
    assert sum(l.startswith("┌") for l in box_lines) == 4
    assert len({len(l) for l in box_lines}) == 1
    # legend carries the detail the cells cannot
    assert "legend:" in out
    assert "waits on scoreboard 3" in out


def test_alias_names():
    a = codec.encode(reuse_a=1, b_mode=0b101)
    b = codec.encode(**{"reuse.A": 1, "form": 0b101})
    assert a == b
