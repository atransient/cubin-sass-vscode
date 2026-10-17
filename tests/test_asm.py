"""Template assembler -- see `nvisa/model/asm.py`.

The assembler inherits opcode bits from a template instruction and rewrites only
the fields this project has calibrated.  Two properties matter and both are
asserted here rather than assumed:

* it must **refuse** anything whose fields are not calibrated, instead of
  silently emitting a wrong encoding (that failure mode is invisible -- the
  cubin loads and the kernel runs, it just does something else);
* text -> fields -> text must be a round trip, since that canonical form is what
  the nvdisasm cross-check compares against.
"""
from __future__ import annotations

import pytest

from nvisa.model.asm import (
    CONTROL_BITS, CONTROL_FIELDS, FIELDS, PT, RZ, AsmError, assemble, control_of, parse,
)
from nvisa.oracle.cubin import get_bits

# FFMA R9, R2, R5, R9 as harvested from corpus/seeds/execfma.cu (same constant
# the other tests use, so a change in bit order breaks all of them together).
FFMA = "0000000502097223008fca0000000009"


# -- parsing ------------------------------------------------------------------

def test_parses_registers_into_slot_order():
    p = parse("FFMA R19, R4, R6, R8")
    assert p.mnemonic == "FFMA"
    assert (p.fields["rd"], p.fields["ra"], p.fields["rb"], p.fields["rc"]) == (19, 4, 6, 8)


def test_rz_is_register_255():
    """RZ is not a name the encoding knows -- it is register 255."""
    assert parse("FFMA R1, RZ, R2, R3").fields["ra"] == RZ
    assert parse("FFMA R1, R255, R2, R3").render() == "FFMA R1, RZ, R2, R3"


def test_reuse_suffix_becomes_a_bitmask_over_source_slots():
    """Slot A/B/C map to bits 122/123/124 in order."""
    assert parse("FFMA R1, R2.reuse, R3, R4").fields["reuse"] == 0b001
    assert parse("FFMA R1, R2, R3.reuse, R4").fields["reuse"] == 0b010
    assert parse("FFMA R1, R2.reuse, R3.reuse, R4.reuse").fields["reuse"] == 0b111
    assert "reuse" not in parse("FFMA R1, R2, R3, R4").fields


def test_control_layout_includes_reuse_but_not_reserved_tail_bits():
    """The segment table consumes this layout for its explained-bit account."""
    assert CONTROL_FIELDS[-1] == "reuse"
    assert set(range(105, 125)) == CONTROL_BITS
    assert 125 not in CONTROL_BITS


@pytest.mark.parametrize("text,pred,neg", [
    ("@P0 FFMA R1, R2, R3, R4", 0, 0),
    ("@!P0 FFMA R1, R2, R3, R4", 0, 1),
    ("@P6 FFMA R1, R2, R3, R4", 6, 0),
    ("@PT FFMA R1, R2, R3, R4", PT, 0),
])
def test_predicate_field_splits_into_select_and_negate(text, pred, neg):
    """3 bits select P0-P6/PT, 1 bit negates -- negation is free."""
    f = parse(text).fields
    assert (f["pred"], f["pred_not"]) == (pred, neg)


def test_render_is_the_inverse_of_parse():
    for text in ["FFMA R19, R4.reuse, R6, R8",
                 "@!P3 FFMA R9, R1.reuse, R2.reuse, R3",
                 "FFMA R7, RZ, R3, R1"]:
        assert parse(text).render() == text


# -- refusing what is not calibrated ------------------------------------------

@pytest.mark.parametrize("text,why", [
    ("FFMA R1, R2, 0x5, R3", "immediate field not calibrated"),
    ("FFMA R1, -R2, R3, R4", "operand negation not calibrated"),
    ("FFMA R1, R2, c[0x0][0x160], R3", "constant bank ref not calibrated"),
    ("FFMA R1, R2, R3, R4, R5", "more than three sources"),
    ("@P9 FFMA R1, R2, R3, R4", "predicate out of range"),
    ("", "no mnemonic"),
])
def test_refuses_uncalibrated_forms(text, why):
    with pytest.raises(AsmError):
        parse(text)


def test_refuses_unknown_control_field():
    with pytest.raises(AsmError):
        assemble(FFMA, "FFMA R1, R2, R3, R4", not_a_field=1)


def test_refuses_value_too_wide_for_its_field():
    """stall is 4 bits; 16 must not silently truncate to 0."""
    with pytest.raises(AsmError):
        assemble(FFMA, "FFMA R1, R2, R3, R4", stall=16)


# -- encoding -----------------------------------------------------------------

def test_assemble_writes_the_calibrated_bits():
    enc = assemble(FFMA, "FFMA R19, R4, R6, R8", stall=4, yield_=1)
    assert get_bits(enc, *FIELDS["rd"]) == 19
    assert get_bits(enc, *FIELDS["ra"]) == 4
    assert get_bits(enc, *FIELDS["rb"]) == 6
    assert get_bits(enc, *FIELDS["rc"]) == 8
    assert control_of(enc)["stall"] == 4
    assert control_of(enc)["yield"] == 1


def test_assemble_leaves_uncalibrated_bits_alone():
    """Opcode bits are inherited -- that is the whole point of a template."""
    enc = assemble(FFMA, "FFMA R1, R2, R3, R4")
    untouched = set(range(128)) - {
        b for lo, hi in FIELDS.values() for b in range(lo, hi + 1)}
    for bit in untouched:
        assert get_bits(enc, bit, bit) == get_bits(FFMA, bit, bit)


def test_reuse_is_cleared_when_the_text_omits_it():
    """Otherwise a template that had .reuse set would leak it into every result."""
    with_reuse = assemble(FFMA, "FFMA R1, R2.reuse, R3, R4")
    assert control_of(with_reuse)["reuse"] == 0b001
    assert control_of(assemble(with_reuse, "FFMA R1, R2, R3, R4"))["reuse"] == 0


def test_explicit_control_overrides_the_text():
    enc = assemble(FFMA, "FFMA R1, R2.reuse, R3, R4", reuse=0b100)
    assert control_of(enc)["reuse"] == 0b100
