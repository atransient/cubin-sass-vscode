"""Human-readable codec for a 128-bit sm_90 instruction word.

Two directions, both against the field skeleton established by the notes:

    decode(word)          128-bit -> fields grouped by functional block + effect
    encode(op=.., Rd=..)  field values -> 128-bit encoding

The skeleton is the *global* part of the ISA: opcode +
operand-form, predicate guard, the four operand slots, the scheduling section and
the reuse flags all sit at fixed positions. Per-opcode modifier bits (72:90) are
NOT decoded here -- they mean different things per instruction, so a
generic decoder can only label the skeleton and print the modifier region raw.

    PYTHONPATH=. python3 -m nvisa.model.codec decode 0000000502097223008fca0000000009
    PYTHONPATH=. python3 -m nvisa.model.codec encode op=0x23 form=0b001 Rd=9 Ra=2 Rb=5 Rc=9
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from nvisa.analyze.fields import B_MODES
from nvisa.oracle.cubin import enc_to_int, int_to_enc

# ---------------------------------------------------------------------------
# field-level interpreters: (raw value, whole 128-bit word) -> effect string
# ---------------------------------------------------------------------------


def _reg(v: int, _w: int) -> str:
    return "RZ" if v == 255 else f"R{v}"

def _ureg(v: int, _w: int) -> str:
    return "URZ" if v == 63 else f"UR{v}"

def _hex(v: int, _w: int) -> str:
    return f"{v:#x}"

def _op(v: int, _w: int) -> str:
    return f"{v:#05x}  (operation body; full opcode = op | form<<9)"

def _form(v: int, _w: int) -> str:
    label = B_MODES.get(v, "unknown")
    # This picks which slot (B/C) holds the non-register operand and
    # via which path; the available sources depend on the base datapath.
    return f"{v:03b}  operand-form ({label})"

def _pred(v: int, w: int) -> str:
    neg = w >> 15 & 1
    num = v & 0b111
    name = "PT" if num == 7 else f"P{num}"
    guard = f"@{'!' if neg else ''}{name}"
    if num == 7 and not neg:
        return f"{guard}  (unguarded)"
    return guard

def _stall(v: int, _w: int) -> str:
    if 1 <= v <= 11:
        return f"{v}  (stall {v} cycle{'s' if v > 1 else ''} after issue)"
    return f"{v}  (special: 0 and 12-15 are not a linear count)"

def _yield(v: int, _w: int) -> str:
    return "0  (yield allowed)" if v == 0 else "1  (no-yield: issue next back-to-back)"

def _bar(v: int, _w: int) -> str:
    return "7  (unused)" if v == 7 else f"{v}  (scoreboard {v})"

def _waitmask(v: int, _w: int) -> str:
    if v == 0:
        return "000000  (waits on nothing)"
    waited = [i for i in range(6) if v >> i & 1]
    return f"{v:06b}  (waits on scoreboard{'s' if len(waited) > 1 else ''} {', '.join(map(str, waited))})"

def _reuse(v: int, _w: int) -> str:
    return "1  (.reuse)" if v else "0"


@dataclass(frozen=True)
class Field:
    name: str
    lo: int
    hi: int
    effect: Callable[[int, int], str]
    note: str = ""

    @property
    def width(self) -> int:
        return self.hi - self.lo + 1


#: The skeleton, grouped by the functional block each field feeds, in pipeline
#: order. Order within a block is by bit position. `imm24` overlaps the
#: Rb/Rc region because which one is live depends on operand-form -- both are
#: printed raw and the reader picks by `form`.
BLOCKS: list[tuple[str, list[Field]]] = [
    ("opcode", [
        Field("op",   0,  8,  _op),
        Field("form", 9, 11, _form),
    ]),
    ("predicate", [
        Field("pred", 12, 15, _pred, "guard predicate: 12-14 num, 15 negate"),
    ]),
    ("operands", [
        Field("Rd",    16, 23, _reg, "dest"),
        Field("Ra",    24, 31, _reg, "src A"),
        Field("Rb",    32, 39, _reg, "src B (if form=R)"),
        Field("imm24", 40, 63, _hex, "32-bit immediate lives here when form=imm"),
        Field("Rc",    64, 71, _reg, "src C"),
    ]),
    ("modifiers", [
        # not decoded: per-opcode meaning. Printed raw for context.
        Field("mod", 72, 90, _hex, "per-opcode modifier region -- NOT generic"),
    ]),
    ("scheduling", [
        Field("stall",    105, 108, _stall),
        Field("yield",    109, 109, _yield),
        Field("wrbar",    110, 112, _bar, "write scoreboard idx"),
        Field("rdbar",    113, 115, _bar, "read scoreboard idx"),
        Field("waitmask", 116, 121, _waitmask),
    ]),
    ("reuse", [
        Field("reuse.A", 122, 122, _reuse, "operand collector reuse, src A"),
        Field("reuse.B", 123, 123, _reuse, "src B"),
        Field("reuse.C", 124, 124, _reuse, "src C"),
    ]),
]

#: Flat name -> Field, for encode() and lookups. Aliases let encode() accept the
#: friendly spelling `reuse_a` for the field named `reuse.A`.
_BY_NAME: dict[str, Field] = {f.name: f for _, fs in BLOCKS for f in fs}
_ALIASES = {"reuse_a": "reuse.A", "reuse_b": "reuse.B", "reuse_c": "reuse.C",
            "opcode": "op", "operand_form": "form", "b_mode": "form"}


def _resolve(name: str) -> Field:
    key = _ALIASES.get(name, name)
    if key not in _BY_NAME:
        raise KeyError(f"unknown field {name!r}; known: {', '.join(_BY_NAME)}")
    return _BY_NAME[key]


# ---------------------------------------------------------------------------
# input parsing
# ---------------------------------------------------------------------------


def parse_word(s: str) -> int:
    """Accept the several ways a 128-bit word gets typed, return bit0=LSB int.

    - 32 hex chars, no prefix  -> an `enc` string in nvdisasm print order
                                  (low half first); half-swapped like the corpus.
    - `0x...`                  -> the true 128-bit value, taken as-is.
    - `0b...` or a 0/1 string  -> binary, MSB first (bit 0 = last char).
    """
    s = s.strip().replace("_", "").replace(" ", "")
    if s.startswith("0x"):
        return int(s, 16)
    if s.startswith("0b"):
        return int(s, 2)
    if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
        return enc_to_int(s)              # enc string, low-half-first
    if s and all(c in "01" for c in s):
        return int(s, 2)                  # plain binary
    raise ValueError(f"cannot parse {s!r} as a 128-bit word "
                     "(give 32-hex enc, 0x..., or a binary string)")


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------


def decode(word: str | int) -> list[dict]:
    """Break a 128-bit word into (block, field, bits, raw, effect) rows."""
    w = word if isinstance(word, int) else parse_word(word)
    rows = []
    for block, fields in BLOCKS:
        for f in fields:
            raw = w >> f.lo & (1 << f.width) - 1
            rows.append({
                "block": block, "field": f.name,
                "bits": (f.lo, f.hi), "raw": raw,
                "effect": f.effect(raw, w), "note": f.note,
            })
    return rows


def format_decode(word: str | int) -> str:
    w = word if isinstance(word, int) else parse_word(word)
    rows = decode(w)
    out = [f"word = 0x{w:032x}", f"enc  = {int_to_enc(w)}   (nvdisasm print order)", ""]
    last = None
    for r in rows:
        if r["block"] != last:
            out.append(f"[{r['block']}]")
            last = r["block"]
        lo, hi = r["bits"]
        span = f"{lo}:{hi}" if hi != lo else f"{lo}"
        out.append(f"  {r['field']:<9} bit {span:<7} = {r['raw']:<10} {r['effect']}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# grid: a bit-layout diagram (bit index row + field-span row)
# ---------------------------------------------------------------------------


def _grid_label(f: Field, raw: int) -> str:
    """Short text to drop into a field's merged cell."""
    if f.name == "op":
        return f"op={raw:#x}"
    if f.name == "form":
        return f"form {raw:03b}"
    if f.name == "pred":
        return _pred(raw, raw << 12).split()[0]      # @PT / @!P3 / @P0
    if f.name in ("Rd", "Ra", "Rb", "Rc"):
        return f"{f.name}={_reg(raw, 0)}"
    if f.name == "imm24":
        return f"imm={raw:#x}"
    if f.name == "mod":
        return "modifiers"
    if f.name == "stall":
        return f"stall={raw}"
    if f.name == "yield":
        return f"y={raw}"
    if f.name == "wrbar":
        return f"wb={raw}"
    if f.name == "rdbar":
        return f"rb={raw}"
    if f.name == "waitmask":
        return f"wait={raw:06b}"
    if f.name.startswith("reuse."):
        return f"{f.name[-1]}={raw}"
    return f"{f.name}={raw}"


def _center(text: str, inner: int) -> str:
    if len(text) > inner:
        text = text[: max(0, inner - 1)] + "…" if inner else ""
    return text.center(inner)


#: bits per diagram row (RFC packet-header style); no skeleton field crosses a
#: 32-bit boundary, so rows never split a field.
ROW_BITS = 32


def _segments(owner: dict[int, "Field"], w: int, base: int) -> list[tuple[str, int, int]]:
    """One row's cells as (label, local_start, span). Consecutive unlabelled bits
    merge into one 'raw bits' cell showing their binary value."""
    segs, b = [], base
    while b < base + ROW_BITS:
        f = owner.get(b)
        if f is None:
            start = b
            while b < base + ROW_BITS and owner.get(b) is None:
                b += 1
            span = b - start
            val = w >> start & (1 << span) - 1
            label = "·" if val == 0 else format(val, f"0{span}b")
            segs.append((label, start - base, span))
        else:
            hi = min(f.hi, base + ROW_BITS - 1)
            raw = w >> f.lo & (1 << f.width) - 1
            segs.append((_grid_label(f, raw), b - base, hi - b + 1))
            b = hi + 1
    return segs


def format_grid(word: str | int, cell: int = 3) -> str:
    """Render the 128-bit word as an RFC-style bit-layout diagram: four boxed
    rows of 32 bits, each labelled with a bit ruler, followed by a field legend.

    `cell` is the per-bit column width (each bit occupies `cell` chars including
    its separator), so every row is the same width and columns line up.
    """
    w = word if isinstance(word, int) else parse_word(word)
    owner: dict[int, Field] = {}
    for _, fields in BLOCKS:
        for f in fields:
            for b in range(f.lo, f.hi + 1):
                owner[b] = f

    U = max(2, cell)                      # column stride per bit
    width = ROW_BITS * U + 1              # constant row width

    def row(base: int) -> list[str]:
        segs = _segments(owner, w, base)
        top = list("─" * width); top[0], top[-1] = "┌", "┐"
        bot = list("─" * width); bot[0], bot[-1] = "└", "┘"
        mid = list(" " * width); mid[0] = mid[-1] = "│"
        ruler = list(" " * width)
        for label, start, span in segs:
            c0, c1 = start * U, (start + span) * U      # left/right border cols
            if start != 0:
                top[c0], bot[c0], mid[c0] = "┬", "┴", "│"
            for j, ch in enumerate(str(base + start)):  # absolute bit number
                if c0 + j < width:
                    ruler[c0 + j] = ch
            inner = _center(label, c1 - c0 - 1)
            mid[c0 + 1: c0 + 1 + len(inner)] = list(inner)
        return ["".join(ruler), "".join(top), "".join(mid), "".join(bot)]

    lines = [f"word = 0x{w:032x}", f"enc  = {int_to_enc(w)}", ""]
    for base in range(0, 128, ROW_BITS):
        lines += row(base)
    # legend: the detail the compact cells cannot carry
    lines += ["", "legend:"]
    for r in decode(w):
        lo, hi = r["bits"]
        span = f"{lo}:{hi}" if hi != lo else f"{lo}"
        lines.append(f"  {r['field']:<9} {span:<7} = {r['raw']:<8} {r['effect']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# encode
# ---------------------------------------------------------------------------


def encode(*, base: str | int = 0, **fields: int) -> str:
    """Assemble a 128-bit `enc` string from field values.

    Unspecified bits come from `base` (default 0). `base` accepts the same forms
    as `parse_word`, so you can start from a real instruction and override slots:

        encode(base="...enc...", Rd=17, stall=2)

    Field names are those in BLOCKS (plus aliases: reuse_a, b_mode, opcode).
    """
    w = base if isinstance(base, int) else (parse_word(base) if base else 0)
    for name, value in fields.items():
        f = _resolve(name)
        if value >> f.width:
            raise ValueError(f"{name}={value} does not fit in {f.width} bits "
                             f"(field {f.name} is {f.width} bits wide)")
        w = w & ~((1 << f.width) - 1 << f.lo) | value << f.lo
    return int_to_enc(w)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_int(s: str) -> int:
    return int(s, 0)  # honours 0x / 0b / decimal


def _emit(text: str, out: Path | None) -> None:
    """Always print; also append to a file when --out is given."""
    print(text)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a") as fh:
            fh.write(text + "\n")
        print(f"\n(written to {out})")


def main(argv: list[str] | None = None) -> None:
    import argparse
    from pathlib import Path

    # shared: every subcommand can tee its output to a file
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", type=Path, help="also write the output to this file")

    ap = argparse.ArgumentParser(description="decode/encode a 128-bit sm_90 word")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", parents=[common], help="128-bit word -> labelled fields")
    d.add_argument("word", help="32-hex enc, 0x..., or a binary string")
    d.add_argument("--grid", action="store_true", help="also draw the bit-layout diagram")

    g = sub.add_parser("grid", parents=[common], help="128-bit word -> bit-layout diagram")
    g.add_argument("word", help="32-hex enc, 0x..., or a binary string")
    g.add_argument("--cell", type=int, default=4, help="per-bit column width")

    e = sub.add_parser("encode", parents=[common], help="field=value ... -> 128-bit enc")
    e.add_argument("--base", default="0", help="start from this word (enc/0x/bin)")
    e.add_argument("assignments", nargs="*", metavar="field=value",
                   help="e.g. op=0x23 form=0b001 Rd=9 Ra=2 Rb=5 Rc=9 stall=1")

    s = sub.add_parser("sass", parents=[common], help="128-bit word -> SASS text (nvdisasm)")
    s.add_argument("word", help="32-hex enc, 0x..., or a binary string")
    s.add_argument("--arch", default="SM90", help="nvdisasm -b arch (default SM90)")

    a = sub.add_parser("asm", parents=[common], help="SASS text -> 128-bit enc (template patch)")
    a.add_argument("text", help='e.g. "FFMA R9, R2, R5, R9"')
    a.add_argument("--arch", default="sm_90", help="seed compile arch (default sm_90)")
    a.add_argument("--template", help="32-hex enc to patch instead of a seed template")

    args = ap.parse_args(argv)

    if args.cmd == "decode":
        text = format_decode(args.word)
        if args.grid:
            text += "\n\n" + format_grid(args.word)
    elif args.cmd == "grid":
        text = format_grid(args.word, cell=args.cell)
    elif args.cmd in ("sass", "asm"):
        from nvisa.model import asm as _asm         # lazy: needs toolchain
        from nvisa.model import translate as _tr
        try:
            if args.cmd == "sass":
                text = _tr.to_sass(args.word, arch=args.arch)
            else:
                enc = _tr.from_sass(args.text, arch=args.arch, template=args.template)
                text = (f"enc  = {enc}\nword = 0x{enc_to_int(enc):032x}\n"
                        f"nvdisasm reads back: {_tr.to_sass(enc)}")
        except (_tr.TranslateError, _asm.AsmError) as err:
            raise SystemExit(f"error: {err}") from err
    else:
        fields = {}
        for a in args.assignments:
            k, _, v = a.partition("=")
            if not _:
                ap.error(f"expected field=value, got {a!r}")
            fields[k] = _parse_int(v)
        enc = encode(base=args.base, **fields)
        text = (f"enc  = {enc}\nword = 0x{enc_to_int(enc):032x}\n\n"
                + format_decode(enc))

    _emit(text, args.out)


if __name__ == "__main__":
    main()
