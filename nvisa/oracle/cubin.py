"""cubin read/write: locate .text, read and inject 128-bit encodings.

A cubin is a plain ELF64 container, so nothing here needs
reverse engineering -- section headers tell us exactly where code lives.
Instructions are fixed 16 bytes with no padding, so an instruction address
inside a section is a direct byte offset.

Byte order note: nvdisasm prints an instruction as two 64-bit halves, low
half first.  On disk those halves are stored little-endian back to back, so

    file bytes  23 72 09 02 05 00 00 00 | 23 0e 00 00 00 00 c0 00
    enc string  0000000502097223          00c00000000e0e23
                ^ low half                ^ high half

`enc` throughout this project is the concatenation, matching Inst.enc.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
# enc_to_int 原来这里和 analyze.fields 各写了一份，留 analyze.fields（无依赖的叶子）那份
from nvisa.analyze.fields import enc_to_int

INST_BYTES = 16

_SHT_PROGBITS = 1
_SHT_SYMTAB = 2
_SHF_EXECINSTR = 0x4
_STT_FUNC = 2

# .nv.info entry: format byte, attribute byte, u16 payload size, then payload.
# EIATTR_REGCOUNT payload is (u32 symbol index, u32 register count).
_EIFMT_SVAL = 0x04
_EIATTR_REGCOUNT = 0x2F


def enc_to_bytes(enc: str) -> bytes:
    """'<low64hex><high64hex>' -> 16 little-endian bytes."""
    if len(enc) != 32:
        raise ValueError(f"encoding must be 32 hex chars, got {len(enc)}")
    lo = int(enc[:16], 16)
    hi = int(enc[16:], 16)
    return struct.pack("<QQ", lo, hi)


def enc_from_bytes(raw: bytes) -> str:
    lo, hi = struct.unpack("<QQ", raw)
    return f"{lo:016x}{hi:016x}"


@dataclass(frozen=True)
class Section:
    name: str
    offset: int   # file offset
    size: int

    def __contains__(self, addr: int) -> bool:
        return 0 <= addr < self.size


class Cubin:
    """Mutable in-memory cubin. Patch encodings, then `save()` and re-query."""

    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)
        self.sections = self._parse_sections()

    @classmethod
    def load(cls, path: Path) -> "Cubin":
        return cls(Path(path).read_bytes())

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(self.data))
        return path

    @property
    def sm_arch(self) -> int:
        """Real SM version recorded in the CUDA ELF ``e_flags`` low byte."""
        flags, = struct.unpack_from("<I", self.data, 0x30)
        return flags & 0xFF

    # -- ELF ---------------------------------------------------------------

    def _headers(self):
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2:
            raise ValueError("not an ELF64 file")
        e_shoff, = struct.unpack_from("<Q", d, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)

        def hdr(i: int) -> tuple:
            # name, type, flags, addr, offset, size
            return struct.unpack_from("<IIQQQQ", d, e_shoff + i * e_shentsize)

        strtab_off = hdr(e_shstrndx)[4]

        def name_at(idx: int) -> str:
            end = d.index(b"\0", strtab_off + idx)
            return d[strtab_off + idx : end].decode()

        return [(name_at(hdr(i)[0]), *hdr(i)[1:]) for i in range(e_shnum)]

    def _parse_sections(self) -> list[Section]:
        return [
            Section(name, off, size)
            for name, s_type, flags, _addr, off, size in self._headers()
            if s_type == _SHT_PROGBITS and flags & _SHF_EXECINSTR
        ]

    # -- kernel metadata ---------------------------------------------------

    def _regcount_slots(self) -> list[tuple[int, int, int]]:
        """Find EIATTR_REGCOUNT entries: (payload offset, symbol index, count)."""
        out = []
        for name, _t, _f, _a, off, size in self._headers():
            if not name.startswith(".nv.info"):
                continue
            pos = off
            end = off + size
            while pos + 4 <= end:
                fmt, attr, plen = struct.unpack_from("<BBH", self.data, pos)
                if fmt != _EIFMT_SVAL:      # non-SVAL entries carry no payload
                    pos += 4
                    continue
                body = pos + 4
                if attr == _EIATTR_REGCOUNT and plen >= 8:
                    sym, cnt = struct.unpack_from("<II", self.data, body)
                    out.append((body, sym, cnt))
                pos = body + plen
        return out

    @property
    def regcounts(self) -> dict[int, int]:
        """Registers allocated per kernel, keyed by symbol index."""
        return {sym: cnt for _off, sym, cnt in self._regcount_slots()}

    def _function_sections(self) -> dict[int, int]:
        """Function symbol index -> executable section index."""
        out = {}
        for _name, s_type, _flags, _addr, off, size in self._headers():
            if s_type != _SHT_SYMTAB:
                continue
            for index, pos in enumerate(range(off, off + size, 24)):
                _nm, info, _other, shndx, _value, _size = struct.unpack_from(
                    "<IBBHQQ", self.data, pos)
                if (info & 0xF) == _STT_FUNC:
                    out[index] = shndx
        return out

    def regcount_for_section(self, section: str) -> int | None:
        """Return the declared register allocation for one kernel section."""
        sec_idx = next((i for i, h in enumerate(self._headers())
                        if h[0] == section), None)
        if sec_idx is None:
            raise KeyError(f"no section {section!r}")
        funcs = self._function_sections()
        hits = [count for _off, sym, count in self._regcount_slots()
                if funcs.get(sym) == sec_idx]
        return min(hits) if hits else None

    def set_section_regcount(self, section: str, count: int) -> int:
        """Set EIATTR_REGCOUNT only for function symbols in ``section``."""
        if not 0 < count <= 255:
            raise ValueError("register count must be in 1..255")
        sec_idx = next((i for i, h in enumerate(self._headers())
                        if h[0] == section), None)
        if sec_idx is None:
            raise KeyError(f"no section {section!r}")
        funcs = self._function_sections()
        changed = 0
        for off, sym, _old in self._regcount_slots():
            if funcs.get(sym) != sec_idx:
                continue
            struct.pack_into("<I", self.data, off + 4, count)
            changed += 1
        return changed

    def set_regcount(self, count: int) -> int:
        """Raise every kernel's declared register budget.

        ptxas records exactly what it needed (e.g. 12).  Patch an instruction to
        touch R200 and the launch dies with ILLEGAL_INSTRUCTION at sync -- not
        because the encoding is wrong, but because the register was never
        allocated.  Widening this budget is what makes full 0-255 field sweeps
        executable on real hardware.
        """
        if not 0 < count <= 255:
            raise ValueError("register count must be in 1..255")
        slots = self._regcount_slots()
        for off, _sym, _cnt in slots:
            struct.pack_into("<I", self.data, off + 4, count)
        return len(slots)

    def section(self, name_or_prefix: str = "") -> Section:
        """Find an executable section. Empty name picks the only one."""
        if not name_or_prefix:
            if len(self.sections) != 1:
                names = [s.name for s in self.sections]
                raise ValueError(f"ambiguous, pick one of {names}")
            return self.sections[0]
        for s in self.sections:
            if s.name == name_or_prefix or s.name.endswith(name_or_prefix):
                return s
        raise KeyError(f"no executable section matching {name_or_prefix!r}")

    # -- instructions ------------------------------------------------------

    def read(self, addr: int, section: str = "") -> str:
        sec = self.section(section)
        if addr not in sec:
            raise IndexError(f"0x{addr:x} outside {sec.name} (size 0x{sec.size:x})")
        off = sec.offset + addr
        return enc_from_bytes(bytes(self.data[off : off + INST_BYTES]))

    def write(self, addr: int, enc: str, section: str = "") -> None:
        sec = self.section(section)
        if addr not in sec:
            raise IndexError(f"0x{addr:x} outside {sec.name} (size 0x{sec.size:x})")
        off = sec.offset + addr
        self.data[off : off + INST_BYTES] = enc_to_bytes(enc)

    def patched(self, addr: int, enc: str, section: str = "") -> "Cubin":
        """Non-destructive variant: return a copy with one instruction replaced."""
        clone = Cubin(bytes(self.data))
        clone.write(addr, enc, section)
        return clone


# -- bit-level helpers on `enc` strings ------------------------------------


def int_to_enc(val: int) -> str:
    return f"{val & (1 << 64) - 1:016x}{val >> 64 & (1 << 64) - 1:016x}"


def get_bits(enc: str, lo: int, hi: int) -> int:
    """Extract inclusive bit range [lo, hi]."""
    return enc_to_int(enc) >> lo & (1 << hi - lo + 1) - 1


def set_bits(enc: str, lo: int, hi: int, value: int) -> str:
    width = hi - lo + 1
    if value >> width:
        raise ValueError(f"{value} does not fit in {width} bits")
    mask = (1 << width) - 1 << lo
    return int_to_enc(enc_to_int(enc) & ~mask | value << lo)


def flip_bit(enc: str, bit: int) -> str:
    return int_to_enc(enc_to_int(enc) ^ 1 << bit)
