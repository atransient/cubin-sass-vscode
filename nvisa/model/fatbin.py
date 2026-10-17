"""Locate and update cubins embedded in a CUDA host ELF fatbinary.

CUDA host objects/executables keep device images in ``.nv_fatbin``.  The
outer ELF and the fatbinary record are containers; the payload of an ELF
entry is an ordinary cubin, so the existing cubin editor can operate on it
unchanged.  This module deliberately supports only uncompressed ELF entries
and exact-size replacement.  Both restrictions let an edit preserve every
outer ELF offset, relocation and program header byte-for-byte.
"""
from __future__ import annotations

import struct
import hashlib
from dataclasses import dataclass


FATBIN_MAGIC = 0xBA55ED50
ELF_MAGIC = b"\x7fELF"
EM_CUDA = 190
FATBIN_KIND_ELF = 2
SHT_NOBITS = 8


class FatbinError(ValueError):
    """The input is not a supported CUDA image container."""


@dataclass(frozen=True)
class EmbeddedCubin:
    """One uncompressed cubin payload inside a host ELF."""

    index: int
    section: str
    payload_offset: int
    payload_size: int
    sm: int
    entry_offset: int
    text_sections: tuple[str, ...] = ()

    @property
    def arch(self) -> str:
        return f"sm_{self.sm}"

    def describe(self) -> dict:
        return {
            "index": self.index,
            "section": self.section,
            "arch": self.arch,
            "payload_offset": self.payload_offset,
            "payload_size": self.payload_size,
            "text_sections": list(self.text_sections),
        }


@dataclass(frozen=True)
class CubinImage:
    """A selected standalone or embedded cubin and its outer container."""

    outer: bytes
    cubin: bytes
    embedded: EmbeddedCubin | None = None

    @property
    def payload_offset(self) -> int:
        return self.embedded.payload_offset if self.embedded else 0

    @property
    def kind(self) -> str:
        return "fatbin" if self.embedded else "cubin"

    def inner_offset(self, outer_offset: int) -> int:
        if not self.embedded:
            return outer_offset
        lo = self.embedded.payload_offset
        hi = lo + self.embedded.payload_size
        if not lo <= outer_offset < hi:
            raise FatbinError(
                f"文件偏移 {outer_offset:#x} 不在所选 {self.embedded.arch} cubin "
                f"payload {lo:#x}..{hi:#x} 内")
        return outer_offset - lo

    def outer_offset(self, inner_offset: int) -> int:
        return self.payload_offset + inner_offset

    def replace(self, cubin: bytes) -> bytes:
        """Return the outer file with an exact-size cubin replacement."""
        cubin = bytes(cubin)
        if not self.embedded:
            return cubin
        if len(cubin) != self.embedded.payload_size:
            raise FatbinError(
                "内嵌 cubin 的长度不能改变："
                f"{self.embedded.payload_size} -> {len(cubin)} 字节。"
                "当前只支持等长编辑，以保证宿主 ELF/fatbin 的布局与重定位不变")
        out = bytearray(self.outer)
        lo = self.embedded.payload_offset
        out[lo:lo + len(cubin)] = cubin
        return bytes(out)

    def info(self) -> dict:
        cubin_base = hashlib.sha256(self.cubin).hexdigest()[:16]
        if not self.embedded:
            return {"kind": "cubin", "embedded": False, "payload_offset": 0,
                    "payload_size": len(self.cubin), "cubin_base": cubin_base}
        return {"kind": "fatbin", "embedded": True,
                **self.embedded.describe(), "cubin_base": cubin_base}


def _elf64_sections(data: bytes) -> list[tuple[str, int, int]]:
    if data[:4] != ELF_MAGIC:
        raise FatbinError("不是 ELF 文件")
    if len(data) < 64 or data[4] != 2 or data[5] != 1:
        raise FatbinError("只支持 little-endian ELF64 宿主文件")
    try:
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    except struct.error as e:
        raise FatbinError("ELF 头不完整") from e
    if shentsize < 64 or not shnum or shstrndx >= shnum:
        raise FatbinError("ELF section header table 无效")
    if shoff + shentsize * shnum > len(data):
        raise FatbinError("ELF section header table 越过文件末尾")

    def header(i: int) -> tuple[int, int, int, int]:
        pos = shoff + i * shentsize
        name, sec_type = struct.unpack_from("<II", data, pos)
        off, size = struct.unpack_from("<QQ", data, pos + 24)
        return name, sec_type, off, size

    _name, _type, str_off, str_size = header(shstrndx)
    if str_off + str_size > len(data):
        raise FatbinError("section name table 越过文件末尾")
    out = []
    for i in range(shnum):
        name_idx, sec_type, off, size = header(i)
        if name_idx >= str_size or (sec_type != SHT_NOBITS and off + size > len(data)):
            raise FatbinError(f"ELF section #{i} 越过文件边界")
        end = data.find(b"\0", str_off + name_idx, str_off + str_size)
        if end < 0:
            raise FatbinError(f"ELF section #{i} 名字没有结尾")
        name = data[str_off + name_idx:end].decode("utf-8", "replace")
        out.append((name, off, size))
    return out


def _cubin_sm(payload: bytes) -> int:
    if len(payload) < 64 or payload[:4] != ELF_MAGIC:
        raise FatbinError("fatbin ELF 条目不是未压缩 cubin")
    machine, = struct.unpack_from("<H", payload, 18)
    if machine != EM_CUDA:
        raise FatbinError(f"fatbin ELF 条目的 e_machine={machine}，不是 CUDA cubin")
    flags, = struct.unpack_from("<I", payload, 0x30)
    return flags & 0xFF


def embedded_cubins(data: bytes) -> list[EmbeddedCubin]:
    """List all uncompressed cubin entries in host ``.nv_fatbin`` sections."""
    data = bytes(data)
    sections = _elf64_sections(data)
    found: list[EmbeddedCubin] = []
    for sec_name, sec_off, sec_size in sections:
        if not sec_name.startswith(".nv_fatbin"):
            continue
        pos, sec_end = sec_off, sec_off + sec_size
        while pos + 16 <= sec_end:
            magic, = struct.unpack_from("<I", data, pos)
            if magic != FATBIN_MAGIC:
                # Linkers may leave zero alignment between concatenated records.
                if data[pos:min(pos + 8, sec_end)].strip(b"\0"):
                    raise FatbinError(
                        f"{sec_name} +{pos - sec_off:#x} 不是 fatbin 记录头")
                pos += 8
                continue
            _magic, version, header_size, fat_size = struct.unpack_from(
                "<IHHQ", data, pos)
            if version != 1 or header_size < 16:
                raise FatbinError(
                    f"不支持的 fatbin header：version={version}, size={header_size}")
            end = pos + header_size + fat_size
            if end > sec_end:
                raise FatbinError("fatbin 记录越过 .nv_fatbin section 末尾")
            ent = pos + header_size
            while ent + 16 <= end:
                kind, _entry_version, entry_size, padded_size = struct.unpack_from(
                    "<HHIQ", data, ent)
                if not kind and not entry_size and not padded_size:
                    break
                if entry_size < 16 or ent + entry_size + padded_size > end:
                    raise FatbinError(
                        f"fatbin entry @ {ent:#x} 的 header/payload 长度无效")
                payload_off = ent + entry_size
                if kind == FATBIN_KIND_ELF:
                    payload = data[payload_off:payload_off + padded_size]
                    try:
                        sm = _cubin_sm(payload)
                    except FatbinError:
                        # Compressed ELF images do not begin with ELF_MAGIC.  Do
                        # not misreport them as editable, but keep scanning PTX
                        # and any following entries.
                        pass
                    else:
                        from nvisa.oracle.cubin import Cubin
                        names = tuple(s.name for s in Cubin(payload).sections)
                        found.append(EmbeddedCubin(
                            len(found), sec_name, payload_off, padded_size, sm, ent,
                            names))
                ent += entry_size + padded_size
            pos = end
    return found


def open_cubin_image(data: bytes, *, image: int | None = None,
                     sm: int = 90) -> CubinImage:
    """Open a standalone cubin or select an embedded ``sm`` cubin.

    ``image`` is the stable index returned by :func:`embedded_cubins`.  Without
    it, selection succeeds only when exactly one editable image matches the
    requested SM, so multi-translation-unit executables are never guessed.
    """
    data = bytes(data)
    if data[:4] != ELF_MAGIC:
        raise FatbinError("不是 ELF/cubin 文件")
    if len(data) >= 20:
        machine, = struct.unpack_from("<H", data, 18)
        if machine == EM_CUDA:
            actual = _cubin_sm(data)
            if actual != sm:
                raise FatbinError(f"这份 cubin 是 sm_{actual}，需要 sm_{sm}")
            return CubinImage(data, data)

    images = embedded_cubins(data)
    if image is not None:
        hit = next((x for x in images if x.index == image), None)
        if hit is None:
            raise FatbinError(
                f"找不到 fatbin image #{image}；可编辑 image："
                + ", ".join(f"#{x.index} {x.arch}" for x in images))
        if hit.sm != sm:
            raise FatbinError(f"fatbin image #{image} 是 {hit.arch}，需要 sm_{sm}")
    else:
        matches = [x for x in images if x.sm == sm]
        if not matches:
            available = sorted({x.arch for x in images})
            detail = ("；检测到可读取的 " + "、".join(available)
                      if available else "；没有检测到未压缩的 device ELF")
            raise FatbinError(
                f"宿主 ELF 中没有 sm_{sm} cubin{detail}。"
                f"当前编辑器只支持 sm_{sm}，请用 -arch=sm_{sm} / "
                f"-gencode arch=compute_{sm},code=sm_{sm} 重新编译")
        # nvcc-linked executables commonly carry a small helper cubin with no
        # executable section next to the application's cubin.  It has nothing
        # the SASS editor could show, so it is safe to exclude from ambiguity.
        visible = [x for x in matches if x.text_sections]
        if len(visible) == 1:
            matches = visible
        if len(matches) != 1:
            choices = ", ".join(
                f"#{x.index} {x.section}@{x.payload_offset:#x}" for x in matches)
            err = FatbinError(
                f"宿主 ELF 中有 {len(matches)} 个 sm_{sm} cubin，请用 --image 选择："
                + choices)
            err.images = [x.describe() for x in matches]
            raise err
        hit = matches[0]
    payload = data[hit.payload_offset:hit.payload_offset + hit.payload_size]
    return CubinImage(data, payload, hit)
