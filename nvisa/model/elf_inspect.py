"""`inspect` 阶段。

ELF 改写走两阶段事务，第一步是 `inspect`：**只读**地说清楚「这份文件是什么、
里面有哪些 section/segment/引用/调试数据、哪些东西我们证明不了」。它必须能单独
运行并输出版本化 JSON（含输入 hash），因为 `apply` 只接受与输入 hash 对应的 plan。

和 `elf_rewrite.py` 的分工：那边是 sm_90 专用的**写**路径，见到别的架构直接拒绝；
这里是**架构无关的读**路径 —— 认不出的架构照样要能 inspect，只是 profile 的能力
集会告诉你「除了看，什么都不能做」。

## 不猜的两处

- **segment 归属按 containment 关系算**，和 `elf_rewrite._segment_members()` 同一
  条规矩：section 落在哪个 program header 的 `[p_offset, p_offset+max(filesz,memsz))`
  里就属于谁，NOBITS 也算（`p_filesz=0` 的共享内存段就是这么来的）。
- **认不出的东西进 `unverified`，不进结论**：未知 section 类型、未知 `.nv.info`
  属性、未知重定位类型只登记，不解释成「没问题」。
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from nvisa.model.arch import ArchError, ArchitectureProfile, detect_arch, profile_for

SCHEMA = "nvisa.inspect/1"

_SHT_NAMES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
              5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
              11: "DYNSYM",
              # NVIDIA 私有类型：名字来自本项目已建模的两个 section
              # （`reflow` 解析 `.nv.info`），不是从类型号猜的。
              0x70000000: "NV_INFO", 0x70000001: "NV_CALLGRAPH"}
_PT_NAMES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
             5: "SHLIB", 6: "PHDR"}
_SHF = {0x1: "WRITE", 0x2: "ALLOC", 0x4: "EXECINSTR", 0x10: "MERGE",
        0x20: "STRINGS", 0x40: "INFO_LINK", 0x200: "OS_NONCONFORMING"}
# 调试 section 的分类是 `debug_policy.classify()` 那一份，不在这里另立一套。


class InspectError(ValueError):
    pass


def _flag_names(flags: int) -> list[str]:
    out = [n for b, n in _SHF.items() if flags & b]
    rest = flags & ~sum(_SHF)
    if rest:
        out.append(hex(rest))
    return out


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _header(data: bytes) -> dict:
    if len(data) < 64:
        raise InspectError(f"文件只有 {len(data)} 字节，装不下 ELF64 header")
    (e_type, e_machine) = struct.unpack_from("<HH", data, 16)
    (_v, entry, phoff, shoff, flags, ehsize, phentsize, phnum,
     shentsize, shnum, shstrndx) = struct.unpack_from("<IQQQIHHHHHH", data, 20)
    return {"type": e_type, "machine": e_machine, "entry": entry,
            "phoff": phoff, "shoff": shoff, "flags": flags, "ehsize": ehsize,
            "phentsize": phentsize, "phnum": phnum, "shentsize": shentsize,
            "shnum": shnum, "shstrndx": shstrndx}


def read_sections(data: bytes) -> list[dict]:
    """架构无关地解 SHT。名字表本身坏了就报错，不返回半份表。"""
    h = _header(data)
    if h["shentsize"] not in (0, 64):
        raise InspectError(f"e_shentsize={h['shentsize']}，不是 ELF64 的 64")
    end = h["shoff"] + h["shnum"] * 64
    if h["shnum"] and end > len(data):
        raise InspectError(f"section header table 越过文件末尾（{end} > {len(data)}）")
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, h["shoff"] + i * 64)
           for i in range(h["shnum"])]
    if h["shstrndx"] >= len(raw):
        raise InspectError(f"e_shstrndx={h['shstrndx']} 越界（shnum={len(raw)}）")
    stro = raw[h["shstrndx"]][4] if raw else 0

    def name_at(off: int) -> str:
        pos = stro + off
        try:
            return data[pos:data.index(b"\0", pos)].decode("utf-8", "replace")
        except ValueError as e:
            raise InspectError(f".shstrtab 里 offset {off} 没有结尾 NUL") from e

    out = []
    for i, r in enumerate(raw):
        file_backed = r[1] not in (0, 8)
        out.append({"idx": i, "name": name_at(r[0]) if raw else "", "name_off": r[0],
                    "type": r[1], "type_name": _SHT_NAMES.get(r[1], hex(r[1])),
                    "flags": r[2], "flag_names": _flag_names(r[2]),
                    "addr": r[3], "offset": r[4], "size": r[5],
                    "link": r[6], "info": r[7], "align": r[8], "entsize": r[9],
                    "file_backed": file_backed})
    return out


def read_segments(data: bytes) -> list[dict]:
    h = _header(data)
    if h["phnum"] and h["phentsize"] != 56:
        raise InspectError(f"e_phentsize={h['phentsize']}，不是 ELF64 的 56")
    end = h["phoff"] + h["phnum"] * 56
    if h["phnum"] and end > len(data):
        raise InspectError(f"program header table 越过文件末尾（{end} > {len(data)}）")
    out = []
    for i in range(h["phnum"]):
        (p_type, p_flags, off, vaddr, paddr, filesz, memsz, align) = \
            struct.unpack_from("<IIQQQQQQ", data, h["phoff"] + i * 56)
        out.append({"idx": i, "type": p_type,
                    "type_name": _PT_NAMES.get(p_type, hex(p_type)),
                    "flags": p_flags, "offset": off, "vaddr": vaddr,
                    "paddr": paddr, "filesz": filesz, "memsz": memsz,
                    "align": align})
    return out


def segment_members(secs: list[dict], segs: list[dict]) -> None:
    """按 containment 关系互相登记成员（就地写 `sections` / `segments`）。"""
    for s in secs:
        s["segments"] = []
    for p in segs:
        lo, hi = p["offset"], p["offset"] + max(p["filesz"], p["memsz"])
        members = []
        for s in secs:
            if not s["idx"]:
                continue
            if not s["file_backed"]:
                inside = lo <= s["offset"] <= hi
            else:
                inside = s["offset"] >= lo and s["offset"] + s["size"] <= hi
            if inside:
                members.append(s["name"])
                s["segments"].append(p["idx"])
        p["sections"] = members


def _references(data: bytes, secs: list[dict]) -> tuple[dict, list[str]]:
    """`sh_link` / `sh_info` / symbol `st_shndx` / RELA 引用是否闭合。"""
    n = len(secs)
    bad: list[str] = []
    links, infos, syms, relas = [], [], [], []
    for s in secs:
        if s["type"] in (2, 3, 4, 11) or s["link"]:
            if s["link"] >= n:
                bad.append(f"{s['name']}.sh_link={s['link']} 越界（shnum={n}）")
            elif s["link"]:
                links.append({"from": s["name"], "to": secs[s["link"]]["name"]})
        if s["type"] == 4 and s["info"]:
            if s["info"] >= n:
                bad.append(f"{s['name']}.sh_info={s['info']} 越界（shnum={n}）")
            else:
                infos.append({"from": s["name"], "to": secs[s["info"]]["name"]})
    for s in secs:
        if s["type"] != 2:                                  # SYMTAB
            continue
        cnt = s["size"] // 24 if s["entsize"] in (0, 24) else 0
        strtab = secs[s["link"]] if s["link"] < n else None
        for i in range(cnt):
            off = s["offset"] + i * 24
            st_name, st_info, _o, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, off)
            if st_shndx < 0xFF00 and st_shndx >= n:
                bad.append(f"symbol #{i} 的 st_shndx={st_shndx} 越界")
            name = ""
            if strtab is not None and st_name:
                pos = strtab["offset"] + st_name
                cut = data.find(b"\0", pos)
                name = data[pos:cut].decode("utf-8", "replace") if cut > 0 else ""
            syms.append({"name": name, "shndx": st_shndx, "value": st_value,
                         "size": st_size, "info": st_info})
    for s in secs:
        if s["type"] != 4:                                  # RELA
            continue
        cnt = s["size"] // 24
        types: dict[int, int] = {}
        for i in range(cnt):
            _off, r_info, _add = struct.unpack_from("<QQq", data,
                                                    s["offset"] + i * 24)
            types[r_info & 0xFFFFFFFF] = types.get(r_info & 0xFFFFFFFF, 0) + 1
        relas.append({"section": s["name"], "count": cnt,
                      "applies_to": secs[s["info"]]["name"] if s["info"] < n else None,
                      "types": {str(k): v for k, v in sorted(types.items())}})
    return {"sh_link": links, "sh_info": infos, "symbols": syms,
            "relocations": relas}, bad


def _structure_problems(data: bytes, secs: list[dict], segs: list[dict]) -> list[str]:
    bad = []
    spans = []
    for s in secs:
        if not s["idx"] or not s["file_backed"]:
            continue
        if s["offset"] + s["size"] > len(data):
            bad.append(f"{s['name']} 越过文件末尾（{s['offset']:#x}+{s['size']:#x}）")
        if s["align"] > 1 and s["offset"] % s["align"]:
            bad.append(f"{s['name']} 偏移 {s['offset']:#x} 不满足 align={s['align']}")
        spans.append((s["offset"], s["offset"] + s["size"], s["name"]))
    spans.sort()
    for (_a0, a1, na), (b0, _b1, nb) in zip(spans, spans[1:]):
        if b0 < a1:
            bad.append(f"{na} 与 {nb} 重叠")
    for p in segs:
        if p["offset"] + p["filesz"] > len(data):
            bad.append(f"program header #{p['idx']} 越过文件末尾")
        if p["align"] > 1 and (p["offset"] - p["vaddr"]) % p["align"]:
            bad.append(f"program header #{p['idx']} 不满足 p_align 同余")
    return bad


def debug_facts(secs: list[dict], refs: dict) -> list[dict]:
    """每个调试 section 的结构化事实 —— 给调试策略（`debug_policy`）用，不在这里下结论。

    `kind` 用 `debug_policy.classify()` 的同一套分类，免得两处各说一套；
    `rewritable` 只对本项目有 parser + 回归测试的格式为真。
    """
    from nvisa.model.debug_policy import KNOWN_DEBUG_RELA_TYPES, classify
    out = []
    for s in secs:
        kind = classify(s["name"])
        if kind is None:
            continue
        relas = [r for r in refs["relocations"] if r["applies_to"] == s["name"]]
        types = sorted({int(k) for r in relas for k in r["types"]})
        out.append({"name": s["name"], "kind": kind, "size": s["size"],
                    "rela": [r["section"] for r in relas],
                    "rela_types": types,
                    "unknown_rela_types": [t for t in types
                                           if t not in KNOWN_DEBUG_RELA_TYPES],
                    "rewritable": kind == "frame"})
    return out


def inspect(data: bytes, *, path: str | Path | None = None,
            requested_arch: str | None = None) -> dict:
    """只读地把一份 cubin 讲清楚，返回版本化 JSON（dict）。

    识别不出架构不是错误，是**结论**：`arch.detected` 为空、能力集只有 `read`
    并在 `unverified` 里记下原因，ELF 层面照常 inspect（只读一档）。
    """
    secs = read_sections(data)
    segs = read_segments(data)
    segment_members(secs, segs)
    refs, ref_bad = _references(data, secs)
    rejects = _structure_problems(data, secs, segs) + ref_bad
    unverified: list[str] = []

    profile: ArchitectureProfile | None = None
    detected: str | None = None
    try:
        detected, sm, flags = detect_arch(data)
        profile = profile_for(data, requested_arch)
    except ArchError as e:
        sm, flags = None, _header(data)["flags"]
        unverified.append(f"架构：{e}")
        if requested_arch is not None:
            rejects.append(str(e))
    if profile is not None:
        missing = profile.missing_artifacts()
        if missing:
            unverified.append(
                f"{profile.arch} 登记的产物缺文件：{', '.join(missing)}")
        if not profile.has("assemble"):
            unverified.append(f"{profile.arch} 不可汇编：{profile.note}")

    for s in secs:
        if s["idx"] and s["type_name"].startswith("0x"):
            unverified.append(f"{s['name']} 的 sh_type={s['type']} 未建模")
    debug = debug_facts(secs, refs)
    if debug:
        unverified.append(
            "调试 section 需要显式的调试策略（preserve/strip/rewrite）："
            + ", ".join(d["name"] for d in debug))
        unknown_rel = sorted({t for d in debug for t in d["unknown_rela_types"]})
        if unknown_rel:
            unverified.append(
                "调试重定位里有认不出的类型："
                + "、".join(hex(t) for t in unknown_rel)
                + " —— preserve/rewrite 会因此被拒绝")

    h = _header(data)
    return {
        "schema": SCHEMA,
        "input": {"path": str(path) if path is not None else None,
                  "size": len(data), "sha256": sha256(data)},
        "arch": {"detected": detected, "requested": requested_arch,
                 "sm": sm, "e_flags": flags,
                 "profile": profile.to_json() if profile else None},
        "elf": h,
        "sections": secs,
        "segments": segs,
        "references": refs,
        "debug_sections": debug,
        "rejects": rejects,
        "unverified": unverified,
        #: 本模块只读，永远不能声称跑过硬件。
        "hardware_verified": False,
    }


def inspect_file(path: str | Path, *, requested_arch: str | None = None) -> dict:
    p = Path(path)
    return inspect(p.read_bytes(), path=p, requested_arch=requested_arch)


def summary(rep: dict) -> str:
    a = rep["arch"]
    caps = ",".join(a["profile"]["capabilities"]) if a["profile"] else "-"
    return (f"{rep['input']['path'] or '<bytes>'}：{a['detected'] or '架构未知'}"
            f"（能力 {caps}），{len(rep['sections'])} section / "
            f"{len(rep['segments'])} segment，"
            f"拒绝 {len(rep['rejects'])} 项、未验证 {len(rep['unverified'])} 项")


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="只读 inspect 一个 cubin/ELF")
    ap.add_argument("cubin", type=Path)
    ap.add_argument("--arch", help="只用于核对，冲突即拒绝（不覆盖检测）")
    ap.add_argument("--json", type=Path, help="把版本化报告写到这里")
    args = ap.parse_args(argv)
    rep = inspect_file(args.cubin, requested_arch=args.arch)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rep, indent=2, ensure_ascii=False))
    print(summary(rep))
    for r in rep["rejects"]:
        print("  拒绝：" + r)
    for u in rep["unverified"]:
        print("  未验证：" + u)
    return 1 if rep["rejects"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
