"""插入/删除指令。

这件事最初被判断为「不建议现在做」，理由是插入一条要处理 `.text` 扩容、后续地址
整体偏移、跳转目标重定位，是「改一条指令」和「改一个程序」的量级差异。这里做的
是**不扩容的那一半**：段的大小、每个函数的大小、所有 ELF 布局元数据一位不动，
只在**一个函数体内挪动一段窗口**，插入吃掉窗口末尾的一条 `NOP`、删除在窗口末尾
补一条 `NOP`。ptxas 在最后一个函数尾部留的那串对齐填充 `NOP` 正是这里的额度。

于是要处理的只剩两件真事：

1. **PC 相对分支**（`BRA`/`CALL.REL`/`RET.REL`）—— 窗口内外都可能跨过挪动点。
   按段表 `slot_facts` 里的偏移合成规则把每条分支解成
   **绝对目标地址**，过一遍「旧地址 → 新地址」的映射再写回去，只动偏移那几位。
2. **`.nv.info` 里记指令偏移的属性**（`EIATTR_EXIT_INSTR_OFFSETS` 这类）——
   它们直接记着某条指令在函数里的偏移，指令挪了不改就指到别的指令上。

不在范围里、且会**明确拒绝**而不是硬来的：跨函数边界的窗口（要改符号的
`st_value`/`st_size`、`.debug_frame` 的重定位加数，那才是「改一个程序」）、
末尾没有可牺牲的 `NOP`、`BRX` 这类目标在常量表里的间接跳转、以及段表读不出
偏移规则的分支 key。
"""
from __future__ import annotations

import struct

INST = 16                       # 一条指令 16 字节
_SHT_SYMTAB = 2
_STT_FUNC = 2

#: `.nv.info*` 里 payload 是「指令偏移数组」的属性码。语料里逐条对着
#: `cuobjdump -elf` 的属性名认出来的：0x1c `EIATTR_EXIT_INSTR_OFFSETS`、
#: 0x28 `EIATTR_COOP_GROUP_INSTR_OFFSETS`、0x31 `EIATTR_INT_WARP_WIDE_INSTR_OFFSETS`。
#: 偏移相对**这一节名字所指的那个函数**的起点。
OFFSET_ATTRS = {0x1C: "EIATTR_EXIT_INSTR_OFFSETS",
                0x28: "EIATTR_COOP_GROUP_INSTR_OFFSETS",
                0x31: "EIATTR_INT_WARP_WIDE_INSTR_OFFSETS"}
_EIFMT_SVAL = 4


class ReflowError(ValueError):
    pass


# --- ELF 读取（只读头，不改布局）-------------------------------------------

def _headers(data: bytes) -> list[tuple]:
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ReflowError("不是 ELF64")
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    es, n, strn = struct.unpack_from("<HHH", data, 0x3A)

    def hdr(i):                       # name, type, flags, addr, offset, size
        return struct.unpack_from("<IIQQQQ", data, e_shoff + i * es)

    stro = hdr(strn)[4]

    def name_at(idx):
        end = data.index(b"\0", stro + idx)
        return data[stro + idx:end].decode()

    return [(name_at(hdr(i)[0]), *hdr(i)[1:]) for i in range(n)]


def _symbols(data: bytes) -> list[dict]:
    """symtab 里的函数符号：`{name, value, size, shndx}`。"""
    hs = _headers(data)
    out = []
    for name, s_type, _fl, _a, off, size in hs:
        if s_type != _SHT_SYMTAB:
            continue
        strtab = None
        for i, h in enumerate(hs):                      # sh_link 指向 .strtab
            if h[0] == ".strtab":
                strtab = h[4]
        for pos in range(off, off + size, 24):
            st_name, st_info, _other, shndx, value, sz = struct.unpack_from(
                "<IBBHQQ", data, pos)
            if (st_info & 0xF) != _STT_FUNC:
                continue
            nm = ""
            if strtab is not None:
                end = data.index(b"\0", strtab + st_name)
                nm = data[strtab + st_name:end].decode()
            out.append({"name": nm, "value": value, "size": sz, "shndx": shndx})
    return out


def section_of(data: bytes, file_off: int) -> tuple[int, str, int, int]:
    """含这个文件偏移的可执行段：`(索引, 名字, sh_offset, sh_size)`。"""
    for i, (name, _t, flags, _a, off, size) in enumerate(_headers(data)):
        if flags & 0x4 and off <= file_off < off + size:      # SHF_EXECINSTR
            return i, name, off, size
    raise ReflowError(f"文件偏移 {file_off:#x} 不在任何可执行段里")


def window_end(data: bytes, sec_idx: int, sec_size: int, addr: int) -> int:
    """挪动窗口的末端：下一个函数的起点，没有就是段末。

    窗口不许跨函数边界 —— 跨了就要改符号的 `st_value`/`st_size` 和
    `.debug_frame` 的重定位加数，那是另一个量级的事（本文件开头）。
    """
    starts = sorted({s["value"] for s in _symbols(data)
                     if s["shndx"] == sec_idx and s["value"] > addr})
    return starts[0] if starts else sec_size


# --- 地址映射 ---------------------------------------------------------------

class Shift:
    """一次挪动：窗口 `[start, end)` 里的指令整体挪 `delta`（±16）。

    `insert`：`[start, end-16)` 的每条 +16，`end-16` 那条（必须是 NOP）被吃掉。
    `delete`：`start` 那条被删掉，`(start, end)` 的每条 -16，`end-16` 补 NOP。
    """

    def __init__(self, start: int, end: int, delta: int) -> None:
        self.start, self.end, self.delta = start, end, delta

    @property
    def dropped(self) -> int:
        """被吃掉/被删掉的那条指令的**旧**地址。"""
        return self.end - INST if self.delta > 0 else self.start

    def moved(self) -> range:
        """真正挪了位置的旧地址（不含被吃掉那条）。"""
        return (range(self.start, self.end - INST, INST) if self.delta > 0
                else range(self.start + INST, self.end, INST))

    def map(self, addr: int) -> int | None:
        """旧地址 -> 新地址。被吃掉的那条返回 None。"""
        if addr == self.dropped:
            return None
        return addr + self.delta if addr in self.moved() else addr


# --- 分支重定位 -------------------------------------------------------------

def _fact(key: str):
    from nvisa.model.asm_spec import pc_offset_fact
    return pc_offset_fact(key)


def relocate_branches(encs: dict[int, str], shift: Shift,
                      texts: dict[int, str]) -> tuple[dict[int, str], list[dict]]:
    """把整段的分支目标过一遍地址映射。返回 `(改过的编码, 改动清单)`。

    `encs`/`texts` 是**旧**地址上的编码与单条反汇编文本（文本只用来判 `.ABS`
    和认出 `BRX` 这类间接跳转）。`.ABS` 的目标是绝对地址，不跟本指令地址走，
    所以只在目标自己挪了位置时才改。
    """
    from cubin_sass import identify
    from nvisa.model import asm_spec

    out, log = {}, []
    for addr, enc in encs.items():
        key = identify(enc)
        text = texts.get(addr) or ""
        mn = (text.split()[1] if text.startswith("@") else text.split()[0]) \
            if text.split() else ""
        base_mn = mn.split(".")[0]
        if base_mn in ("BRX", "BRXU", "JMX", "JMXU"):
            raise ReflowError(
                f"{addr:#x} 是 {mn} —— 间接跳转的目标在常量表里，不在指令身上，"
                f"挪了位置修不了；插入/删除不碰这种段")
        fact = _fact(key) if key else None
        if not fact:
            if base_mn in ("BRA", "CALL", "RET", "JMP", "BSSY", "SSY"):
                if base_mn in ("BSSY", "SSY") or "`" in text or "0x" in text:
                    raise ReflowError(
                        f"{addr:#x} 的 {mn}（key {key}）段表里没有偏移规则，"
                        f"挪了位置改不了它的目标")
            continue
        absolute = ".ABS" in text.upper()
        new_addr = shift.map(addr)
        if new_addr is None:
            continue                                  # 这条本身就被吃掉了
        old_off = asm_spec.read_offset(fact, enc)
        old_target = old_off if absolute else addr + INST + old_off
        new_target = shift.map(old_target)
        if new_target is None:
            raise ReflowError(
                f"{addr:#x} 的 {mn} 指向 {old_target:#x} —— 那条指令正好是这次"
                f"要吃掉/删掉的，目标没了")
        new_off = new_target if absolute else new_target - new_addr - INST
        if new_off == old_off:
            continue
        out[addr] = asm_spec.write_offset(fact, enc, new_off)
        log.append({"addr": addr, "new_addr": new_addr, "mnemonic": mn,
                    "target": old_target, "new_target": new_target})
    return out, log


# --- .nv.info 里的指令偏移 ---------------------------------------------------

def relocate_nvinfo(data: bytearray, sec_idx: int, shift: Shift,
                    force: bool = False) -> tuple[list[dict], list[dict]]:
    """改 `.nv.info*` 里记着指令偏移的属性。返回 `(改动清单, 存疑清单)`。

    偏移相对这一节名字所指的那个函数的起点，所以先把它换算成段内地址再过映射。
    认不出的属性（`OFFSET_ATTRS` 之外）里若出现了「16 对齐、正好等于某条挪动过
    的指令」的字，就当成可能的指令偏移**拒绝**（`force=True` 才照打）——宁可
    多问一句，也别把一个指向别处的偏移悄悄留在文件里。
    """
    syms = {s["name"]: s for s in _symbols(bytes(data)) if s["shndx"] == sec_idx}
    changed, suspect = [], []
    for name, _t, _fl, _a, off, size in _headers(bytes(data)):
        if not name.startswith(".nv.info"):
            continue
        fn = name[len(".nv.info."):] if name.startswith(".nv.info.") else ""
        base = syms[fn]["value"] if fn in syms else 0
        pos, end = off, off + size
        while pos + 4 <= end:
            fmt, attr, plen = struct.unpack_from("<BBH", data, pos)
            if fmt != _EIFMT_SVAL:
                pos += 4
                continue
            body, n = pos + 4, plen // 4
            for i in range(n):
                word, = struct.unpack_from("<I", data, body + i * 4)
                addr = base + word
                if attr in OFFSET_ATTRS:
                    new = shift.map(addr)
                    if new is None:
                        raise ReflowError(
                            f"{OFFSET_ATTRS[attr]} 记着 {addr:#x} 上那条指令，"
                            f"而这次正好要吃掉/删掉它")
                    if new != addr:
                        struct.pack_into("<I", data, body + i * 4, new - base)
                        changed.append({"attr": OFFSET_ATTRS[attr],
                                        "was": word, "now": new - base})
                elif word % INST == 0 and addr in shift.moved():
                    suspect.append({"attr": f"0x{attr:02x}", "section": name,
                                    "word": word})
            pos += 4 + plen
    if suspect and not force:
        raise ReflowError(
            "`.nv.info` 里有认不出的属性，值看着像挪动过的指令偏移："
            + "、".join(f"{s['attr']}@{s['section']} = {s['word']:#x}"
                        for s in suspect)
            + "。确认无关就用 force 跳过。")
    return changed, suspect
