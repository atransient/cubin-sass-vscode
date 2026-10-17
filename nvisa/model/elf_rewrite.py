"""变长 `.text` 与 cubin 打包。

输入是「基底 cubin、目标 section、源码汇编生成的新指令字节、旧地址 → 新地址映射」，
输出新的 cubin bytes。定长插入/删除（`reflow`：在函数体内挪窗口、吃尾部 `NOP`）是快速
路径，条数一变就得走这里：段大了/小了，后面每个 section 的文件偏移、section
header table、program header table、符号的 `st_value`/`st_size`、RELA 的 addend、
`.nv.info` 里记的指令偏移，全都要跟着改。

## 只做一种 ELF

ELF64 little-endian、`EM_CUDA`(190)、`e_flags` 低字节 = 90（sm_90）。section 的
**数量、名字、索引全部保留**，首版不支持新增/删除 section —— 布局问题因此被限制
在「同一批 section 换一组偏移」这个可验范围内。

## 三条不肯猜的规矩

1. **segment 归属按基底的 containment 关系定**，不按新偏移猜：一个 section 属于
   哪个 program header，是它在**基底里**落在谁的 `[p_offset, p_offset+p_filesz)`
   里决定的。新布局照着这份归属重算 `p_offset`/`p_filesz`/`p_memsz`。一个
   section 同时落进两个 `PT_LOAD`、或者新偏移满足不了 `p_align` 的同余约束，
   都明确拒绝。
2. **`.nv.info` 未知属性一个字节不动**；但它的 payload 里若出现「16 对齐、正好
   等于某条挪动过的指令」的字，默认**拒绝**变长 —— 不打印 warning 然后接着写。
   已知的指令偏移属性（`reflow.OFFSET_ATTRS`）按映射改。
3. **常量 bank 引用不是地址**：`c[0x0][0x28]` 里的数值属于常量段，不因代码扩容
   平移。这里只动明确是「本 section 内指令地址」的字段。

## 调试信息

手写 SASS 之后，原来的 CUDA 源级行号已经失真 —— 这一点不掩盖。处置由
`debug_policy` 定：每个调试 section 必须显式落到 `preserve` / `strip` / `rewrite`
之一，决策和理由逐条进报告（`Report.debug_decisions`）。`.debug_frame` 是唯一有
parser + 回归测试、因而能 `rewrite` 的格式；行号类和 `.nv.debug*` 只能 preserve
（要有 proof）或 strip（连带清空关联 RELA）。`strip_debug=True` 仍然可用，它等价于
`DebugRequest.from_legacy(True)`。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from nvisa.model.debug_policy import (REWRITE, STRIP, DebugPolicyError,
                                      DebugRequest, Decision, classify)
from nvisa.model.debug_policy import plan as plan_debug
from nvisa.model.reflow import INST, OFFSET_ATTRS, _EIFMT_SVAL

_EM_CUDA = 190
_SHT_NULL, _SHT_PROGBITS, _SHT_SYMTAB, _SHT_STRTAB = 0, 1, 2, 3
_SHT_RELA, _SHT_NOBITS = 4, 8
_PT_PHDR = 6
_PT_LOAD = 1
#: `.nv.info` 里**确定不是指令偏移**的属性。名字是拿 `cuobjdump -elf` 的输出与
#: 原始字节逐条对位认出来的（语料里出现过的全在这儿）：payload 记的是寄存器数、
#: 栈帧大小、参数布局、常量 bank 引用这些，跟代码挪不挪一点关系没有。
#: 白名单之外、又不在 `reflow.OFFSET_ATTRS` 里的，只要 payload 看着像挪过的
#: 指令地址就**硬拒绝** —— 宁可多问一句。
NON_OFFSET_ATTRS = {
    0x0A: "EIATTR_PARAM_CBANK",       # 常量 bank 引用：不是后续指令地址
    0x11: "EIATTR_FRAME_SIZE",        # 栈帧字节数（localmem 里正好 0xc0，撞过）
    0x12: "EIATTR_MIN_STACK_SIZE",
    0x17: "EIATTR_KPARAM_INFO",
    0x19: "EIATTR_CBANK_PARAM_SIZE",
    0x1E: "EIATTR_CRS_STACK_SIZE",
    0x2F: "EIATTR_REGCOUNT",
    0x36: "EIATTR_SW_WAR",
    0x37: "EIATTR_CUDA_API_VERSION",
}

#: 行号类调试信息：手写 SASS 之后证明不了还对。
_LINE_DEBUG = (".debug_line", ".debug_info", ".debug_abbrev", ".debug_str",
               ".debug_pubnames", ".debug_ranges", ".nv.debug")


class RewriteError(ValueError):
    pass


@dataclass
class Shdr:
    idx: int
    name: str
    name_off: int
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int

    @property
    def in_file(self) -> bool:
        return self.type not in (_SHT_NULL, _SHT_NOBITS)


@dataclass
class Report:
    """一次打包做了什么 —— 调用方要把它讲给用户听。"""
    section: str
    old_size: int
    new_size: int
    moved_sections: list[str] = field(default_factory=list)
    symbols: list[dict] = field(default_factory=list)
    relas: list[dict] = field(default_factory=list)
    nvinfo: list[dict] = field(default_factory=list)
    debug: list[str] = field(default_factory=list)
    #: 每个调试 section 的策略决策（`debug_policy.Decision`）。
    debug_decisions: list[Decision] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# --- 读 ---------------------------------------------------------------------

def _check(data: bytes) -> tuple[int, int, int, int, int, int]:
    """校验并返回 `(e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum)`。"""
    if data[:4] != b"\x7fELF":
        raise RewriteError("不是 ELF")
    if data[4] != 2 or data[5] != 1:
        raise RewriteError("只支持 ELF64 little-endian")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_machine != _EM_CUDA:
        raise RewriteError(f"e_machine={e_machine}，不是 EM_CUDA({_EM_CUDA})")
    (_v, _entry, e_phoff, e_shoff, e_flags, _eh,
     e_phentsize, e_phnum, e_shentsize, e_shnum, _stridx) = struct.unpack_from(
        "<IQQQIHHHHHH", data, 20)
    if (e_flags & 0xFF) != 90:
        raise RewriteError(f"e_flags 低字节 = {e_flags & 0xFF}，不是 sm_90")
    return e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum


def _sections(data: bytes) -> list[Shdr]:
    _ph, e_shoff, _pe, _pn, es, n = _check(data)
    _t, _m = struct.unpack_from("<HH", data, 16)
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * es) for i in range(n)]
    stro = raw[shstrndx][4]

    def name_at(off: int) -> str:
        end = data.index(b"\0", stro + off)
        return data[stro + off:end].decode()

    return [Shdr(i, name_at(r[0]), r[0], r[1], r[2], r[3], r[4], r[5],
                 r[6], r[7], r[8], r[9]) for i, r in enumerate(raw)]


def _phdrs(data: bytes) -> list[list[int]]:
    e_phoff, _sh, es, n, _se, _sn = _check(data)
    return [list(struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * es))
            for i in range(n)]


# --- 布局 -------------------------------------------------------------------

def _align_up(v: int, a: int) -> int:
    return v if a <= 1 else (v + a - 1) // a * a


def _relayout(secs: list[Shdr], target: int, new_size: int,
              rep: Report) -> dict[int, int]:
    """按基底的文件顺序排新偏移，返回 `{索引: 新偏移}`。

    **最小改动**：目标 section 之前的一个字节都不挪，目标之后的整体平移
    `new_size - old_size`，再按各自的 `sh_addralign` 抬到对齐位置（对齐不够时
    多补几个字节，只多不少）。不做「重新紧凑排布」—— 基底里的空隙是 ptxas 留
    的，压掉它等于改了一堆与本次编辑无关的偏移，也就没法把「文件为什么变了」
    讲清楚。

    NOBITS 不占文件字节，只跟着邻居走一个位置，不推进游标。
    """
    order = sorted((s for s in secs if s.idx), key=lambda s: (s.offset, s.idx))
    tgt = next(s for s in order if s.idx == target)
    out, shift, cursor = {0: 0}, 0, 0
    for s in order:
        if s.offset < tgt.offset or s.idx == target:
            out[s.idx] = s.offset                       # 目标及其之前：一位不动
            if s.idx == target:
                shift = new_size - s.size               # 后面的整体平移这么多
            if s.in_file:
                cursor = s.offset + (new_size if s.idx == target else s.size)
            continue
        pos = _align_up(max(s.offset + shift, cursor if s.in_file else 0),
                        s.align or 1)
        out[s.idx] = pos
        shift = pos - s.offset
        if s.in_file:
            cursor = pos + s.size
            if pos != s.offset:
                rep.moved_sections.append(s.name)
    return out


def _segment_members(secs: list[Shdr], ph: list[int]) -> tuple[list[Shdr], list[Shdr]]:
    """这个 program header 在**基底**里装着哪些 section（containment，不是猜）。

    返回 `(占文件字节的, NOBITS 的)`。NOBITS 不占文件，但 `p_offset` 仍要跟着它
    走 —— cubin 里的 `.nv.shared.reserved.0` 就是一个 `p_filesz=0` 的段，只按
    file-backed 找成员会把它判成「不装任何 section」。
    """
    lo, hi = ph[2], ph[2] + max(ph[5], ph[6])
    inf, nob = [], []
    for s in secs:
        if not s.idx:
            continue
        if not s.in_file:
            if lo <= s.offset <= hi:
                nob.append(s)
        elif lo <= s.offset and s.offset + s.size <= ph[2] + ph[5]:
            inf.append(s)
    return inf, nob


# --- 各类引用的更新 ---------------------------------------------------------

def _map_addr(amap: dict[int, int], addr: int, what: str) -> int:
    if addr not in amap:
        raise RewriteError(
            f"{what} 指着旧地址 {addr:#x}，新布局里没有这条指令（被删了，"
            f"或那一行是手敲的、没有原地址注释）—— 不猜，直接拒绝")
    return amap[addr]


def _update_symbols(data: bytearray, secs: list[Shdr], target: int,
                    amap: dict[int, int], rep: Report) -> None:
    """目标 section 里符号的 `st_value`/`st_size`。

    `st_size` 按**映射后的两端**算（`map(起点+长度) - map(起点)`），不是「到下一个
    符号」—— cubin 里 kernel 符号会把整个 device function 包在里面，两者嵌套。
    """
    for sh in secs:
        if sh.type != _SHT_SYMTAB:
            continue
        for pos in range(sh.offset, sh.offset + sh.size, 24):
            st_name, st_info, other, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", data, pos)
            if shndx != target:
                continue
            new_value = _map_addr(amap, value, f"符号 st_value={value:#x}")
            new_end = _map_addr(amap, value + size,
                                f"符号 st_value+st_size={value + size:#x}")
            if (new_value, new_end - new_value) == (value, size):
                continue
            struct.pack_into("<IBBHQQ", data, pos, st_name, st_info, other,
                             shndx, new_value, new_end - new_value)
            rep.symbols.append({"st_value": [value, new_value],
                                "st_size": [size, new_end - new_value]})


def _sym_section(data: bytes, secs: list[Shdr], symtab: Shdr, idx: int) -> int:
    pos = symtab.offset + idx * 24
    return struct.unpack_from("<H", data, pos + 6)[0]


def _update_relas(data: bytearray, secs: list[Shdr], target: int,
                  amap: dict[int, int], rep: Report) -> None:
    """RELA：指向目标 section 的 `r_offset` 与 addend 都要过映射。

    addend 只有在**这条重定位确实指向目标 section**（符号的 `st_shndx` 就是它）
    时才动 —— 常量 bank 里的数值、别的 section 的偏移都不是指令地址，盲目平移
    就是「因代码扩容盲目平移」的错。
    """
    symtabs = [s for s in secs if s.type == _SHT_SYMTAB]
    for sh in secs:
        if sh.type != _SHT_RELA:
            continue
        symtab = next((s for s in symtabs if s.idx == sh.link), None)
        for pos in range(sh.offset, sh.offset + sh.size, 24):
            r_offset, r_info, addend = struct.unpack_from("<QQq", data, pos)
            new_off, new_add = r_offset, addend
            if sh.info == target:                      # 重定位落在目标段身上
                new_off = _map_addr(amap, r_offset, f"RELA r_offset={r_offset:#x}")
            sym = r_info >> 32
            if symtab is not None and _sym_section(data, secs, symtab, sym) == target:
                new_add = _map_addr(amap, addend, f"RELA addend={addend:#x}")
            if (new_off, new_add) == (r_offset, addend):
                continue
            struct.pack_into("<QQq", data, pos, new_off, r_info, new_add)
            rep.relas.append({"section": sh.name,
                              "r_offset": [r_offset, new_off],
                              "addend": [addend, new_add]})


def _update_nvinfo(data: bytearray, secs: list[Shdr], target: int,
                   amap: dict[int, int], sym_base: dict[str, tuple[int, int]],
                   force: bool, rep: Report) -> None:
    """`.nv.info*` 里记指令偏移的属性。规矩同定长插入/删除（`reflow.relocate_nvinfo`）。

    偏移相对**这一节名字所指的那个函数**的起点，而这里函数起点自己也可能挪了，
    所以换算要用「旧起点解出旧地址、映射到新地址、再减新起点」。
    """
    suspect = []
    for sh in secs:
        if not sh.name.startswith(".nv.info"):
            continue
        fn = sh.name[len(".nv.info."):] if sh.name.startswith(".nv.info.") else ""
        old_base, new_base = sym_base.get(fn, (0, 0))
        pos, end = sh.offset, sh.offset + sh.size
        while pos + 4 <= end:
            fmt, attr, plen = struct.unpack_from("<BBH", data, pos)
            if fmt != _EIFMT_SVAL:
                pos += 4
                continue
            body = pos + 4
            for i in range(plen // 4):
                word, = struct.unpack_from("<I", data, body + i * 4)
                addr = old_base + word
                if attr in OFFSET_ATTRS:
                    new = _map_addr(amap, addr, OFFSET_ATTRS[attr]) - new_base
                    if new != word:
                        struct.pack_into("<I", data, body + i * 4, new)
                        rep.nvinfo.append({"attr": OFFSET_ATTRS[attr],
                                           "was": word, "now": new})
                elif (attr not in NON_OFFSET_ATTRS and word % INST == 0
                      and addr in amap and amap[addr] != addr):
                    suspect.append(f"0x{attr:02x}@{sh.name}={word:#x}")
            pos += 4 + plen
    if suspect and not force:
        raise RewriteError(
            "`.nv.info` 里有认不出的属性，值看着像挪动过的指令偏移："
            + "、".join(suspect) + "。确认无关再用 force。")
    rep.warnings += [f"未知 .nv.info 属性按原样保留：{s}" for s in suspect]


def _debug_inventory(data: bytes, secs: list[Shdr], target: int) -> list[dict]:
    """每个调试 section 的事实：关联 RELA、其中的重定位类型、是否引用被改 section。

    `touches_target` 是 `preserve` 那条 proof 的依据，所以它按**实际的重定位符号**
    算：RELA 的符号落在被改 section 上，就是「引用了被改范围」。`.debug_frame`
    另外还有一层 —— 它的 FDE `address_range` 就是函数长度，函数在被改 section 里，
    因此只要基底里有指向该段的 FDE 重定位就算引用。
    """
    symtabs = [s for s in secs if s.type == _SHT_SYMTAB]

    def sym_shndx(tab: Shdr, i: int) -> int:
        return struct.unpack_from("<H", data, tab.offset + i * 24 + 6)[0]

    out = []
    for sh in secs:
        if classify(sh.name) is None:
            continue
        relas, types, touches = [], set(), False
        for rs in secs:
            if rs.type != _SHT_RELA or rs.info != sh.idx:
                continue
            relas.append(rs.name)
            tab = next((s for s in symtabs if s.idx == rs.link), None)
            for pos in range(rs.offset, rs.offset + rs.size, 24):
                _off, r_info, _add = struct.unpack_from("<QQq", data, pos)
                types.add(r_info & 0xFFFFFFFF)
                if tab is not None and sym_shndx(tab, r_info >> 32) == target:
                    touches = True
        out.append({"name": sh.name, "idx": sh.idx, "rela": relas,
                    "rela_types": types, "touches_target": touches})
    return out


def _apply_debug(data: bytearray, secs: list[Shdr],
                 decisions: list[Decision], amap: dict[int, int],
                 sym_base: dict[str, tuple[int, int, int, int]],
                 rep: Report) -> set[int]:
    """执行调试策略的决策，返回「要清空」的 section 索引集合（含关联 RELA）。"""
    by_name = {s.name: s for s in secs}
    stripped: set[int] = set()
    for d in decisions:
        rep.debug_decisions.append(d)
        rep.debug.append(d.line)
        if d.policy == STRIP:
            stripped.add(by_name[d.section].idx)
            # 关联 RELA 一起清：留着等于留下一批指向空段的加数。
            stripped.update(by_name[n].idx for n in d.relocations)
        elif d.policy == REWRITE:
            _update_debug_frame(data, by_name[d.section], amap, sym_base, rep)
    return stripped


def _update_debug_frame(data: bytearray, sh: Shdr, amap: dict[int, int],
                        sym_base: dict[str, tuple[int, int]], rep: Report) -> None:
    """DWARF CFI：把每条 FDE 的 `address_range` 换成映射后的函数长度。

    cubin 里这一节用的是 **DWARF64**：长度字段前面有 `0xffffffff` 转义、后面跟
    8 字节长度，CIE 标记也是 8 字节的全 1。FDE 的载荷是
    `CIE_pointer(8) | initial_location(8) | address_range(8)`；`initial_location`
    由 RELA 填（文件里是 0），`address_range` 就是**函数字节数** —— 这个值本项目
    自己算得出来，所以可以更新，不是「假装还有效」。

    对不上任何已知函数长度的 FDE 不动，并如实写进报告。行号信息不在这里，
    那类 section 由 `_update_debug()` 拒绝或剥离。
    """
    lens = {old_size: new_size
            for _old_start, _new_start, old_size, new_size in sym_base.values()}
    pos, end = sh.offset, sh.offset + sh.size
    touched, skipped = 0, 0
    while pos + 4 <= end:
        l32, = struct.unpack_from("<I", data, pos)
        if l32 == 0xFFFFFFFF:                       # DWARF64
            length, = struct.unpack_from("<Q", data, pos + 4)
            body, idw = pos + 12, 8
        else:
            length, body, idw = l32, pos + 4, 4
        if not length or body + length > end:
            break
        cie_id, = struct.unpack_from("<Q" if idw == 8 else "<I", data, body)
        is_cie = cie_id == (0xFFFFFFFFFFFFFFFF if idw == 8 else 0xFFFFFFFF)
        if not is_cie and length >= idw + 16:
            rng_at = body + idw + 8
            rng, = struct.unpack_from("<Q", data, rng_at)
            if rng in lens and lens[rng] != rng:
                struct.pack_into("<Q", data, rng_at, lens[rng])
                touched += 1
            elif rng not in lens:
                skipped += 1
        pos = body + length
    if skipped:
        rep.debug.append(f".debug_frame：{skipped} 条 FDE 的 address_range 对不上"
                         f"任何已知函数长度，原样保留")
    rep.debug.append(f".debug_frame：{touched} 条 FDE 的 address_range 已更新"
                     if touched else
                     ".debug_frame：没有需要改的 address_range（函数长度没变）")


# --- 主流程 -----------------------------------------------------------------

def rewrite(base: bytes, section: str, new_bytes: bytes,
            addr_map: dict[int, int],
            *, force: bool = False,
            strip_debug: bool = False,
            debug: DebugRequest | None = None) -> tuple[bytes, Report]:
    """把 `new_bytes` 装进 `section`，输出新的 cubin。

    `addr_map` 是「旧段内地址 -> 新段内地址」，来自源码汇编（每行行尾的 `// @0x…`
    原地址注释）。段末那个边界地址也要在表里 —— 符号的 `st_value + st_size`、
    跳到段尾的分支都用它。
    """
    if len(new_bytes) % INST:
        raise RewriteError(f"新段长度 {len(new_bytes)} 不是 {INST} 的倍数")
    if debug is not None and strip_debug:
        raise RewriteError(
            "同时给了 debug=DebugRequest(...) 和 strip_debug=True —— "
            "两种写法说的是同一件事，只留一种，免得报告说不清是谁做的决定")
    request = debug if debug is not None else DebugRequest.from_legacy(strip_debug)
    secs = _sections(base)
    tgt = next((s for s in secs if s.name == section), None)
    if tgt is None:
        raise RewriteError(f"没有 section {section}")
    if not tgt.in_file:
        raise RewriteError(f"{section} 不占文件字节，改不了")
    rep = Report(section=section, old_size=tgt.size, new_size=len(new_bytes))
    if tgt.align and len(new_bytes) % tgt.align:
        rep.warnings.append(
            f"新段长度 {len(new_bytes)} 不是 sh_addralign({tgt.align}) 的倍数 —— "
            f"ptxas 一向把 .text 填 NOP 补齐到这个粒度，建议保留尾部填充")

    data = bytearray(base)
    # 符号表先读旧值：`.nv.info`/`.debug_frame` 的换算要用「旧起点/新起点」。
    sym_base: dict[str, tuple[int, int, int, int]] = {}
    for sh in secs:
        if sh.type != _SHT_SYMTAB:
            continue
        strtab = next((s for s in secs if s.idx == sh.link), None)
        for pos in range(sh.offset, sh.offset + sh.size, 24):
            st_name, _info, _o, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", data, pos)
            if shndx != tgt.idx or strtab is None:
                continue
            end = base.index(b"\0", strtab.offset + st_name)
            nm = base[strtab.offset + st_name:end].decode()
            if value in addr_map and value + size in addr_map:
                sym_base[nm] = (value, addr_map[value], size,
                                addr_map[value + size] - addr_map[value])

    _update_nvinfo(data, secs, tgt.idx, addr_map,
                   {k: (v[0], v[1]) for k, v in sym_base.items()}, force, rep)
    _update_relas(data, secs, tgt.idx, addr_map, rep)
    _update_symbols(data, secs, tgt.idx, addr_map, rep)
    layout_changed = (len(new_bytes) != tgt.size
                      or any(k != v for k, v in addr_map.items()))
    try:
        decisions = plan_debug(_debug_inventory(base, secs, tgt.idx),
                               request=request, layout_changed=layout_changed)
    except DebugPolicyError as e:
        raise RewriteError(str(e)) from e
    stripped = _apply_debug(data, secs, decisions, addr_map, sym_base, rep)

    # 新布局：先算偏移，再把每个 section 的字节按新偏移摆进去。
    new_off = _relayout(secs, tgt.idx, len(new_bytes), rep)
    sizes = {s.idx: (len(new_bytes) if s.idx == tgt.idx else
                     (0 if s.idx in stripped else s.size)) for s in secs}
    tail = max((new_off[s.idx] + sizes[s.idx] for s in secs if s.in_file),
               default=0x40)
    # SHT / PHT 的先后顺序照抄基底 —— 不重新发明文件尾的排法。
    e_phoff, e_shoff, phes, phn, shes, shn = _check(base)
    sht_first = e_shoff <= e_phoff
    a_sz, b_sz = ((shn * shes, phn * phes) if sht_first else (phn * phes, shn * shes))
    a_off = _align_up(tail, 8)
    b_off = _align_up(a_off + a_sz, 8)
    new_shoff, new_phoff = (a_off, b_off) if sht_first else (b_off, a_off)

    out = bytearray(b_off + b_sz)
    out[:0x40] = data[:0x40]
    for s in secs:
        if not s.in_file or not sizes[s.idx]:
            continue
        src = (new_bytes if s.idx == tgt.idx
               else data[s.offset:s.offset + s.size])
        out[new_off[s.idx]:new_off[s.idx] + sizes[s.idx]] = src

    # program header：归属按基底的 containment 算，新范围由成员的新偏移定。
    phs = _phdrs(base)
    seen: dict[int, int] = {}
    for i, ph in enumerate(phs):
        members, nobits = _segment_members(secs, ph)
        if not members and not nobits:
            if ph[2] == e_phoff and ph[5] == phn * phes:
                ph[2], ph[5], ph[6] = new_phoff, phn * phes, phn * phes
            elif ph[2] == e_shoff and ph[5] == shn * shes:
                ph[2], ph[5], ph[6] = new_shoff, shn * shes, shn * shes
            else:
                raise RewriteError(
                    f"program header #{i} 在基底里不装任何 section，也不是"
                    f"表头本身（off={ph[2]:#x} filesz={ph[5]:#x}）—— 认不出来就不动它")
        elif not members:                          # 只有 NOBITS：文件里不占字节
            ph[2] = min(new_off[m.idx] for m in nobits)
            ph[5] = 0
        else:
            if ph[0] == _PT_LOAD:
                for m in members:
                    if m.idx in seen and seen[m.idx] != i:
                        raise RewriteError(
                            f"{m.name} 同时落在两个 PT_LOAD（#{seen[m.idx]}、#{i}）里，"
                            f"新布局没法同时满足，拒绝")
                    seen[m.idx] = i
            lo = min(new_off[m.idx] for m in members)
            hi = max(new_off[m.idx] + sizes[m.idx] for m in members)
            grow = ph[6] - ph[5]                       # 基底里 memsz 多出来的部分
            ph[2], ph[5], ph[6] = lo, hi - lo, hi - lo + grow
        if ph[7] and (ph[2] - ph[3]) % ph[7]:
            raise RewriteError(
                f"program header #{i} 的 p_offset({ph[2]:#x}) 与 "
                f"p_vaddr({ph[3]:#x}) 不满足 p_align({ph[7]:#x}) 的同余约束")
        struct.pack_into("<IIQQQQQQ", out, new_phoff + i * phes, *ph)

    # section header table
    for s in secs:
        struct.pack_into("<IIQQQQIIQQ", out, new_shoff + s.idx * shes,
                         s.name_off, s.type, s.flags, s.addr,
                         new_off[s.idx] if s.idx else 0, sizes.get(s.idx, s.size),
                         s.link, s.info, s.align, s.entsize)
    struct.pack_into("<Q", out, 0x28, new_shoff)
    struct.pack_into("<Q", out, 0x20, new_phoff)
    return bytes(out), rep
