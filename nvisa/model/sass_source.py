"""`.nvsass` 源码格式。

源码模式是一份**真正的文本 document**：撤销/重做、搜索、多光标、行号、
诊断都沿用编辑器自己的实现。这个模块负责把基底 cubin 的单个或全部 `.text.*`
section 导成源码文本，也就是 `--emit-source`；反方向（整段两遍汇编、变长写回）
在 `sass_asm` / `elf_rewrite`，这里不做。

格式（本项目自己定，参考已有工具的惯例）：

    .arch sm_90
    .section .text._Z10fma_kernelPfS_S_
    .base <cubin 内容的 sha256 前 16 位>      // 保存时用来发现基底被外部改过
    .regcount 16                               // __global__ 的 EIATTR_REGCOUNT

    .L_0000:                                  // 只在真有人跳到这里时才出现
    [B------:R-:W1:-:S01] FFMA R9, R2.reuse, R5, R9;
    [B------:R-:W-:-:S01] @P0 BRA .L_0000;
    [B------:R-:W-:Y:S00] EXIT;

**控制码属于源码行**：`[B...:R.:W.:Y/-:S..]` 是把这条指令现有的 bits 105:121
解码出来的，reuse 继续按 nvdisasm 的写法留在操作数上（bits 122:124）。移动/复制
一行时控制码跟着这一行走，删一行就一起删 —— 这正是源码模式不允许「按原地址继承
基底控制码」的原因。

**分支目标写成标号**：段内的 PC 相对目标（段表的 `slot_facts`）导出成
`.L_<段内地址>`，跳出段外或间接跳转保持 nvdisasm 打印的数值。标号让插删指令后
「跳转还指向同一条指令」这件事在源码层面就是成立的，不依赖任何重定位。

**已知不保真的一处**：`.reuse` 只有在 `yield=1 且 stall>=1` 时 nvdisasm 才打印
（见 `cubin_sass.probe_reuse_bits` 的实测注释）。基底里存在「reuse 位是 1 但不
会被打印」的指令时，这里不静悄悄丢掉，而是在行尾留一条 `// !! reuse=...` 注释并
计入 `warnings`，由调用方决定要不要拒绝。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from nvisa.model import asm_spec
from nvisa.model.reflow import _headers, _symbols
from nvisa.model.sass_parser import format_ctrl
from nvisa.oracle.cubin import get_bits

#: 控制段字段的位置，与 `asm.FIELDS` 同源。
_CTRL_BITS = {"stall": (105, 108), "yield": (109, 109), "wr": (110, 112),
              "rd_bar": (113, 115), "wait": (116, 121), "reuse": (122, 124)}
_INST_BYTES = 16
#: 行尾的跳转目标：数值（`BRA 0x70`）或 nvdisasm 的符号标号（`` `(.L_x_0) ``）。
_TAIL_TARGET = re.compile(r"(`\([^)]*\)|-?0x[0-9a-fA-F]+|-?\d+)\s*$")


class SourceError(ValueError):
    """导出失败。`sections` 非空时是「有多个 section，得让用户挑一个」——
    调用方（CLI/扩展）据此弹选择框，而不是去解析错误文本。"""

    def __init__(self, msg: str, sections: list[str] | None = None):
        super().__init__(msg)
        self.sections = sections or []


@dataclass
class SourceFile:
    text: str
    section: str
    base_hash: str
    labels: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SourceBundle:
    """A single editable source document containing every executable section."""

    text: str
    sections: list[str]
    base_hash: str
    warnings: list[str] = field(default_factory=list)


# Virtual documents use this as their binding key.  It is deliberately not a
# valid ELF section name, so it cannot collide with a real kernel.
ALL_TEXT_SECTIONS = "__all_text_sections__"
BUNDLE_MARKER = "// nvsass: all-text-sections"


_SECTION_DIRECTIVE = re.compile(r"^\s*\.section\s+(\S+)\s*(?://.*)?$")


def source_section_names(text: str) -> list[str]:
    """Return source section directives in order, without guessing ownership."""
    return [m.group(1) for line in text.splitlines()
            if (m := _SECTION_DIRECTIVE.match(line))]


def is_source_bundle(text: str) -> bool:
    return any(line.strip() == BUNDLE_MARKER for line in text.splitlines())


def _section_index(data: bytes, name: str) -> int | None:
    for i, h in enumerate(_headers(data)):
        if h[0] == name:
            return i
    return None


def base_hash(data: bytes) -> str:
    """基底 cubin 的内容指纹 —— document 绑定「hash + section 集合」。"""
    return hashlib.sha256(data).hexdigest()[:16]


def label_for(addr: int) -> str:
    return f".L_{addr:04x}"


def ctrl_prefix(enc: str) -> str:
    """一条编码的 bits 105:121 -> `[B------:R-:W-:-:S01]`。"""
    g = {k: get_bits(enc, *v) for k, v in _CTRL_BITS.items()}
    return format_ctrl(g["wait"], g["rd_bar"], g["wr"], g["yield"], g["stall"])


def _branch_target(key: str | None, text: str, enc: str, addr: int) -> int | None:
    """段内 PC 相对目标的绝对地址；不是分支或是 `.ABS` 返回 None。

    偏移**从编码里读**（段表的 `slot_facts`），不从文本读：整段反汇编时 nvdisasm
    把目标印成它自己的标号（`` `(.L_x_0) ``），文本里根本没有地址。`.ABS` 的目标
    不是段内地址（`CALL.ABS` 指向别的段），导出成段内标号会撒谎。
    """
    # ``identify`` and the nvdisasm text are independent evidence.  A
    # PC-relative target is safe to decode only when their mnemonics agree;
    # otherwise a stale/misassociated text row such as ``NOP`` must not be
    # treated as a branch just because the encoding key is branch-shaped.
    toks = (text or "").split()
    if toks and toks[0].startswith("@"):
        toks.pop(0)
    mnemonic = toks[0].split(".", 1)[0] if toks else ""
    expected = key.split("_", 1)[0] if key else ""
    if mnemonic != expected:
        return None
    fact = asm_spec.pc_offset_fact(key) if key else None
    if (not fact or asm_spec._is_absolute(text)
            or fact.get("text_coordinate") == "relative_offset"):
        return None
    return addr + fact["insn_len"] + asm_spec.read_offset(fact, enc)


def _external_symbol(text: str) -> bool:
    """目标是**外部符号**（函数入口 `` `(_Z10fma_kernelPfS_S_) ``）而不是局部标号。

    这种目标原样保留，不改写成 `.L_<地址>`：它指的是别的符号，地址只是它此刻
    恰好落在的位置；改写会把「跳到这个函数」偷换成「跳到这个偏移」。源码汇编的
    原样回填路径也因此能逐字节保住这一条。nvdisasm 自己的局部标号
    （`` `(.L_x_0) ``）不算外部符号，照常换成本文件的标号。
    """
    m = re.search(r"`\(([^)]*)\)", text or "")
    return bool(m) and not m.group(1).startswith(".L")


def emit_source(data: bytes, section: str | None = None) -> SourceFile:
    """基底 cubin 的一个可执行 section -> `.nvsass` 源码。

    `section` 省略时：只有一个 `.text.*` 就用它，多个则报错要求指定 ——
    多 section 的 cubin 先让用户选，不替用户猜。
    """
    import cubin_sass
    from nvisa.oracle.cubin import Cubin

    cub = Cubin(data)
    if cub.sm_arch != 90:
        raise SourceError(
            f"SASS 源码编辑目前只支持 sm_90；这个 cubin 是 sm_{cub.sm_arch}。"
            "不同架构的指令宽度和控制段格式不同，不能按 sm_90 安全汇编回写")
    execs = [s for s in cub.sections if s.name.startswith(".text")]
    if not execs:
        raise SourceError("这个 cubin 里没有 .text.* section")
    if section:
        hit = [s for s in execs if s.name == section]
        if not hit:
            raise SourceError(
                f"没有 section {section!r}；有的是：{', '.join(s.name for s in execs)}",
                [s.name for s in execs])
        sec = hit[0]
    elif len(execs) > 1:
        raise SourceError(
            f"这个 cubin 有 {len(execs)} 个 .text section，请用 --section 指定："
            f"{', '.join(s.name for s in execs)}", [s.name for s in execs])
    else:
        sec = execs[0]

    texts = cubin_sass._section_texts(data, sec.name)
    warnings: list[str] = []
    rows = []
    for addr in range(0, sec.size - sec.size % _INST_BYTES, _INST_BYTES):
        enc = cub.read(addr, sec.name)
        text = (texts.get(addr) or "").strip().rstrip(";").strip()
        if not text:
            raise SourceError(
                f"{sec.name}+{addr:#x} nvdisasm 读不出来 —— 导不出可再汇编的源码")
        rows.append({"addr": addr, "enc": enc, "text": text,
                     "key": cubin_sass.identify(enc)})

    # 第一遍：哪些地址是段内跳转目标，才需要标号。
    labels: dict[int, str] = {}
    for r in rows:
        if _external_symbol(r["text"]):
            continue
        tgt = _branch_target(r["key"], r["text"], r["enc"], r["addr"])
        if tgt is None or tgt % _INST_BYTES or not 0 <= tgt < sec.size:
            continue
        labels[tgt] = label_for(tgt)

    # 函数符号的起点：变长打包要按它更新 `st_value`/`st_size`，所以符号必须
    # 在源码里有位置，否则插一条指令之后没人知道函数从哪开始、有多长。
    funcs = {s["value"]: s["name"] for s in _symbols(data)
             if s["shndx"] == _section_index(data, sec.name)}

    lines = [".arch sm_90", f".section {sec.name}", f".base {base_hash(data)}"]
    regcount = cub.regcount_for_section(sec.name)
    if regcount is not None:
        # EIATTR_REGCOUNT belongs to the kernel, not to an instruction.  Keep
        # it next to the section header so multi-kernel sources expose each
        # kernel's independent allocation explicitly.
        lines.append(f".regcount {regcount}")
    lines.append("")
    for r in rows:
        if r["addr"] in funcs:
            lines.append(f".func {funcs[r['addr']]}")
        if r["addr"] in labels:
            lines.append(f"{labels[r['addr']]}:")
        text = r["text"]
        tgt = (None if _external_symbol(text)
               else _branch_target(r["key"], text, r["enc"], r["addr"]))
        if tgt in labels:
            m = _TAIL_TARGET.search(text)
            if m is None:
                raise SourceError(
                    f"{sec.name}+{r['addr']:#x} 是分支，但行尾找不到目标：{text!r}")
            text = text[:m.start(1)] + labels[tgt]
        # 行尾的 `// @0x0070` 是这一行**在基底里的原地址**。变长打包靠它把「旧地址 →
        # 新地址」这张映射建起来（`.nv.info` 的指令偏移、RELA addend、分支目标都
        # 要过这张映射），源码汇编也靠它认出「这一行没改过，只是挪了位置」从而沿用
        # 基底的位。手敲的新行没有这个注释，就是新指令。
        line = f"{ctrl_prefix(r['enc'])} {text};    // @{r['addr']:#06x}"
        reuse = get_bits(r["enc"], *_CTRL_BITS["reuse"])
        if reuse and ".reuse" not in text:
            msg = (f"{sec.name}+{r['addr']:#x}：reuse 位 = {reuse:#05b} 但 nvdisasm "
                   f"没打印（yield/stall 让它隐藏），源码里表达不了")
            warnings.append(msg)
            line += f"  !! reuse={reuse:#05b} 未打印"
        lines.append(line)
    return SourceFile("\n".join(lines) + "\n", sec.name, base_hash(data),
                      labels, warnings)


def emit_all_sources(data: bytes) -> SourceBundle:
    """Export all ``.text*`` sections as one foldable ``.nvsass`` document.

    Labels and ``// @address`` anchors are section-relative, so each section is
    kept as an independent source block.  The shared architecture and base
    fingerprint appear once at the top of the document.
    """
    from nvisa.oracle.cubin import Cubin

    cub = Cubin(data)
    names = [s.name for s in cub.sections if s.name.startswith(".text")]
    if not names:
        raise SourceError("这个 cubin 里没有 .text.* section")

    rendered = [emit_source(data, name) for name in names]
    lines = [BUNDLE_MARKER, ".arch sm_90", f".base {base_hash(data)}", ""]
    warnings: list[str] = []
    for index, src in enumerate(rendered):
        own = src.text.splitlines()
        # emit_source's first three lines are .arch/.section/.base.  The bundle
        # owns the first and third globally, while .section starts each fold.
        lines.append(f".section {src.section}")
        lines.extend(own[3:])
        if index + 1 < len(rendered) and (not lines or lines[-1] != ""):
            lines.append("")
        warnings.extend(src.warnings)
    return SourceBundle("\n".join(lines) + "\n", names, base_hash(data), warnings)


_ORIGIN = re.compile(r"//\s*@0x([0-9a-fA-F]+)")


def refresh_source(text: str, new_base: str,
                   addr_map: dict[int, int] | None = None) -> str:
    """保存成功之后，把源码「重新绑到新基底」。

    落盘写的是源码自己的基底时，源码头里的 `.base` 和行尾的 `// @0x....` 都还
    指着**旧**基底：`.base` 会被下一次保存的冲突闸挡下来（第一次能存、第二次报
    「基底对不上」），`@0x....` 则在插删之后指错行，把「没改过的行」误判成新
    指令。这里按 `addr_map`（旧地址 -> 新地址）把两者一起换掉，只动这两处，
    用户的排版、注释、标号名一个字不碰。
    """
    amap = addr_map or {}

    def fix(m: re.Match[str]) -> str:
        old = int(m.group(1), 16)
        return f"// @{amap.get(old, old):#06x}"

    out = []
    for line in text.splitlines():
        if re.match(r"^\s*\.base\s+", line):
            out.append(re.sub(r"^(\s*\.base\s+)\S+", lambda m: m[1] + new_base, line))
        else:
            out.append(_ORIGIN.sub(fix, line))
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def refresh_source_bundle(text: str, new_base: str,
                          addr_maps: dict[str, dict[int, int]]) -> str:
    """Rebind a multi-section source document after a successful transaction."""
    current: str | None = None
    out = []
    for line in text.splitlines():
        section = _SECTION_DIRECTIVE.match(line)
        if section:
            current = section.group(1)
        if re.match(r"^\s*\.base\s+", line):
            out.append(re.sub(r"^(\s*\.base\s+)\S+", lambda m: m[1] + new_base, line))
            continue
        amap = addr_maps.get(current or "", {})

        def fix(m: re.Match[str], amap: dict[int, int] = amap) -> str:
            old = int(m.group(1), 16)
            return f"// @{amap.get(old, old):#06x}"

        out.append(_ORIGIN.sub(fix, line))
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")
