"""`.nvsass` 整段两遍汇编。

输入是 `--emit-source` 导出（或用户手改）的源码文本，输出是**整段的 16 字节编码序列**；
这里只负责「文本 → 编码」。塞回 cubin 由 `assemble_into()` 负责：条数不变就地回填，
条数变了交给 `elf_rewrite`（变长打包）；整次保存的事务与验收在 `sass_save`。

两遍：

1. **第一遍**只解析：directive、控制码、指令 AST，同时给每条指令排 16 字节对齐的
   地址，建立「标号 → 地址」符号表。这一遍不编码，所以标号可以后向引用。
2. **第二遍**把局部标号换成数值地址，走本项目自己的
   `AST → values → encode_spec` 那条路，逐条过 nvdisasm 回环。

## 与 `assemble_at()` 的三处硬性差别

* **控制码是硬要求**。`assemble_at()` 改的是一条已经存在的指令，控制段可以沿用
  原指令（`cubin_sass._inherit_ctrl()`）；源码模式**没有原指令**——一行可能是刚敲出来
  的，也可能是从别处剪切过来的。所以缺控制码直接报错，给出的字段在编码完成后
  统一覆盖 bits 105:121，绝不从模板或原地址带值。
* **`.reuse` 按 opcode 现探**。文本里的 `.reuse` 挂在第几个操作数上，对应
  122:124 的哪一位是逐 opcode 不同的，由 `probe_reuse_bits()` 问
  nvdisasm。没写 `.reuse` 时**不清零这三位**——少数 opcode 会把其中某位用于非
  reuse 语义，只能改已经被探明确认是 reuse 的位。
* **全有或全无**。任何一条不支持、标号未定义/重复、控制码非法、回读不符，整次
  编译失败并把所有诊断（精确到行/列）一次交出来，不产生半份结果。

## 边界说清楚

支持的是**段表已经覆盖的 form**：语料文本当前覆盖 866/909（95.27%），不是完整
ISA。剩下的会在这里报「不支持的 form」，而不是悄悄编错——每条编码都过 nvdisasm
回环，分支按最终地址重基准（`asm_spec.rebase()`）。首版不做宏、表达式、自动寄存器
分配、自动 barrier/stall 排程，也不新建 section、不动 kernel 参数 ABI。
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from nvisa.model import asm_spec
from nvisa.model.sass_parser import Label, SassSyntaxError, parse_line
from nvisa.model.sass_source import base_hash

#: 控制段字段（bits 105:121），与 `asm.FIELDS` / `sass_source._CTRL_BITS` 同源。
_CTRL_BITS = {"stall": (105, 108), "yield": (109, 109), "wr": (110, 112),
              "rd_bar": (113, 115), "wait": (116, 121)}
_REUSE_BITS = (122, 124)
_INST_BYTES = 16
_ARCH = "sm_90"


@dataclass
class Diagnostic:
    """一条诊断。`line` 0 基，`col`/`end` 0 基列 —— 编辑器直接映射到 Range。"""
    line: int
    col: int
    end: int
    msg: str

    def render(self) -> str:
        return f"第 {self.line + 1} 行第 {self.col + 1} 列：{self.msg}"


class SourceAsmError(ValueError):
    """整次编译失败。`diagnostics` 是全部问题，不是第一个。"""

    def __init__(self, diags: list[Diagnostic]):
        super().__init__("；".join(d.render() for d in diags[:5])
                         + (f"（共 {len(diags)} 条）" if len(diags) > 5 else ""))
        self.diagnostics = diags


@dataclass
class Assembled:
    section: str | None
    arch: str
    base: str | None
    encodings: list[str] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)
    regcount: int | None = None          # `.regcount` 显式给的值
    regcount_line: int | None = None     # 诊断定位
    regs_used: int = 0                   # 扫出来的显式 GPR 预算
    warnings: list[str] = field(default_factory=list)
    #: 旧地址 -> 新地址。来自每行行尾的 `// @0x0070` 原地址注释；手敲的新行没有
    #: 原地址，也就不在这张表里。变长打包的 `.nv.info`/RELA/符号更新全靠它。
    addr_map: dict[int, int] = field(default_factory=dict)
    #: 源码里删掉的旧地址（基底有、源码里没有）。
    dropped: list[int] = field(default_factory=list)
    #: `.func` 标出来的函数符号新起点：`{名字: 新地址}`。
    symbols: dict[str, int] = field(default_factory=dict)
    #: 每个调试 section 的策略决策（`debug_policy.Decision`）。变长打包才有。
    debug_decisions: list = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.encodings) * _INST_BYTES

    def to_bytes(self) -> bytes:
        from nvisa.oracle.cubin import enc_to_bytes
        return b"".join(enc_to_bytes(e) for e in self.encodings)


# --- 第一遍 ---------------------------------------------------------------

@dataclass
class _Row:
    """一条待编码的指令：源码行号、段内**新**地址、AST、原地址（没有就是 None）。"""
    lineno: int
    addr: int
    insn: object
    text: str
    origin: int | None = None


def _pass1(text: str) -> tuple[Assembled, list[_Row], list[Diagnostic]]:
    """解析 + 排地址 + 建符号表。不编码，所以标号可以后向引用。"""
    out = Assembled(section=None, arch=_ARCH, base=None)
    rows: list[_Row] = []
    diags: list[Diagnostic] = []
    addr = 0
    for i, raw in enumerate(text.splitlines()):
        try:
            line = parse_line(raw, i)
        except SassSyntaxError as e:
            diags.append(Diagnostic(i, e.col, e.end, e.msg))
            continue
        if line.directive is not None:
            if line.directive.name == ".func" and len(line.directive.args) == 1:
                # 函数符号落在**当前**地址上：插了指令它就跟着往后走，变长打包按这个
                # 更新 `st_value`。
                out.symbols[line.directive.args[0]] = addr
            _directive(out, line.directive, i, diags)
            continue
        if line.label is not None:
            name = line.label.name
            if name in out.labels:
                diags.append(Diagnostic(i, line.label.col, line.label.end,
                                        f"标号 {name} 重复定义"))
                continue
            out.labels[name] = addr
            continue
        if line.insn is None:
            continue
        if line.insn.ctrl is None:
            # 源码模式没有可继承控制段的原指令，缺了就是硬错误。
            diags.append(Diagnostic(
                i, line.insn.col, line.insn.end,
                "这条指令没有控制码 —— 源码模式要求每行显式写 "
                "[B------:R-:W-:-:S01]，不继承基底、不自动排程"))
            continue
        body = raw[line.insn.ctrl.end:]
        body = body.split("//")[0].strip().rstrip(";").strip()
        rows.append(_Row(i, addr, line.insn, body, _origin(line.comment)))
        addr += _INST_BYTES
    return out, rows, diags


def _directive(out: Assembled, d, lineno: int, diags: list[Diagnostic]) -> None:
    if d.name == ".arch":
        if d.args != [_ARCH]:
            diags.append(Diagnostic(lineno, d.col, d.end,
                                    f"只支持 .arch {_ARCH}，写的是 {' '.join(d.args)}"))
        return
    if d.name == ".section":
        if len(d.args) != 1:
            diags.append(Diagnostic(lineno, d.col, d.end, ".section 要正好一个名字"))
            return
        out.section = d.args[0]
        return
    if d.name == ".base":
        out.base = d.args[0] if d.args else None
        return
    if d.name == ".func":
        if len(d.args) != 1:
            diags.append(Diagnostic(lineno, d.col, d.end, ".func 要正好一个符号名"))
        return
    if d.name == ".regcount":
        if out.regcount is not None:
            diags.append(Diagnostic(lineno, d.col, d.end, ".regcount 重复定义"))
            return
        try:
            if len(d.args) != 1:
                raise ValueError
            out.regcount = int(d.args[0], 0)
        except (IndexError, ValueError):
            diags.append(Diagnostic(lineno, d.col, d.end, ".regcount 要一个整数"))
            return
        out.regcount_line = lineno
        if not 1 <= out.regcount <= 255:
            diags.append(Diagnostic(
                lineno, d.col, d.end, ".regcount 必须在 1..255 之间"))
        return
    diags.append(Diagnostic(lineno, d.col, d.end,
                            f"不认识的 directive {d.name}"
                            f"（只支持 .arch/.section/.base/.regcount/.func）"))


# --- 第二遍 ---------------------------------------------------------------

#: 行尾的原地址注释：`// @0x0070`。`--emit-source` 写的，手敲的新行没有。
_ORIGIN = re.compile(r"//\s*@(0x[0-9a-fA-F]+)")


def _origin(comment: str | None) -> int | None:
    m = _ORIGIN.search(comment or "")
    return int(m.group(1), 16) if m else None


#: 局部标号名：`.L_0d40` / `.L_loop`（点开头，不含 `SR_TID.X` 这种）。
_LOCAL_LABEL = re.compile(r"\.L[\w.$]*")


def _resolve_labels(row: _Row, labels: dict[str, int],
                    diags: list[Diagnostic]) -> str | None:
    """把指令文本里的局部标号换成数值地址。全部替换成功才返回文本。

    只认第一遍建起来的符号表。`` `(符号) `` 这种指向别的 section 的外部符号
    这里给不出地址（要接 ELF 符号表），明确报错，不猜。
    """
    text = row.text
    edits = []
    for op in row.insn.operands:
        if not isinstance(op, Label):
            continue
        name = op.text
        if name.startswith("`("):
            diags.append(Diagnostic(row.lineno, op.col, op.end,
                                    f"外部符号 {name} 解析不了 —— 源码模式只认本段内"
                                    f"定义的局部标号"))
            return None
        # 少写逗号的写法（`RET.REL.NODEC R10 .L_0000`）会把整段粘成一个 label
        # 节点，标号名嵌在里面 —— 按名字替换，不整节点替换。
        found = _LOCAL_LABEL.findall(name)
        if not found and not name.startswith("."):
            continue                       # SR_TID.X 一类：不是标号，别动
        if not found:
            diags.append(Diagnostic(row.lineno, op.col, op.end,
                                    f"标号 {name} 没有定义"))
            return None
        rep = name
        for nm in found:
            if nm not in labels:
                diags.append(Diagnostic(row.lineno, op.col, op.end,
                                        f"标号 {nm} 没有定义"))
                return None
            rep = rep.replace(nm, f"{labels[nm]:#x}")
        edits.append((op.col, op.end, rep))
    if not edits:
        return text
    # span 是相对整行的，`row.text` 是从控制码之后截出来的 —— 减掉指令起始列。
    off = row.insn.col
    out = text
    for col, end, rep in sorted(edits, reverse=True):
        out = out[:col - off] + rep + out[end - off:]
    return out


def _write_ctrl(enc: str, ctrl) -> str:
    """把源码行上的控制码盖到 bits 105:121。编码里原有的控制值一律不保留。"""
    from nvisa.oracle.cubin import set_bits
    vals = {"stall": ctrl.stall, "yield": int(ctrl.yield_), "wr": ctrl.wr_bar,
            "rd_bar": ctrl.rd_bar, "wait": ctrl.wait}
    for name, (lo, hi) in _CTRL_BITS.items():
        enc = set_bits(enc, lo, hi, vals[name])
    return enc


def _hides_reuse(ctrl) -> bool:
    """这条控制码会不会让 nvdisasm 不打印 `.reuse`。

    实测（`cubin_sass.probe_reuse_bits` 的注释）：只有 `yield=1 且 stall>=1` 时
    nvdisasm 才把 `.reuse` 打出来 —— reuse cache 只有背靠背发射才有意义。所以
    「改了控制码让 reuse 不再显示」不算回环不符，只是读不回来。
    """
    return not (ctrl.yield_ and ctrl.stall >= 1)


def _verify(enc: str, key: str | None, text: str, row: _Row) -> str | None:
    """把最终编码交回 nvdisasm 读一遍，与源码行逐字比。不符返回读回的文本。"""
    import cubin_sass
    from nvisa.oracle.cubin import enc_to_bytes

    got = cubin_sass.disasm_one(enc_to_bytes(enc))
    shown = asm_spec.rebase(key, got, row.addr) if key else got   # 按最终地址
    a, b = cubin_sass._norm_sass(shown), cubin_sass._norm_sass(text)
    if a == b:
        return None
    if _hides_reuse(row.insn.ctrl) and a == b.replace(".reuse", ""):
        return None
    return shown or "<nvdisasm 拒绝>"


def _reuse_of(enc: str) -> int:
    from nvisa.oracle.cubin import get_bits
    return get_bits(enc, *_REUSE_BITS)


def _relocate(enc: str, row: _Row, text: str,
              addr_map: dict[int, int]) -> tuple[str | None, str]:
    """沿用基底的位、但这一行挪了位置时，**只改偏移那几位**把分支目标修回来。

    与定长插入/删除（`reflow`）同一条规矩：分支不整条重编 —— 整条重编会
    让段表把 `CALL.REL` 归并成 `.ABS`，也会丢掉未解释的那 36%
    位。目标地址过一遍「旧地址 → 新地址」映射；目标被删掉、或落在映射表外
    （手敲的新行没有原地址）就报错，不猜。
    """
    import cubin_sass

    if row.origin is None or row.origin == row.addr:
        return enc, ""
    key = cubin_sass.identify(enc)
    fact = asm_spec.pc_offset_fact(key) if key else None
    if not fact:
        return enc, ""
    absolute = asm_spec._is_absolute(text)
    off = asm_spec.read_offset(fact, enc)
    old_target = off if absolute else row.origin + fact["insn_len"] + off
    new_target = addr_map.get(old_target)
    if new_target is None:
        return None, (f"这一行从 {row.origin:#x} 挪到了 {row.addr:#x}，它的目标 "
                      f"{old_target:#x} 在新布局里找不到（被删了，或那一行是新加的、"
                      f"没有原地址注释）")
    new_off = new_target if absolute else new_target - row.addr - fact["insn_len"]
    if new_off == off:
        return enc, ""
    try:
        return asm_spec.write_offset(fact, enc, new_off), ""
    except asm_spec.AsmSpecError as e:
        return None, str(e)


def _identity(row: _Row, text: str, base: dict[int, tuple[str, str]]) -> str | None:
    """**原样一行的快速路径**：这一行就是基底同址那条指令时，沿用它的 128 位。

    为什么要有这条路：从零编码只能填出**段表解释得到**的位。往返测量显示还有约 36%
    的位没有解释（`LEA` 的 `.HI`/`.SX32` 这类），`encode_spec` 只能给默认值 ——
    对没改过的行来说这是白丢信息，导出再原样保存本该逐字节一致。
    所以先比一次：与 `--emit-source` 为同一地址生成的那行文本完全相同，就沿用
    基底的位，只把控制码按源码行覆盖回 105:121 —— **控制码永远以源码行为准**，
    这条不因走快速路径而松动。

    比对的锚点是行尾 `// @0x0070` 注释里的**原地址**，不是这一行现在的地址 ——
    在前面插一条指令会把后面每一行都挪走，但它们一行都没改，凭什么重编。挪过的
    行由 `_relocate()` 只改分支偏移那几位。

    比较的对象是**导出侧那行文本**，不是 `disasm_one()` 的单条反汇编：整段反汇编
    里 nvdisasm 会把跳转目标印成符号（`` `(_Z10helperi) ``），单条反汇编看不见
    符号表只能印成数值，拿后者比会把「一行都没改」误判成改过。

    改过的行走不到这里：文本一变就对不上，回到从零编码那条路，也就回到段表
    覆盖的 95.27% 那个边界。
    """
    import cubin_sass

    hit = base.get(row.origin if row.origin is not None else row.addr)
    if hit is None:
        return None
    enc, btext = hit
    if cubin_sass._norm_sass(btext) != cubin_sass._norm_sass(text):
        return None
    return _write_ctrl(enc, row.insn.ctrl)


def _encode_one(row: _Row, text: str, diags: list[Diagnostic],
                base: dict[int, tuple[str, str]]) -> str | None:
    """一条指令 -> 编码。每个候选 key 都过 nvdisasm 回环，全不符就报错。"""
    import cubin_sass
    from nvisa.model.encode import encode_spec
    from nvisa.oracle.cubin import set_bits

    same = _identity(row, text, base)          # 标号换成数值后可能才对得上
    if same is not None:
        return same

    try:
        keys = asm_spec.spec_keys(text)
    except asm_spec.AsmSpecError as e:
        diags.append(Diagnostic(row.lineno, row.insn.col, row.insn.end, str(e)))
        return None
    errors = []
    for key in keys:
        try:
            values = asm_spec.text_to_values(key, text, row.addr)
            enc = encode_spec(key, values)
        except Exception as e:                                   # noqa: BLE001
            errors.append(f"{key}: {e}")
            continue
        slots = values.get("reuse_slots") or []
        if slots:
            # 只改探明确认是 reuse 的位；没写 `.reuse` 时这三位一位不碰。
            reuse = cubin_sass.probe_reuse_bits(enc, slots)
            if reuse is None:
                errors.append(f"{key}: .reuse 位对不上任何操作数（nvdisasm 探测）")
                continue
            enc = set_bits(enc, *_REUSE_BITS, reuse)
        enc = _write_ctrl(enc, row.insn.ctrl)
        bad = _verify(enc, key, text, row)
        if bad is not None:
            errors.append(f"{key}: 回环不符，读回 {bad!r}")
            continue
        return enc
    diags.append(Diagnostic(
        row.lineno, row.insn.col, row.insn.end,
        f"编不出来（段表覆盖的 form 之外）：{text}"
        + ("；试过 " + "、".join(errors[:3]) if errors else "")))
    return None


_REG = re.compile(r"\bR(\d+)\b")


def _regs_used(rows: list[_Row], texts: list[str]) -> int:
    """显式 GPR 预算：文本里出现的最大 `R<n>` + 1（`RZ` 已经是 R255，不算）。

    这是**下界**：64/128 位操作数会隐式用到 `R<n+1>`，段表里没有位宽信息可查，
    所以只能保证「低于这个数一定不够」，不能保证「达到就一定够」。
    """
    top = -1
    for t in texts:
        for m in _REG.finditer(t):
            n = int(m.group(1))
            if n != 255:
                top = max(top, n)
    return top + 1


def _base_rows(data: bytes | None,
               section: str | None) -> dict[int, tuple[str, str]]:
    """基底目标 section 的 `{段内地址: (编码, 导出文本)}` —— `_identity()` 的参照。

    文本走的是 `--emit-source` 同一条路（`sass_source.emit_source()`），所以
    「导出的源码原样存回去」在定义上就是逐行命中快速路径。
    """
    if data is None or not section:
        return {}
    from nvisa.model.sass_source import SourceError, emit_source
    from nvisa.oracle.cubin import Cubin
    try:
        src = emit_source(data, section)
    except SourceError:
        return {}
    cub = Cubin(data)
    out, addr = {}, 0
    for ln in src.text.splitlines():
        line = parse_line(ln)
        if line.insn is None or line.insn.ctrl is None:
            continue
        body = ln[line.insn.ctrl.end:].strip().rstrip(";").strip()
        body = body.split("//")[0].strip()
        out[addr] = (cub.read(addr, section), body)
        addr += _INST_BYTES
    return out


def assemble_source(text: str, base_data: bytes | None = None) -> Assembled:
    """`.nvsass` 源码 -> 整段编码。失败抛 `SourceAsmError`（带全部诊断）。"""
    out, rows, diags = _pass1(text)

    if base_data is not None and out.base and out.base != base_hash(base_data):
        raise SourceAsmError([Diagnostic(
            0, 0, 1, f"基底对不上：源码写的是 .base {out.base}，"
                     f"给的 cubin 是 {base_hash(base_data)} —— "
                     f"基底在导出之后被改过，按外部修改冲突处理")])

    base_rows = _base_rows(base_data, out.section)
    # 复制一行会把原地址注释也复制走。映射表**第一次出现的那行说了算**：拷贝
    # 出来的副本算新指令（它不是「原来那条指令挪到了这里」），否则谁跳到旧地址
    # 都会被指到副本上。
    out.addr_map = {}
    for r in rows:
        if r.origin is not None and r.origin not in out.addr_map:
            out.addr_map[r.origin] = r.addr
    if base_rows:
        # 段末（最后一条的下一个地址）也是个合法的映射目标：分支可以跳到段尾，
        # `st_value + st_size` 也是这个坐标。
        out.addr_map.setdefault(max(base_rows) + _INST_BYTES,
                                len(rows) * _INST_BYTES)
        out.dropped = sorted(set(base_rows) - set(out.addr_map))
    texts = []
    encs = []
    for row in rows:
        # 先试原样一行的快速路径：**在解析标号之前**。没改过的行不需要标号地址，
        # 也就不该被「外部符号解析不了」挡住 —— `RET.REL.NODEC R10 `(kernel)` 这类
        # 指向别的符号的目标，原样保留才是对的（改写成偏移就换了语义）。
        same = _identity(row, row.text, base_rows)
        if same is not None:
            same, why = _relocate(same, row, row.text, out.addr_map)
            if same is None:
                diags.append(Diagnostic(row.lineno, row.insn.col, row.insn.end, why))
                texts.append(row.text)
                continue
            texts.append(row.text)
            encs.append(same)
            continue
        resolved = _resolve_labels(row, out.labels, diags)
        if resolved is None:
            texts.append(row.text)
            continue
        texts.append(resolved)
        enc = _encode_one(row, resolved, diags, base_rows)
        if enc is not None:
            encs.append(enc)
    if diags:
        raise SourceAsmError(diags)          # 全有或全无：不产生半份结果

    out.encodings = encs
    out.regs_used = _regs_used(rows, texts)
    base_budget = _base_regcount(base_data, out.section)
    if out.regcount is not None and base_budget is None:
        raise SourceAsmError([Diagnostic(
            out.regcount_line or 0, 0, 1,
            f"{out.section} 没有 EIATTR_REGCOUNT，不能凭空新增寄存器元数据")])
    # A changed .regcount is an expert override: write it literally and let the
    # user own launch/runtime consequences.  emit_source always prints the
    # current value, though, so an unchanged directive is still merely
    # inherited metadata and keeps the useful guard for instruction-only edits.
    overridden = out.regcount is not None and out.regcount != base_budget
    budget = None if overridden else base_budget
    if budget is not None and out.regs_used > budget:
        raise SourceAsmError([Diagnostic(
            0, 0, 1,
            f"寄存器超预算：源码用到 R{out.regs_used - 1}（至少要 {out.regs_used} 个），"
            f"预算只有 {budget} —— 加一行 .regcount {out.regs_used} 提高它。"
            f"注意 64/128 位操作数还会隐式多用一个 R，这个数只是下界")])
    return out


def _base_regcount(data: bytes | None, section: str | None) -> int | None:
    """基底里这个 section 对应 kernel 的 `EIATTR_REGCOUNT`（`.regcount` 省略时用）。"""
    if data is None:
        return None
    from nvisa.oracle.cubin import Cubin
    cub = Cubin(data)
    counts = cub.regcounts
    if not counts:
        return None
    if section is None or len(counts) == 1:
        return min(counts.values())
    idx = _section_index(data, section)
    syms = _func_symbols(data)
    hit = [counts[i] for i, s in syms.items() if s == idx and i in counts]
    return min(hit) if hit else None


def _section_index(data: bytes, name: str) -> int | None:
    from nvisa.model.reflow import _headers
    for i, h in enumerate(_headers(data)):
        if h[0] == name:
            return i
    return None


def _func_symbols(data: bytes) -> dict[int, int]:
    """symtab 里函数符号的 `{符号索引: shndx}` —— regcount 是按符号索引记的。"""
    from nvisa.model.reflow import _SHT_SYMTAB, _headers
    out = {}
    for name, s_type, _fl, _a, off, size in _headers(data):
        if s_type != _SHT_SYMTAB:
            continue
        for k, pos in enumerate(range(off, off + size, 24)):
            _n, st_info, _o, shndx, _v, _s = struct.unpack_from("<IBBHQQ", data, pos)
            if (st_info & 0xF) == 2:                       # STT_FUNC
                out[k] = shndx
    return out


def assemble_into(base_data: bytes, text: str, *, force: bool = False,
                  strip_debug: bool = False,
                  debug=None) -> tuple[bytes, Assembled]:
    """把源码编译进基底 cubin 的目标 section。

    条数没变就地回填（不动任何 ELF 元数据）；条数变了交给
    `elf_rewrite.rewrite()` —— 重排 section、重建 SHT/PHT，并把符号、RELA、
    `.nv.info` 的指令偏移按 `addr_map` 更新。
    """
    from nvisa.oracle.cubin import Cubin

    out = assemble_source(text, base_data)
    cub = Cubin(base_data)
    if not out.section:
        raise SourceAsmError([Diagnostic(0, 0, 1, "源码里没有 .section，不知道写哪一段")])
    sec = next((s for s in cub.sections if s.name == out.section), None)
    if sec is None:
        raise SourceAsmError([Diagnostic(
            0, 0, 1, f"基底里没有 section {out.section}")])
    room = sec.size - sec.size % _INST_BYTES
    if out.size != room:                          # 变长打包
        from nvisa.model.elf_rewrite import RewriteError, rewrite
        missing = [f"{a:#x}" for a in out.dropped]
        try:
            data, rep = rewrite(base_data, sec.name, out.to_bytes(), out.addr_map,
                                force=force, strip_debug=strip_debug, debug=debug)
        except RewriteError as e:
            raise SourceAsmError([Diagnostic(0, 0, 1, str(e))]) from e
        out.warnings += rep.warnings + rep.debug
        out.debug_decisions = list(rep.debug_decisions)
        if missing:
            out.warnings.append("源码里删掉了这些旧地址上的指令："
                                + "、".join(missing))
        return _apply_regcount(data, out), out
    data = bytearray(base_data)
    data[sec.offset:sec.offset + out.size] = out.to_bytes()
    return _apply_regcount(bytes(data), out), out


def _apply_regcount(data: bytes, out: Assembled) -> bytes:
    """Apply an explicit per-kernel EIATTR_REGCOUNT after code/ELF rewriting."""
    if out.regcount is None:
        return data
    from nvisa.oracle.cubin import Cubin
    cub = Cubin(data)
    changed = cub.set_section_regcount(out.section or "", out.regcount)
    if not changed:
        raise SourceAsmError([Diagnostic(
            out.regcount_line or 0, 0, 1,
            f"{out.section} 找不到可写的 EIATTR_REGCOUNT")])
    return bytes(cub.data)
