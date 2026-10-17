"""原生 SASS parser。

`asm_spec.text_to_values()` 原先直接加载 CuAssembler 的 `CuInsParser` 来拆
文本。源码模式不能沿用：产品代码、默认测试和 VS Code 扩展**不得** `import
CuAsm`、不得 subprocess 调 `cuasm.py`、不得依赖 `CUASM_PATH`。这里是本项目自己的
实现 —— tokenizer + 操作数递归下降 parser，产出带**源码 span** 的稳定 AST：

    parse_line(text)  ->  Line（ctrl 前缀 / predicate / mnemonic+modifiers /
                                operands / 注释 / label 定义 / directive）
    lower(ins)        ->  LowerResult(key, vals, modi, tags)

AST 是给编辑器用的（诊断精确到行/列、语法高亮、hover）；`lower()` 是给编码层用的
——它把 AST 摊平成段表 `cells` 里 `slot`/`tag` 那一套坐标。**两者分层**：换一种
文本语法只动 parser，换一套位映射只动段表。

## 为什么 `lower()` 的输出长得像 CuAssembler

段表（`data/segtable-sm90.json`）的 `slot` 列号和 `tag` 名字最初就是按
CuInsParser 的列序标定的：谓词前缀占 slot 0（`P.Guard`），地址形式永远补一个
`Imme.Addr` 零立即数，`c[][]` 的 bank 单独占一列。**这是段表的坐标系，不是
CuAssembler 的权重。** 实测 CuAssembler 解出来的权重（哪一位放哪）不可
信，本项目从不用；这里复刻的只有「文本怎么拆成列」这个约定，换掉它就要重标一遍
段表。所以 `lower()` 逐条对齐了那套列序约定（`_ADDR_FUNCS` 的分支打包、
`NegIntImme`、位置相关修饰符的 `@n` 后缀……）。

## 控制码是源码行的一部分

`[B0-----:R-:W1:-:S04]` 前缀：6 位 wait mask、read/write barrier、yield、stall。
源码模式要求**每条指令显式写控制码**，不继承基底、不自动调度 —— 于是移动
一行时控制码跟着走。`parse_ctrl()`/`format_ctrl()` 是这个前缀的唯一入口。
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field


class SassSyntaxError(ValueError):
    """带位置的语法错误 —— `col` 是 0 基列号，`end` 是出错片段的结束列。"""

    def __init__(self, msg: str, col: int = 0, end: int | None = None):
        super().__init__(msg)
        self.msg = msg
        self.col = col
        self.end = end if end is not None else col + 1

    def __str__(self) -> str:                       # pragma: no cover - 展示用
        return f"第 {self.col + 1} 列：{self.msg}"


# ---------------------------------------------------------------------------
# tokenizer
# ---------------------------------------------------------------------------

#: 单字符前缀修饰符，同 CuInsParser 的 `c_OpPreModifierChar`。
_PRE_MODI = {"!": "cNOT", "-": "cNEG", "|": "cABS", "~": "cINV"}

_PUNCT = set("[](),+-|!~{}")
#: 「词」允许的字符：标识符、数字、点号（修饰符/浮点）、`?`（`RET.NODEC` 一类
#: 的通配助记符里出现过）、反引号标号 `` `(.L_x_0) `` 的组成部分。
_WORD = re.compile(r"[A-Za-z0-9_.?@$]+")


@dataclass(frozen=True)
class Token:
    kind: str          # 'word' | 'punct' | 'label'
    text: str
    col: int

    @property
    def end(self) -> int:
        return self.col + len(self.text)


def tokenize(s: str, base: int = 0) -> list[Token]:
    """把一段操作数文本切成 token。`base` 是这段文本在整行里的起始列。"""
    out: list[Token] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "`":                       # 符号标号 `(.L_x_0)
            j = s.find(")", i)
            if j < 0:
                raise SassSyntaxError("符号标号没有闭合的 `)`", base + i, base + n)
            out.append(Token("label", s[i:j + 1], base + i))
            i = j + 1
            continue
        if c in _PUNCT:
            out.append(Token("punct", c, base + i))
            i += 1
            continue
        m = _WORD.match(s, i)
        if not m:
            raise SassSyntaxError(f"无法识别的字符 {c!r}", base + i)
        j = m.end()
        # 科学计数法的指数符号：`1.5e-39` 里的 `-` 属于这个数，不是操作数前缀。
        # 只在「词以 e/E 结尾且后面紧跟符号+数字」时接上，`R2-0x10` 不受影响。
        if m.group()[-1] in "eE" and m.group()[0].isdigit():
            e = re.match(r"[-+]\d+", s[j:])
            if e:
                j += e.end()
        out.append(Token("word", s[i:j], base + i))
        i = j
    return out


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass
class Node:
    col: int = 0
    end: int = 0

    @property
    def span(self) -> tuple[int, int]:
        return (self.col, self.end)


@dataclass
class Reg(Node):
    """索引寄存器：`R2`、`UR4`、`P0`、`UP7`、`B3`、`SB1`、`SBSET25`。

    `RZ`/`URZ`/`PT`/`UPT` 在这里已经规范成 `R255`/`UR63`/`P7`/`UP7` ——
    段表里存的是编码值，中性值是全 1。
    """
    label: str = "R"
    index: int = 0
    pre: list[str] = field(default_factory=list)       # cNEG/cABS/cNOT/cINV
    modifiers: list[str] = field(default_factory=list)  # .reuse/.X4/.64/...


@dataclass
class Imme(Node):
    """立即数。`is_float` 时 `value` 还是**文本**，位宽要看 opcode 精度，
    只能在 `lower()` 里定；整数在这里就已经是 Python int（负数就是负的）。"""
    text: str = ""
    value: int = 0
    is_float: bool = False
    pre: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)


@dataclass
class Addr(Node):
    """`[R2+UR4+0x10]` —— 三个子项都可省略，编码坐标里立即数永远补 0。"""
    reg: Reg | None = None
    ureg: Reg | None = None
    imm: Imme | None = None


@dataclass
class ConstMem(Node):
    """`c[0x0][0x160]` / `c[0x0][R2+0x28]`；`cx[UR4][...]` 时 `ubank` 非空。"""
    bank: int | None = None
    ubank: Reg | None = None
    addr: Addr | None = None
    pre: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)


@dataclass
class DescAddr(Node):
    """`desc[UR6][R2.64]` —— 带 cache-policy 描述符的地址。"""
    ureg: Reg | None = None
    addr: Addr | None = None
    pre: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)


@dataclass
class Label(Node):
    """认不出结构的操作数：`SR_TID.X`、`` `(.L_x_0) ``、`.L_loop`。

    值不在指令自己身上（标号）或干脆没有值（特殊寄存器名），`lower()` 只把
    原文当一个修饰符 token 交出去，靠 fieldscan 的 token 表去认。
    """
    text: str = ""


@dataclass
class Pred(Node):
    """谓词前缀 `@!P0`。`value` 是编码值：`idx | (取反 << 3)`。"""
    label: str = "P"
    index: int = 7
    negate: bool = False

    @property
    def value(self) -> int:
        return self.index + (8 if self.negate else 0)


@dataclass
class Ctrl(Node):
    """控制段 `[B0-----:R-:W1:-:S04]`（bits 105:121）。"""
    wait: int = 0
    rd_bar: int = 7
    wr_bar: int = 7
    yield_: bool = False
    stall: int = 0


@dataclass
class Instruction(Node):
    ctrl: Ctrl | None = None
    pred: Pred | None = None
    mnemonic: str = ""
    modifiers: list[str] = field(default_factory=list)   # opcode 上的 `.XXX`
    operands: list[Node] = field(default_factory=list)

    @property
    def opcode_full(self) -> str:
        return ".".join([self.mnemonic] + self.modifiers)


@dataclass
class LabelDef(Node):
    """`.L_loop:` 局部标号定义。"""
    name: str = ""


@dataclass
class Directive(Node):
    """`.arch sm_90` / `.section .text.foo` / `.regcount 16`。"""
    name: str = ""
    args: list[str] = field(default_factory=list)


@dataclass
class Line(Node):
    """一整行。四种形态互斥，都可能带行尾 `//` 注释；空行三者皆 None。"""
    lineno: int = 0
    text: str = ""
    insn: Instruction | None = None
    label: LabelDef | None = None
    directive: Directive | None = None
    comment: str | None = None


# ---------------------------------------------------------------------------
# 控制码前缀
# ---------------------------------------------------------------------------

_CTRL_RE = re.compile(
    r"\[\s*B(?P<wait>[0-5\-]{6})\s*:\s*R(?P<rd>[0-5\-])\s*:\s*W(?P<wr>[0-5\-])"
    r"\s*:\s*(?P<yield>[Y\-])\s*:\s*S(?P<stall>\d{1,2})\s*\]")


def parse_ctrl(s: str, col: int = 0) -> Ctrl:
    """`[B0-----:R-:W1:-:S04]` -> `Ctrl`。

    `B` 后面 6 个字符是 wait mask 的 barrier 0..5（`-` 表示不等）；`R`/`W` 是
    read/write barrier 编号，`-` = 7（未用）；`Y` 表示允许 yield；`S00..S15`
    是 stall 原始值。这是本项目自己定的拼写，参考了已有工具的惯例。
    """
    m = _CTRL_RE.fullmatch(s.strip())
    if not m:
        raise SassSyntaxError(
            f"控制码格式不对：{s!r}，应形如 [B------:R-:W-:-:S01]", col, col + len(s))
    wait = 0
    for i, c in enumerate(m.group("wait")):
        if c == "-":
            continue
        if int(c) != i:
            raise SassSyntaxError(
                f"wait mask 第 {i} 位只能写 '{i}' 或 '-'，写的是 {c!r}", col, col + len(s))
        wait |= 1 << i
    stall = int(m.group("stall"))
    if not 0 <= stall <= 15:
        raise SassSyntaxError(f"stall 只能是 0..15，写的是 {stall}", col, col + len(s))
    return Ctrl(col=col, end=col + len(s),
                wait=wait,
                rd_bar=7 if m.group("rd") == "-" else int(m.group("rd")),
                wr_bar=7 if m.group("wr") == "-" else int(m.group("wr")),
                yield_=m.group("yield") == "Y",
                stall=stall)


def format_ctrl(wait: int, rd_bar: int, wr_bar: int, yield_: int, stall: int) -> str:
    """`Ctrl` 的字段 -> 前缀文本。与 `parse_ctrl()` 严格互逆。"""
    mask = "".join(str(i) if (wait >> i) & 1 else "-" for i in range(6))
    rd = "-" if rd_bar == 7 else str(rd_bar)
    wr = "-" if wr_bar == 7 else str(wr_bar)
    return f"[B{mask}:R{rd}:W{wr}:{'Y' if yield_ else '-'}:S{stall:02d}]"


# ---------------------------------------------------------------------------
# 操作数解析（递归下降）
# ---------------------------------------------------------------------------

#: `RZ`/`URZ`/`PT`/`UPT` 的规范化目标，同 CuInsParser 的 `p_ConstTrDict`。
#: `.RZ`（舍入模式）不在此列 —— 它是修饰符，parser 里走的是另一条路。
_CONST_REG = {"RZ": ("R", 255), "URZ": ("UR", 63),
              "PT": ("P", 7), "UPT": ("UP", 7)}
_INDEXED = re.compile(r"^(R|UR|P|UP|B|SB|SBSET|SR)(\d+)$")
_HEX = re.compile(r"^-?0[xX][0-9a-fA-F]+$")
_FLOAT = re.compile(
    r"^((-?\d+)(\.\d*)?([eE][-+]?\d+)?|[+-]?(?:Q?NAN|INF)|-?0[fF][0-9a-fA-F]+)$")


def _split_word(text: str) -> tuple[str, list[str]]:
    """把一个「词」拆成主体和 `.` 修饰符。

    修饰符是**字母开头**的点分段（`p_ModifierPattern` 的 `(\\.\\w+)*` 在实际
    语料里就这一种）；数字开头的点分段属于主体，否则 `1.5.NEG` 的小数部分会
    被当成修饰符、`R2.64` 的 `.64` 又该是修饰符 —— 区别在主体是不是索引寄存器。
    """
    parts = text.split(".")
    main, modi = parts[0], []
    for p in parts[1:]:
        if modi or (p[:1].isalpha() or p == "") or _INDEXED.match(main):
            modi.append(p)
        else:
            main += "." + p
    return main, modi


class _OperandParser:
    """一条指令的操作数流。`toks` 是整段操作数文本的 token 列表。"""

    def __init__(self, toks: list[Token], text: str, mnemonic: str = "",
                 base: int = 0):
        self.toks = toks
        self.i = 0
        self.text = text
        self.mnemonic = mnemonic
        self.base = base

    # --- token 原语 ---------------------------------------------------
    def peek(self) -> Token | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> Token:
        t = self.peek()
        if t is None:
            last = self.toks[-1].end if self.toks else 0
            raise SassSyntaxError("操作数意外结束", last)
        self.i += 1
        return t

    def accept(self, text: str) -> Token | None:
        t = self.peek()
        if t is not None and t.text == text:
            self.i += 1
            return t
        return None

    def expect(self, text: str) -> Token:
        t = self.accept(text)
        if t is None:
            got = self.peek()
            raise SassSyntaxError(
                f"缺少 {text!r}", got.col if got else (self.toks[-1].end if self.toks else 0))
        return t

    # --- 语法 ---------------------------------------------------------
    def operands(self) -> list[Node]:
        """`operand (',' operand)*`，外加分支指令 `BRX R18 -0x320` 的空格分隔。"""
        out: list[Node] = []
        if self.peek() is None:
            return out
        while True:
            out.append(self.operand())
            if self.accept(","):
                continue
            if self.peek() is None:
                break
            # 逗号省略只有一种合法写法：跳转类的「寄存器 + 数值偏移」
            # （`BRX R18 -0x320`）。这是段表按 CuInsParser 的 p_RImmeAddr
            # 标定的列序，不是通用语法。
            # uniform 变体（`BRXU UR4 0x1c0`、`JMP UR4 ...`）走的是同一套列序，
            # 只是寄存器堆不同；漏掉 UR 会让整段退化成一个 label 操作数，于是
            # `BRXU_UR_II` 被解析成 `BRXU_L`，IR 导出按「parser 漂移」拒绝。
            nxt = self.peek()
            if (self.mnemonic in _ADDR_FUNCS and isinstance(out[-1], Reg)
                    and out[-1].label in ("R", "UR") and self._is_number_ahead(
                        self.i + 1 if nxt.text == "-" else self.i)):
                continue
            # 其余「粘」在一起的写法（`RET.REL.NODEC R10 \`(kernel)`）整段退化
            # 成一个 label 操作数 —— 值不在指令身上，交给上层报真正的原因。
            out[-1] = self._merge_label(out[-1])
            if self.accept(","):
                continue
            break
        return out

    def _merge_label(self, first: Node) -> Label:
        """从 `first` 起把剩下的 token 粘成一个 label 操作数（空白全去掉）。"""
        text = self.text[first.col - self.base:first.end - self.base]
        while self.peek() is not None and self.peek().text != ",":
            t = self.next()
            text += t.text
        end = self.toks[self.i - 1].end if self.i else first.end
        return Label(col=first.col, end=end, text=text.replace(" ", ""))

    def _pre_modifiers(self) -> list[str]:
        """`-R2`、`|R7|`、`!P0`、`~R3` 的前缀。`|` 的闭合在主体之后处理。"""
        out = []
        while True:
            t = self.peek()
            if t is None or t.kind != "punct" or t.text not in _PRE_MODI:
                return out
            # `-0x10` 的 `-` 属于立即数本身，不是修饰符（CuInsParser 也会先
            # 剥成 cNEG 再在 II 分支上丢掉，等价）。
            if t.text == "-" and self._is_number_ahead(self.i + 1):
                return out
            self.i += 1
            out.append(_PRE_MODI[t.text])

    def _is_number_ahead(self, idx: int) -> bool:
        t = self.toks[idx] if idx < len(self.toks) else None
        # This decides whether a leading `-` belongs to an immediate or is an
        # operand cNEG modifier.  INF/NAN are numeric literals too, despite
        # not beginning with a digit.
        return (t is not None and t.kind == "word"
                and (_HEX.match(t.text) or _FLOAT.match(t.text)))

    def operand(self) -> Node:
        pre = self._pre_modifiers()
        t = self.peek()
        if t is None:
            raise SassSyntaxError("缺少操作数",
                                  self.toks[-1].end if self.toks else 0)
        if t.kind == "label":
            self.i += 1
            return Label(col=t.col, end=t.end, text=t.text)
        if t.text == "[":
            node = self.address(pre)
        elif t.kind == "word" and t.text.split(".")[0] in ("c", "cx", "desc"):
            node = self.memory(pre)
        else:
            node = self.value(pre)
        self._close_abs(node, pre)
        self._post_modifiers(node)
        return node

    def _close_abs(self, node: Node, pre: list[str]) -> None:
        """`|R7|` 的收尾竖线。写了前缀 `|` 就必须闭合。"""
        if "cABS" in pre:
            # nvdisasm may put an operand suffix *inside* the absolute-value
            # delimiters: `|c[...][...].H1_H1|`.  It has the same semantic
            # coordinate as the more familiar `|R7|.H1_H1`; consume the
            # former before requiring the closing bar.  The ordinary
            # post-pass below still accepts suffixes outside the delimiter.
            self._post_modifiers(node)
            t = self.accept("|")
            if t is None:
                raise SassSyntaxError("`|` 没有闭合", node.col, node.end)
            node.end = t.end

    def _post_modifiers(self, node: Node) -> None:
        """闭合括号之后还可能挂修饰符：`desc[UR6][R2.64].64`、`[R0.X4].A`。"""
        while True:
            t = self.peek()
            if t is None or t.kind != "word" or not t.text.startswith("."):
                return
            self.i += 1
            node.modifiers.extend(p for p in t.text.lstrip(".").split(".") if p)
            node.end = t.end

    def value(self, pre: list[str]) -> Node:
        """索引寄存器或立即数。"""
        # `+INF` is emitted by CuAssembler's saved historical records for
        # floating comparisons.  It is an immediate's explicit sign, not a
        # binary operator (the latter only exists inside an address).
        sign = self.accept("-") or self.accept("+")
        t = self.next()
        if t.kind != "word":
            raise SassSyntaxError(f"这里应该是寄存器或立即数，读到 {t.text!r}", t.col, t.end)
        main, modi = _split_word(t.text)
        if sign is not None:
            v = self.immediate(t, main, modi, pre, sign.text)
            v.col = sign.col
            return v
        if main in _CONST_REG:
            label, idx = _CONST_REG[main]
            return Reg(col=t.col, end=t.end, label=label, index=idx,
                       pre=pre, modifiers=modi)
        m = _INDEXED.match(main)
        if m:
            return Reg(col=t.col, end=t.end, label=m.group(1),
                       index=int(m.group(2)), pre=pre, modifiers=modi)
        # `-INF` / `+QNAN` tokenize their sign separately from the word.
        # Preserve it exactly as for a numeric literal; otherwise the AST has
        # seen the sign but float lowering silently constructs the opposite
        # value.
        return self.immediate(t, main, modi, pre, sign.text if sign else "")

    def immediate(self, t: Token, main: str, modi: list[str],
                  pre: list[str], neg: str) -> Node:
        """`0x10` / `-0x10` / `1.5` / `0f3f800000` / `INF`。

        认不出来的（`SR_TID.X`、`.L_loop`、`32@lo`）退化成 `Label` —— 与
        CuInsParser 的 `optype='L'` 同一条兜底路径：值不在指令身上，交给
        fieldscan 的 token 表去认。
        """
        text = neg + t.text
        col = t.col - len(neg)
        if _HEX.match(neg + main):
            return Imme(col=col, end=t.end, text=text,
                        value=int(neg + main, 16), pre=pre, modifiers=modi)
        if _FLOAT.match(neg + main):
            # `t.text` still includes dot modifiers (for example
            # `0.0078125.H1`).  `_split_word()` has already separated those
            # into `modi`; feeding the original token to `float()` rejects a
            # valid literal even though its modifier was recognized correctly.
            return Imme(col=col, end=t.end, text=neg + main,
                        value=0, is_float=True,
                        pre=pre, modifiers=modi)
        return Label(col=col, end=t.end, text=text)

    def address(self, pre: list[str]) -> Addr:
        """`'[' (reg|ureg|imm) ('+' ...)* ']'`，子项顺序随意、可全省。"""
        open_ = self.expect("[")
        node = Addr(col=open_.col, end=open_.end)
        while self.peek() is not None and self.peek().text != "]":
            self._addr_item(node)
            if not self.accept("+"):
                break
        close = self.expect("]")
        node.end = close.end
        return node

    def _addr_item(self, node: Addr) -> None:
        neg = "-" if self.accept("-") else ""
        t = self.next()
        if t.kind != "word":
            raise SassSyntaxError(f"地址里读到 {t.text!r}", t.col, t.end)
        main, modi = _split_word(t.text)
        if main in _CONST_REG or _INDEXED.match(main):
            if neg:
                raise SassSyntaxError("地址里的寄存器不能取负", t.col, t.end)
            label, idx = (_CONST_REG[main] if main in _CONST_REG
                          else (_INDEXED.match(main).group(1),
                                int(_INDEXED.match(main).group(2))))
            reg = Reg(col=t.col, end=t.end, label=label, index=idx, modifiers=modi)
            slot = "ureg" if label == "UR" else "reg"
            if getattr(node, slot) is not None:
                raise SassSyntaxError(f"地址里出现了两个 {label}", t.col, t.end)
            setattr(node, slot, reg)
            return
        v = self.immediate(t, main, modi, [], neg)
        if not isinstance(v, Imme) or v.is_float:
            raise SassSyntaxError(f"地址偏移不是整数立即数：{t.text!r}", t.col, t.end)
        if node.imm is not None:
            raise SassSyntaxError("地址里出现了两个立即数", t.col, t.end)
        node.imm = v

    def memory(self, pre: list[str]) -> Node:
        """`c[bank][addr]`、`cx[URn][addr]`、`desc[URn][addr]`。"""
        head = self.next()
        kind, modi = _split_word(head.text)
        if kind == "desc":
            self.expect("[")
            ur = self.value([])
            if not isinstance(ur, Reg) or ur.label != "UR":
                raise SassSyntaxError("desc[] 里应该是 UR 寄存器", head.col, head.end)
            self.expect("]")
            addr = self.address([])
            return DescAddr(col=head.col, end=addr.end, ureg=ur, addr=addr,
                            pre=pre, modifiers=modi)
        self.expect("[")
        bank_tok = self.peek()
        bank = self.value([])
        self.expect("]")
        addr = self.address([])
        if kind == "cx":
            if not isinstance(bank, Reg) or bank.label != "UR":
                raise SassSyntaxError("cx[] 的 bank 应该是 UR 寄存器",
                                      bank_tok.col, bank_tok.end)
            return ConstMem(col=head.col, end=addr.end, ubank=bank, addr=addr,
                            pre=pre, modifiers=modi)
        if not isinstance(bank, Imme) or bank.is_float:
            raise SassSyntaxError("c[] 的 bank 应该是整数立即数",
                                  bank_tok.col, bank_tok.end)
        return ConstMem(col=head.col, end=addr.end, bank=bank.value, addr=addr,
                        pre=pre, modifiers=modi)


# ---------------------------------------------------------------------------
# 行解析
# ---------------------------------------------------------------------------

_COMMENT = re.compile(r"//.*$|/\*.*?\*/")
_PRED_RE = re.compile(r"@(!?)(U?P[0-7T])\b")
_LABELDEF = re.compile(r"^(\.?[A-Za-z_][\w.$]*)\s*:\s*$")
_SBSET = re.compile(r"\{\s*\d\s*(?:,\s*\d\s*)*\}")


def _strip_comment(text: str) -> tuple[str, str | None]:
    m = re.search(r"//", text)
    if m is None:
        return text, None
    return text[:m.start()], text[m.start():]


def _sbset(text: str) -> str:
    """DEPBAR 的 `{4,2}` -> `SBSET20`（位掩码），与索引寄存器同构。"""
    def sub(m):
        v = 0
        for b in m.group().strip("{}").split(","):
            v |= 1 << int(b.strip())
        return f"SBSET{v}"
    return _SBSET.sub(sub, text)


def parse_instruction(text: str, base: int = 0, *, require_ctrl: bool = False) -> Instruction:
    """一条指令（可带控制码前缀）-> `Instruction`。列号相对 `text` 加 `base`。"""
    body = text.rstrip().rstrip(";")
    stripped = body.lstrip()
    off = base + (len(body) - len(stripped))

    ctrl = None
    if stripped.startswith("["):
        j = stripped.find("]")
        if j >= 0 and _CTRL_RE.fullmatch(stripped[:j + 1]):
            ctrl = parse_ctrl(stripped[:j + 1], off)
            stripped = stripped[j + 1:]
            off += j + 1
    if require_ctrl and ctrl is None:
        raise SassSyntaxError(
            "这一行没有控制码 —— 源码模式要求每条指令显式写 [B...:R.:W.:.:S..]",
            off, off + max(1, len(stripped)))
    lead = len(stripped) - len(stripped.lstrip())
    stripped, off = stripped.lstrip(), off + lead

    ins = Instruction(col=off, end=off + len(stripped), ctrl=ctrl)
    rest, rest_off = stripped, off
    m = _PRED_RE.match(rest)
    if m:
        name = m.group(2)
        label = "UP" if name.startswith("UP") else "P"
        idx = 7 if name.endswith("T") else int(name[-1])
        ins.pred = Pred(col=rest_off, end=rest_off + m.end(), label=label,
                        index=idx, negate=bool(m.group(1)))
        rest = rest[m.end():]
        rest_off += m.end()
        lead = len(rest) - len(rest.lstrip())
        rest, rest_off = rest.lstrip(), rest_off + lead
    elif rest.startswith("@"):
        raise SassSyntaxError("谓词前缀写法不对，应形如 @P0 / @!UP1 / @PT",
                              rest_off, rest_off + 4)

    m = re.match(r"[A-Za-z_][\w.?]*", rest)
    if not m:
        raise SassSyntaxError("缺少助记符", rest_off, rest_off + max(1, len(rest)))
    op = m.group()
    parts = op.split(".")
    ins.mnemonic, ins.modifiers = parts[0], parts[1:]
    ops_text = _sbset(rest[m.end():])
    ins.operands = _OperandParser(
        tokenize(ops_text, rest_off + m.end()), ops_text,
        ins.mnemonic, rest_off + m.end()).operands()
    return ins


def parse_line(text: str, lineno: int = 0, *, require_ctrl: bool = False) -> Line:
    """一整行源码 -> `Line`。空行/纯注释行三个形态都是 None。"""
    line = Line(col=0, end=len(text), lineno=lineno, text=text)
    code, comment = _strip_comment(text)
    line.comment = comment
    body = code.strip()
    if not body:
        return line
    off = len(code) - len(code.lstrip())
    m = _LABELDEF.match(body)
    if m:
        line.label = LabelDef(col=off, end=off + len(body), name=m.group(1))
        return line
    if body.startswith(".") and not body.startswith(".L"):
        toks = body.split()
        line.directive = Directive(col=off, end=off + len(body),
                                   name=toks[0], args=toks[1:])
        return line
    line.insn = parse_instruction(code, 0, require_ctrl=require_ctrl)
    return line


# ---------------------------------------------------------------------------
# AST -> 段表坐标（key / vals / modi / tags）
# ---------------------------------------------------------------------------

#: 用得上「本指令地址」的 opcode，同 CuInsParser 的 `c_AddrFuncs`。
_ADDR_FUNCS = {"BRA", "BRX", "BRXU", "CALL", "JMP", "JMX", "JMXU", "RET",
               "WARPSYNC",
               "BSSY", "SSY", "CAL", "PRET", "PBK"}
#: 公开别名 —— `model/keys.py` 的分支标号归一要用同一份名单。
ADDR_FUNCS = _ADDR_FUNCS
#: sm_90 上偏移被劈成两段的跳转类（复核过）。
_SPLIT_ADDR = {"BRA", "BRX", "BRXU", "CALL", "JMP", "JMX", "JMXU", "RET",
               "WARPSYNC"}
#: 文本立即数已经是编码位移、不再减 PC 的那几个。
_NO_PC_ADJUST = {"BRX", "BRXU", "JMX", "JMXU"}
_CVT_OPCODES = {"I2F", "I2I", "F2I", "F2F", "I2FP", "I2IP", "F2IP", "F2FP", "FRND"}
_MODE_DEP_ATOMIC = {"ATOM", "ATOMG", "REDG"}
_MODE_DEP_MODIS = {"MIN", "MAX"}
_FLOAT_ATOMIC_TYPES = {"F16x2", "F16x4", "F16x8", "BF16x2", "BF16x4", "BF16x8",
                       "F32", "F32x2", "F32x4", "F64", "INVALID16"}
_DTYPES = {"S4", "S8", "S16", "S32", "S64", "U4", "U8", "U16", "U32", "U64",
           "F16", "F32", "F64"}
#: 位置相关修饰符（`F2F.F32.F64` ≠ `F2F.F64.F32`），sm_90 档。
_POSDEP = {"I2I": _DTYPES, "F2F": _DTYPES, "I2IP": _DTYPES, "F2FP": _DTYPES,
           "IDP": _DTYPES, "HMMA": _DTYPES, "IMMA": _DTYPES,
           "VABSDIFF": _DTYPES, "VABSDIFF4": _DTYPES,
           "TLD4": {"R", "G", "B", "A"}}
#: 浮点立即数按 opcode 精度截位，同 `CuSMVersion.FloatImmeFormat_7x_8x`。
_FLOAT_FMT = {"H": ("e", "H", 16, 16), "F": ("f", "I", 32, 32),
              "D": ("d", "Q", 64, 32)}
_INSN_LEN = 16


@dataclass
class LowerResult:
    key: str
    vals: list[int]
    modi: list[str]
    tags: list[str]


def _float_value(ins: Instruction, node: Imme) -> int:
    """浮点立即数 -> 位模式。精度看 opcode 首字母（`H`/`F`/`D`）。"""
    p = ins.mnemonic[0]
    if p in _FLOAT_FMT:
        prec = p
    elif ins.mnemonic in ("MUFU", "RRO"):
        full = ins.opcode_full
        prec = "D" if "64" in full else ("H" if "16" in full else "F")
    else:
        raise SassSyntaxError(
            f"{ins.mnemonic} 的浮点立即数精度未知（{node.text}）", node.col, node.end)
    text = node.text.lower().strip()
    if text.startswith("0f") or text.startswith("-0f"):
        return int(text.lstrip("-")[2:], 16)
    ifmt, ofmt, fullbits, keepbits = _FLOAT_FMT[prec]
    # nvdisasm 的 QNAN 拼写不是 Python 浮点字面量。它对应 all-ones
    # mantissa（`-QNAN` 是 0xffffffff for F32），不是 Python 默认给 NAN
    # 的 0x7fc00000；保留这个精确位型才能重建 FSEL 的生产样本。
    sign = 1 if text.startswith("-") else 0
    bare = text.lstrip("+-")
    if bare in ("qnan", "nan"):
        # Build the *source-precision* payload first, then truncate.  D
        # immediates keep their high 32 bits; constructing an F32 NAN/INF
        # directly is a coordinate error shared by every D* instruction.
        ival = (1 << fullbits) - 1
        return (ival >> (fullbits - keepbits)) | (sign << (keepbits - 1))
    if bare == "inf":
        exponent = {16: 5, 32: 8, 64: 11}[fullbits]
        mantissa = {16: 10, 32: 23, 64: 52}[fullbits]
        ival = (sign << (fullbits - 1)) | (((1 << exponent) - 1) << mantissa)
        return ival >> (fullbits - keepbits)
    ival = struct.unpack(ofmt, struct.pack(ifmt, float(text)))[0]
    trunc = fullbits - keepbits
    return ival >> trunc if trunc > 0 else ival


def _int_imme(ins: Instruction, value: int) -> tuple[int, list[str]]:
    """负立即数要不要挂 `NegIntImme` —— 跳转目标不挂。"""
    if value >= 0 or ins.mnemonic in _ADDR_FUNCS:
        return value, []
    return value, ["NegIntImme"]


def _lower_addr(ins: Instruction, a: Addr) -> tuple[str, list[int], list[str], list[str]]:
    """地址 -> `('A[R][UR]I', vals, modi, tags)`。**立即数永远补齐**：
    段表按「有这一列」标定的，没写就是 0（`_align_omitted_addr_reg` 同源）。"""
    optype, vals, modi, tags = "A", [], [], []
    if a.reg is not None:
        optype += "R"
        vals.append(a.reg.index)
        modi += [f"R.{m}" for m in a.reg.modifiers]
        tags.append("R.Addr")
    if a.ureg is not None:
        optype += "UR"
        vals.append(a.ureg.index)
        modi += [f"UR.{m}" for m in a.ureg.modifiers]
        tags.append("UR.Addr")
    optype += "I"
    if a.imm is not None:
        v, m = _int_imme(ins, a.imm.value)
        vals.append(v)
        modi += m + list(a.imm.modifiers)
    else:
        vals.append(0)
    tags.append("Imme.Addr")
    return optype, vals, modi, tags


def _lower_operand(ins: Instruction, node: Node) -> tuple[str, list[int], list[str], list[str]]:
    if isinstance(node, Reg):
        return (node.label, [node.index], list(node.pre) + list(node.modifiers),
                [node.label])
    if isinstance(node, Imme):
        if node.is_float:
            return "FI", [_float_value(ins, node)], list(node.modifiers), ["FI"]
        v, m = _int_imme(ins, node.value)
        return "II", [v], m + list(node.modifiers), ["II"]
    if isinstance(node, Addr):
        return _lower_addr(ins, node)
    if isinstance(node, ConstMem):
        atype, avals, amodi, atags = _lower_addr(ins, node.addr)
        if node.ubank is not None:
            return ("cx" + atype, [node.ubank.index] + avals,
                    [f"UR_{m}" for m in node.ubank.modifiers] + amodi
                    + list(node.pre) + list(node.modifiers),
                    ["UR.CBank"] + atags)
        return ("c" + atype, [node.bank] + avals,
                list(node.pre) + list(node.modifiers) + amodi,
                ["Imme.CBank"] + atags)
    if isinstance(node, DescAddr):
        atype, avals, amodi, atags = _lower_addr(ins, node.addr)
        return ("d" + atype, [node.ureg.index] + avals,
                amodi + list(node.pre) + list(node.modifiers),
                ["UR.Desc"] + atags)
    if isinstance(node, Label):
        return "L", [], [node.text], []
    raise SassSyntaxError(f"不认识的操作数节点 {type(node).__name__}",
                          node.col, node.end)


def _special(ins: Instruction, key: str, vals: list[int], modi: list[str],
             addr: int) -> tuple[list[int], list[str]]:
    """CuInsParser `__specialTreatment` 的等价物 —— 段表列序约定的一部分。"""
    op, full = ins.mnemonic, ins.opcode_full
    if op in _CVT_OPCODES:
        if "64" in full:
            modi.append("0_CVT64")
    elif op in _ADDR_FUNCS and key.endswith("_II") and "ABS" not in full:
        if op in _NO_PC_ADJUST:
            off = vals[-1]                      # 已经是编码位移，不再减 PC
        else:
            off = vals[-1] - addr - _INSN_LEN
        if op in _SPLIT_ADDR:
            # sm_90 的分支偏移是不连续字段（bit 16:24 + 34:82）。这里只做和
            # 段表同一套的打包；真正落位由 `asm_spec` 的 `slot_facts` 决定，
            # CuAssembler 那一列值在 `asm_spec` 里连看都不看。
            u = off & ((1 << 58) - 1)
            off = (u & 0x3FF) | ((u >> 10) << 20)
        elif off < 0:
            modi.append("0_NegAddrOffset")
        vals[-1] = off

    if op in _MODE_DEP_ATOMIC:
        is_float = any(m.startswith("0_") and m[2:] in _FLOAT_ATOMIC_TYPES
                       for m in modi)
        suffix = "@F" if is_float else "@I"
        for i, m in enumerate(modi):
            if m.startswith("0_") and m[2:] in _MODE_DEP_MODIS:
                modi[i] = m + suffix

    if op in _POSDEP:
        counter = 0
        for i, m in enumerate(modi):
            if m.startswith("0_") and m[2:] in _POSDEP[op]:
                modi[i] += "@%d" % counter
                counter += 1
    return vals, modi


def lower(ins: Instruction, addr: int = 0) -> LowerResult:
    """`Instruction` -> 段表坐标里的 `(key, vals, modi, tags)`。

    `vals[0]` 永远是谓词槽（`P.Guard`，无谓词 = `PT` = 7），后面按操作数从左到
    右展开；`modi` 里的 `n_` 前缀是列号（0 = opcode 自己）。`addr` 只有 PC 相对
    跳转用得上，其余指令不参与任何计算。
    """
    pred_val = ins.pred.value if ins.pred is not None else 7
    key = ins.mnemonic
    vals = [pred_val]
    tags = ["P.Guard"]
    modi = ["0_" + m for m in [ins.mnemonic] + ins.modifiers]
    for i, node in enumerate(ins.operands):
        optype, opval, opmodi, optag = _lower_operand(ins, node)
        key += "_" + optype
        vals.extend(opval)
        tags.extend(optag)
        modi.extend(f"{i + 1}_{m}" for m in opmodi)
    vals, modi = _special(ins, key, vals, modi, addr)
    return LowerResult(key, vals, modi, tags)


def parse(text: str, addr: int = 0) -> tuple[str, list[int], list[str], list[str]]:
    """`parse_instruction()` + `lower()` 的便捷包装（`asm_spec` 的入口）。"""
    r = lower(parse_instruction(text), addr)
    return r.key, r.vals, r.modi, r.tags
