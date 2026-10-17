"""文本 ⇄ 语义值的通用翻译层。

`asm.py` 是模板补丁：只认 `[@pred] MNEMONIC Rd, Ra, Rb, Rc[.reuse]`，立即数/
常量 bank/地址形式/枚举修饰符一律拒绝。`encode.py`证明了"编码的每一位都从
段表 + fieldscan 现查、不需要模板"这条路可行，但吃的是语义值（`{cells, mods}`），
不是 SASS 文本。这里补上中间这层翻译：

    text_to_values(key, text)  ->  values   （喂给 encode_spec）
    values_to_text(key, values) -> text     （编码后交给 nvdisasm 读回）

**文本的拆分交给本项目自己的 `sass_parser.py`。** 早期版本先是手写了一整套
R/UR/P/UP/地址形式的行级正则，漏掉一堆形式（寄存器取反 `-R2`、绝对值 `|R7|`、
双寄存器地址 `[R0+UR4]`、`desc[][]` 描述符、分支符号标号）；随后改为借
CuAssembler 的 `CuInsParser` 拆文本，形式是齐了，但把 `import CuAsm` 焊进了
产品代码。源码模式不得依赖它，于是 `sass_parser.py` 用
tokenizer + 递归下降重写了这一层，产出带源码 span 的 AST，`lower()` 再把 AST
摊平成段表的列坐标（`slot`/`tag`）。两边在语料全量 922 条文本上逐条对齐过。

**摆位的规则仍然是这个项目自己验过的段表**，与解析器换不换无关 —— 早就验过
CuAssembler 解出来的权重（`vals`/`modi` 怎么摆进 128 位）不可信，
本项目从来只借「文本怎么拆成列」这个约定，权重判断从没经过它。

渲染方向同理：`values_to_text()` 编码之后直接交给 nvdisasm 读回，不自己
拼字符串猜它会怎么打印——decode 方向从来不需要"猜 nvdisasm 怎么写"，
这里也不需要。

**范围**（不奢求 100%）：段表/fieldscan
解释到的每一位都能从文本正确摆进去；没被解释到的位（往返测量里约 36%，
`LEA` 的 `.HI`/`.SX32` 这类）文本层给不出信息，只能照 `_carry_cells()`
填默认值。分支/返回目标的符号标号（`` `(.L_x) ``）parser 认得出但不解析成
地址，编码需要的数值地址不在指令自己身上，留给下面的分支目标处理。
"""
from __future__ import annotations

import re


class AsmSpecError(ValueError):
    pass


#: 编码时可以填 0 的位，同 `encode.py.ZEROABLE`——只有 `dontcare` 有正面证据。
_ZEROABLE = ("dontcare",)
_NCODE = 105          # 控制段起点，同 `encode.py.NCODE`
_PAD_CTRL = 0x7E0     # common.with_ctrl 的良性控制码；全零会让部分指令非法


def _base_code(key: str) -> int | None:
    """该 key 的基底编码 —— fieldscan 扫这个 key 时用的那条真实指令。

    `repos.code` 是从语料里取的合法编码，所以它的每一位都是"这个 key 至少
    有一条真指令这么填"的正面证据。段表解释不到的位拿它兜底，比填 0 强：
    填 0 是在断言"这位不重要"，而那正是我们不知道的事。
    """
    from cubin_sass import fieldscan
    code = (fieldscan().get(key, {}).get("repos") or {}).get("code")
    return None if code is None else int(code)


def _carry_cells(key: str, mod_bits: set) -> dict[tuple, int]:
    """operand/enum 之外的格子——**指令身份**的一部分，不是文本能带出来的。

    多数是 `const`（opcode）：值是 key 的固有属性，抄段表的 `value` 字段。
    `dc_safe`/`hwcare`/`unknown` 这类段表没有稳定取值可抄，改**抄基底编码的
    对应位**（`_base_code()`），抄不到才填 0。

    原来一律填 0。`F2F_R_R` 的 bit 76 / 84 恒为 1、段表解释不到，于是
    `F2F.F32.F64 R21, R12` 这条基底自己能编对（走的是另一条路），一旦带上
    `.RM` / `-R12` / `.FTZ` 就落到这里被清零 —— 实测 40 条合法编码只能重现
    23 条，失败的 17 条全是这个原因，与 fieldscan 缺不缺字段无关。
    """
    base = _base_code(key)
    out = {}
    for c in _cells(key):
        if c["kind"] in ("operand", "enum"):
            continue
        lo, hi = c["bits"]
        if c["kind"] == "ctrl" and lo < 122 and hi > _NCODE:
            out[(lo, hi)] = (_PAD_CTRL >> max(0, lo - _NCODE)) & _mask(hi - lo)
            continue
        if c["kind"] in _ZEROABLE and lo < _NCODE:
            continue
        if set(range(lo, hi)) <= mod_bits:
            continue
        v = c.get("value")
        if v is None and base is not None and hi <= _NCODE:
            v = (base >> lo) & _mask(hi - lo)
        out[(lo, hi)] = v or 0
    return out


def _cells(key: str) -> list[dict]:
    from cubin_sass import segtable
    return segtable()[key]["cells"]


def _fs_fields(key: str) -> list[dict]:
    from cubin_sass import fs_enum_fields
    return fs_enum_fields(key, None)          # mode 0：文本层没有编码可供选模式


def enum_fields(key: str, modi: list[str] | None = None) -> list[dict]:
    """该 key 的全部枚举/修饰符字段，fieldscan 为准，段表补它没测到的。

    每条 `{"bit_list": [...], "tokens": {raw: (modi_token, ...)}}`——
    `tokens` 的空元组表示默认档；非空的 token 字符串**原样**是 fieldscan 扫
    出来的那套拼写（`"2_cNEG"` 这种，数字前缀是操作数列号），直接拿去和
    `_parse()` 返回的 `modi` 做字符串相等比较，不剥前缀——剥了就跟段表对不上。
    """
    from cubin_sass import _LABEL_DEFAULT
    out, covered = [], set()
    for f in _fs_fields(key):
        bl = tuple(f["bit_list"])
        toks = {raw: (() if label == _LABEL_DEFAULT else tuple(label.split()))
                for raw, label in f["values"].items()}
        out.append({"bit_list": bl, "tokens": toks, "mode": f.get("mode", 0)})
        covered |= set(bl)

    # 文本编码手里没有原编码，不能像 decode 侧那样按 opcode 选择位调用
    # pick_mode()。但 modifier token 本身能给出单向的确定信息：如果 mode 0 的
    # 字段全集根本表达不了 `.HI`，而 mode 1 的重叠字段明确含 `0_HI`，就应使用
    # mode 1。只在“当前表无法表达 token”时替换，避免 `.WIDE` 这种多个 mode
    # 都出现的名字被武断改道。
    if modi:
        from cubin_sass import fieldscan
        known = {t for f in out for ts in f["tokens"].values() for t in ts}
        missing = set(modi) - known
        entries = [f for f in fieldscan().get(key, {}).get("fields", [])
                   if f.get("mode", 0) and not f.get("skipped") and f.get("values")]
        for f in sorted(entries, key=lambda x: x.get("mode", 0)):
            bl = tuple(f.get("bit_list") or range(*f["bits"]))
            toks = {int(raw): (() if names == [] else tuple(names))
                    for raw, names in f["values"].items() if names is not None}
            universe = {t for ts in toks.values() for t in ts}
            if not (missing & universe):
                continue
            out = [old for old in out if not (set(old["bit_list"]) & set(bl))]
            out.append({"bit_list": bl, "tokens": toks, "mode": f.get("mode", 0)})
            covered |= set(bl)
            known |= universe
            missing -= universe
    for c in _cells(key):
        if c["kind"] != "enum":
            continue
        lo, hi = c["bits"]
        bits = tuple(range(lo, hi))
        if set(bits) & covered:
            continue
        toks = {int(v): (() if n == "" else tuple(n.split()))
                for v, n in (c.get("values") or {}).items()}
        out.append({"bit_list": bits, "tokens": toks, "mode": 0})
    return out


def semantic_profile(key: str, modi: list[str]) -> dict | None:
    """选出一个由段表样本自动收敛的联合枚举 profile。

    profile 按完整 token 集精确匹配，不凭单个同名 token 猜测；因此它能表达
    “一个 token 写多段位”，又不会把 IMAD 的 `.MOV` 之类 mode 别名误复制。
    没有唯一匹配时返回 None，由字段层和最终 nvdisasm 回环维持失败安全。
    """
    from cubin_sass import segtable
    base = '0_' + key.split('_', 1)[0]
    want = sorted(set(m for m in modi if m != base))
    hits = [p for p in (segtable().get(key) or {}).get('semantic_profiles', [])
            if p.get('tokens') == want]
    return hits[0] if len(hits) == 1 else None


def operand_cells(key: str) -> list[dict]:
    """按 slot 排序的 operand 格，含 `P.Guard`——谓词前缀在这套列坐标里也是
    普通一列（`vals[0]`，见 `sass_parser.lower()`），不用单独摘出来处理。

    同一个 `(slot, tag)` 可能在段表里被劈成好几个不连续的位段——`IMAD.MOV`
    的立即数曾被一个插在中间的 `.MOV` 模式选择位隔断成 `[32,34)`+`[35,64)`
    两截（现已在段表源头修复）。这里按 `(slot, tag)` 归并成一个
    逻辑操作数，`ranges` 按位置从低到高排——**低位段放整数值的低位**。
    """
    raw = [c for c in _cells(key) if c["kind"] == "operand"]
    groups: dict[tuple, dict] = {}
    for c in raw:
        k = (c.get("slot"), c.get("tag"))
        g = groups.setdefault(k, {"slot": c.get("slot"), "tag": c.get("tag"), "ranges": [],
                                  "implicit": c.get("implicit", False),
                                  "default": c.get("default")})
        g["ranges"].append(tuple(c["bits"]))
    out = list(groups.values())
    for g in out:
        g["ranges"].sort()
    return sorted(out, key=lambda c: (c["slot"] if c["slot"] is not None else 1 << 30,
                                       c["ranges"][0][0]))


def _ranges(c: dict) -> list[tuple]:
    return c["ranges"]


def _mask(width: int) -> int:
    return (1 << width) - 1


def _set_composite(cells: dict, c: dict, value: int) -> None:
    """把一个整数按 `ranges` 从低位到高位拆开填回 `cells` 字典。
    `value & mask` 天然处理负数（Python 的按位与对负数是无限位二补码），
    parser 给负的立即数就是普通负 Python int（`-0x55555555` 这种）。
    """
    shift = 0
    for lo, hi in _ranges(c):
        w = hi - lo
        cells[(lo, hi)] = (value >> shift) & _mask(w)
        shift += w


def _get_composite(cells: dict, c: dict, default: int = 0) -> int:
    """`_set_composite` 的反向：把 `ranges` 各段拼回一个整数。"""
    v, shift = 0, 0
    for lo, hi in _ranges(c):
        w = hi - lo
        v |= (cells.get((lo, hi), default) & _mask(w)) << shift
        shift += w
    return v


def parse_ast(text: str):
    """SASS 文本 -> `sass_parser.Instruction`（带源码 span 的 AST）。

    编辑器要的诊断位置、源码模式的整段解析都走这里；`text_to_values()` 只是
    在它后面接一层「AST -> 段表列坐标」。
    """
    from nvisa.model.sass_parser import SassSyntaxError, parse_instruction
    try:
        return parse_instruction(text.strip().rstrip(";"))
    except SassSyntaxError as exc:
        raise AsmSpecError(f"解析失败：{text!r}：{exc}") from exc


def _parse(text: str, addr: int = 0) -> tuple[str, list[int], list[str], list[str]]:
    """AST 摊平成 `(InsKey, vals, modi, tags)` —— 段表 `cells` 的列坐标。

    `vals` 按操作数列顺序给出**语义值**（寄存器号、谓词槽的 `idx|neg<<3`、
    立即数——负数就是负的 Python int，`c[][]`/`desc[][]` 的每个子部分各占
    一列），列号多数时候与段表 `cells` 里的 `slot` 一一对应；`tags` 是每一列的
    操作数标签（`'R'`/`'Imme.Addr'`……），键不上时（见 `text_to_values` 的地址
    省略寄存器分支）靠它对齐。`modi` 是字符串列表：助记符基名（`'0_IMAD'`）、
    真修饰符（`'0_WIDE'`）、取反/绝对值（`'2_cNEG'`/`'3_cABS'`）、`.reuse`
    （`'2_reuse'`）、特殊寄存器名（`'2_SR_TID.X'`）、没法转成地址的符号标号都
    混在一起，靠字符串匹配到段表的字段表去认，认不出的原样丢弃。
    """
    from nvisa.model.keys import normalize_key
    from nvisa.model.sass_parser import SassSyntaxError, lower
    ast = parse_ast(text)
    try:
        r = lower(ast, addr)
    except SassSyntaxError as exc:
        raise AsmSpecError(f"解析失败：{text!r}：{exc}") from exc
    # 分支标号归一到 PC 相对立即数形态：AST 保留 `L`，
    # 编码层只有 `II` 这一种布局。归一之后 `vals`/`tags` 仍然少了目标那一列
    # ——标号的地址不在指令身上，得由符号表补；`text_to_values()` 会先拦下来。
    return normalize_key(r.key), r.vals, r.modi, r.tags


def _align_omitted_default_operand(key: str, target: list[dict],
                                   parsed_tags: list[str], vals: list[int]) -> list[int] | None:
    """对齐 parser 因省略默认操作数而另起的 InsKey。

    最初这里只处理“地址省略了基址寄存器”——
    `c[0x0][0x28]`（无基址寄存器）是 `LDC_R_cAI`，`c[0x0][R2+0x28]` 是
    `LDC_R_cARI`，两者列数都不同。这个项目自己的段表把两种情况按同一个
    key 处理（省略的寄存器就是 `RZ`：寄存器槽的中性值是
    全 1，不是 0）。实测 LEA 的普通 R/UR 进位槽也会以同样方式省略。
    这里把 `parsed_tags`/`vals` 对齐到 `target_tags`。除了地址基址 RZ/URZ，
    nvdisasm 还会省略末尾或中间的 PT/UPT（例如 HFMA2 的条件谓词、IADD3 的
    carry 谓词）。段表的长 form 仍保留那些列，必须补回该 form 已验证的默认值。

    不是见到 P 就无条件补：只接受“已解析列是目标列序列的子序列”，且所有被
    跳过的目标列都必须有已知的中性值；若存在多种不同对齐，宁可返回 `None`。
    这保留了 LEA 等物理谓词字段的失败安全性，也不会放行跨助记符的形态误配。
    """
    target_tags = [c["tag"] for c in target]
    static = {"R": 255, "UR": 63, "R.Addr": 255, "UR.Addr": 63}
    base = _base_code(key)

    def default_at(i: int) -> int | None:
        tag = target_tags[i]
        if tag in static:
            return static[tag]
        # P/UP 的“没打印”不是统一的 7：有的 field 表示 PT，有的表示 P3，
        # 还有的在该 form 中是固定 P0。fieldscan 的基底正是这个 form 的真
        # 指令，取其已实测位值而不臆测一套跨 form 编码。
        if tag not in ("P", "UP") or base is None:
            return None
        return _get_composite({r: (base >> r[0]) & _mask(r[1] - r[0])
                               for r in _ranges(target[i])}, target[i])
    candidates: dict[tuple[int, ...], int] = {}

    def walk(ti: int, pi: int, out: tuple[int, ...], inserted: int) -> None:
        if ti == len(target_tags):
            if pi == len(parsed_tags):
                old = candidates.get(out)
                candidates[out] = inserted if old is None else min(old, inserted)
            return
        tag = target_tags[ti]
        if pi < len(parsed_tags) and parsed_tags[pi] == tag:
            walk(ti + 1, pi + 1, out + (vals[pi],), inserted)
        default = default_at(ti)
        if default is not None:
            walk(ti + 1, pi, out + (default,), inserted + 1)

    walk(0, 0, (), 0)
    if not candidates:
        return None
    best = min(candidates.values())
    winners = [out for out, n in candidates.items() if n == best]
    return list(winners[0]) if len(winners) == 1 else None


def spec_keys(text: str, hint: str | None = None,
              limit: int | None = None) -> list[str]:
    """这条文本可能对应的 InsKey，按可信度排序（段表认识的才留）。

    parser 自己拼出来的 key 排第一；`hint`（编辑位置上原指令认出的 key）
    次之——它常常正是要改的那条 form；再补同助记符的其它 form，因为按文本
    形态拼出来的 key 比段表细（省略的默认操作数列会另起一个
    key），parser 给的名字未必在段表里。

    **默认整枚举，不截断**：原先固定只留 4 个
    候选，而段表里同一个助记符最多有 15 个 form（LEA），截断有可能把正确的那个
    切掉，且切掉时无声无息。消费侧（`_assemble_spec`）对每个候选都要过 nvdisasm
    回环，猜错的候选会被回环挡住，所以多试几个只花时间不损正确性。`limit` 仍然
    保留，给需要限流的调用方显式指定。
    """
    from cubin_sass import segtable
    seg = segtable()
    pkey, _, _, _ = _parse(text)          # 已按 §1.3 归一：`BRA_L` -> `BRA_II`
    mn = pkey.split("_", 1)[0]
    out = [k for k in (pkey, hint) if k and k in seg and k.split("_", 1)[0] == mn]
    out = list(dict.fromkeys(out))
    out += sorted(k for k in seg
                  if k.split("_", 1)[0] == mn and k not in out)
    return out[:limit] if limit is not None else out


# --- 分支目标 ---------------------------------------------------------
#
# PC 相对分支的文本坐标分两类：绝对目标形式是
# `(目标 - 本指令地址 - 16) / 4` 的两补码；BRX 则保留文本里的相对偏移。
# 位段都散在 16:24 和 34:82 两截。这条合成规则是手工解出、
# 逐位复测过的，存在段表的 `slot_facts` 里；这里把它
# 消费掉，让文本层能直接填地址。
#
# **parser 摊平出来的那一列值在这里不能用**：`BRA 0x1230` 它按 CuAssembler 的
# 老约定算出 0x400220（`sass_parser._special()` 复刻了那套打包，只为让 key 和
# 列数对得上段表）—— 早就验过那套权重不可信，这里连一眼都不看，偏移
# 完全按 `slot_facts` 自己算。

#: 目标写成 `` `(.L_x_0) `` 这种符号标号时，地址不在指令自己身上。
_LABEL = re.compile(r"`\(")
#: nvdisasm 打印的目标/偏移：一行的最后一个数（`BRA 0x30`、`BRX R18 -0x320`）。
_TAIL_NUM = re.compile(r"(-?0x[0-9a-fA-F]+|-?\d+)\s*;?\s*$")


def pc_offset_fact(key: str) -> dict | None:
    """这个 key 的 PC 相对偏移规则（没有就返回 None，绝大多数指令都没有）。"""
    from cubin_sass import segtable
    for f in (segtable().get(key) or {}).get("slot_facts", []):
        if f.get("kind") == "pc_offset":
            # Published JMP facts predates the direct nonzero-address probe.
            # JMP prints its encoded displacement (zero stays ``0x0`` at
            # addresses 0, 0x10 and 0x20), not a PC+16 target like BRA.
            # Keep older generated tables compatible until their facts are
            # regenerated with text_coordinate explicitly set.
            if key.split("_", 1)[0] == "JMP" and not f.get("text_coordinate"):
                return {**f, "text_coordinate": "relative_offset",
                        "relative_to": "current_insn"}
            return f
    return None


def _fact_bits(fact: dict) -> list[int]:
    """规则声明的位，低位在前。"""
    dead = set(fact.get("dead_bits", ()))
    return sorted(b for lo, hi in fact["bits"]
                  for b in range(lo, hi) if b not in dead)


def _is_absolute(text: str) -> bool:
    """`.ABS` 的目标就是绝对地址，不减本指令地址 —— 同一个 key（`CALL_II`）
    下 `.REL` 和 `.ABS` 共用同一批位，差别只在怎么解释，所以只能看文本。"""
    return ".ABS" in (text or "").upper()


def target_of(text: str) -> int | None:
    """从文本里取分支目标。符号标号返回 None（地址不在指令身上）。"""
    body = (text or "").strip().rstrip(";").strip()
    if _LABEL.search(body):
        return None
    m = _TAIL_NUM.search(body)
    return int(m.group(1), 0) if m else None


def offset_value(fact: dict, target: int, addr: int, absolute: bool = False) -> int:
    """文本坐标 -> 该槽要填的整数（两补码，还没散进各段）。

    默认文本坐标是绝对目标地址（BRA/CALL 的形式）。间接相对分支如
    BRX 的 nvdisasm 操作数本身就是相对偏移，所以由 fact 明确标成
    ``relative_offset``，不能再减一次 PC。
    """
    relative_text = fact.get("text_coordinate") == "relative_offset"
    raw = target if absolute or relative_text else target - addr - fact["insn_len"]
    if raw % fact["scale"]:
        raise AsmSpecError(
            f"分支目标 {target:#x} 不是 {fact['scale']} 的倍数（最低两位不进编码）")
    v = raw // fact["scale"]
    bits = _fact_bits(fact)
    if v < 0:
        if fact.get("sign_bit") is None:
            raise AsmSpecError(
                f"这个 key 的符号位没验过（slot_facts.sign_bit 是 null），"
                f"负偏移 {raw:#x} 编不了")
        v += 1 << len(bits)
    if not 0 <= v < (1 << len(bits)):
        raise AsmSpecError(f"分支目标 {target:#x} 放不下（偏移字段 {len(bits)} 位）")
    return v


def read_offset(fact: dict, enc: str) -> int:
    """从**已有编码**里把 PC 相对偏移读出来（字节，已乘 scale、已解两补码）。

    这里不加 `insn_len` —— 给的是「相对下一条指令」的那个偏移本身。
    """
    from nvisa.oracle.cubin import get_bits
    bits = _fact_bits(fact)
    v = 0
    for i, b in enumerate(bits):
        v |= get_bits(enc, b, b) << i
    if fact.get("sign_bit") is not None and v >> (len(bits) - 1):
        v -= 1 << len(bits)
    return v * fact["scale"]


def write_offset(fact: dict, enc: str, delta: int) -> str:
    """把偏移（字节，相对下一条指令）写回编码。规则声明之外的位一位不动 ——
    插入/删除挪指令时改的只是偏移，别的位（opcode、控制段、谓词）必须原样。"""
    from nvisa.oracle.cubin import set_bits
    if delta % fact["scale"]:
        raise AsmSpecError(f"偏移 {delta:#x} 不是 {fact['scale']} 的倍数")
    bits = _fact_bits(fact)
    v = delta // fact["scale"]
    if v < 0:
        if fact.get("sign_bit") is None:
            raise AsmSpecError("这个 key 的符号位没验过，负偏移写不了")
        v += 1 << len(bits)
    if not 0 <= v < (1 << len(bits)):
        raise AsmSpecError(f"偏移 {delta:#x} 放不下（{len(bits)} 位）")
    for i, b in enumerate(bits):
        enc = set_bits(enc, b, b, (v >> i) & 1)
    return enc


def rebase(key: str, text: str, addr: int) -> str:
    """把 nvdisasm 单条反汇编（基址 0）打印的目标改写成 `addr` 处的绝对地址。

    单条反汇编时 nvdisasm 以为这条指令在地址 0，打印的是 `off + 16`；同一条
    编码摆在 `addr` 上，目标是 `addr + 16 + off` —— 正好差一个 `addr`。回环
    校验要拿它跟用户输入的绝对地址比，不然每条分支都会「读回不符」。
    `.ABS`、相对偏移形式、非分支、符号标号一律原样返回。
    """
    fact = pc_offset_fact(key)
    if (not fact or not addr or _is_absolute(text)
            or fact.get("text_coordinate") == "relative_offset"):
        return text
    body = (text or "").strip().rstrip(";").strip()
    m = _TAIL_NUM.search(body)
    if not m:
        return text
    v = int(m.group(1), 0) + addr
    return body[:m.start(1)] + (f"-{-v:#x}" if v < 0 else f"{v:#x}")


def text_to_values(key: str, text: str, addr: int = 0) -> dict:
    """SASS 文本 -> `encode_spec()` 要的 `values`。

    不从文本解析调度控制段（那是 `asm.py:FIELDS` / `assemble_at()` 的地盘）；这里只填
    nvdisasm 可接受的良性控制码，避免全零控制码让部分指令直接非法。

    `addr` 是这条指令自己的地址（段内，与编辑器 addr 列同一套坐标）。默认
    PC 相对分支文本里写的是**目标地址**，编码里存的是相对下一条指令的偏移，
    两者差 `addr + 16`。标成 `text_coordinate=relative_offset` 的间接
    分支文本里已经是偏移，`addr` 不参与换算。其余指令 `addr` 不参与任何计算。
    """
    fact = pc_offset_fact(key)
    if (fact or _LABEL.search(text or "")) and target_of(text) is None:
        # 先于 key 比对报出来：标号形式的 key 已经归一成 `BRA_II`（§1.3），
        # 不拦的话报出来的会是列数对不上，说不出真正的原因。
        raise AsmSpecError(
            f"分支目标是符号标号（{text!r}）—— 标号的地址不在指令自己身上，"
            f"需要汇编器的符号表；请直接填数值地址（段内绝对地址）")

    pkey, vals, modi, parsed_tags = _parse(text)
    if pkey != key:
        if pkey.split('_', 1)[0] != key.split('_', 1)[0]:
            raise AsmSpecError(f"{text!r} 解析出的形态是 {pkey}，不是 {key}")
        target = operand_cells(key)
        aligned = _align_omitted_default_operand(key, target, parsed_tags, vals)
        if aligned is None:
            raise AsmSpecError(f"{text!r} 解析出的形态是 {pkey}，不是 {key}")
        vals = aligned
    modi = list(modi)

    fact_slots = {c["slot"] for c in operand_cells(key)
                  if fact and c["tag"] == fact.get("tag")} if fact else set()

    cells: dict[tuple, int] = {}
    reuse_slots: list[int] = []
    for c in operand_cells(key):
        slot = c["slot"]
        if c.get("implicit"):
            # 短 form 的源码没有这一列；非中性值由另一条长 form 表达。
            _set_composite(cells, c, c.get("default", 0))
            continue
        if slot in fact_slots:
            # 分支目标。parser 那一列值不要（见本文件「分支目标」段的注释），
            # 按 slot_facts 自己算，并且**只写规则声明的那些位** —— `CALL_II`
            # 的槽比规则多一位（符号位没验过，段表把它算进槽、规则没算），
            # 那一位留 0，别当成符号扩展写出去。
            v = offset_value(fact, target_of(text), addr, _is_absolute(text))
            _set_composite(cells, c, 0)
            for i, b in enumerate(_fact_bits(fact)):
                lo, hi = next((lo, hi) for lo, hi in _ranges(c) if lo <= b < hi)
                cells[(lo, hi)] = ((cells[(lo, hi)] & ~(1 << (b - lo)))
                                   | (((v >> i) & 1) << (b - lo)))
            continue
        if slot is None:
            # 段表自己没定这一列的槽号（`(探测)` 这类未定案格子，以及
            # `IMAD_R_R_R_R` 的 bit 81-84 那种认出 tag 却没配上槽的）。
            # 这跟文本缺不缺列无关 —— 文本里压根没有对应的 token 可给它，
            # 报错等于把段表的未完成状态算成使用者的错。按基底编码的对应位
            # 填过去（同 `_carry_cells()`），拿不到基底才填 0。
            b = _base_code(key)
            for lo, hi in _ranges(c):
                cells[(lo, hi)] = 0 if b is None else (b >> lo) & _mask(hi - lo)
            continue
        if slot >= len(vals):
            raise AsmSpecError(f"{key} 的操作数槽 {slot} 没有对应的解析值：{text!r}")
        _set_composite(cells, c, vals[slot])
        reuse_tok = f"{slot}_reuse"
        if reuse_tok in modi:
            reuse_slots.append(slot)
            modi.remove(reuse_tok)

    # 样本 profile 是字段匹配的上层约束：字段层仍负责一般文本，profile 在
    # 最后覆盖同一位组，确保联合赋值不会被“每个 token 只能消费一次”的旧规则
    # 拆散。
    profile = semantic_profile(key, modi)
    mods: dict[tuple, int] = {}
    efields = enum_fields(key, modi)

    # **解释得多的字段先挑。** token 是边匹配边从 `modi` 里划掉的，于是顺序会
    # 决定结果：`IMAD_R_R_R_R` 的 bit 0（`.MOV`/`.WIDE`）和 bit 74+75
    # （`.MOV`、`.MOV`+第 4 列取反、`.X`…）都写着 `0_MOV`，fieldscan 的天然
    # 顺序让 bit 0 先把 `0_MOV` 划走，74/75 就只剩默认档，
    # `IMAD.MOV R6, RZ, RZ, -R4` 的那个负号于是编不出来。按「这个字段最多能
    # 认下几个 token」排一遍，能解释两个的排在只能解释一个的前面。
    def _best(f):
        return max((len(ts) for ts in f["tokens"].values()
                    if ts and all(t in modi for t in ts)), default=0)

    for f in sorted(efields, key=_best, reverse=True):
        cands = sorted(f["tokens"].items(), key=lambda kv: -len(kv[1]))
        chosen = None
        for raw, tok_seq in cands:
            if tok_seq and all(t in modi for t in tok_seq):
                chosen = raw, tok_seq
                break
        if chosen is None:
            defaults = [raw for raw, ts in f["tokens"].items() if not ts]
            chosen = (defaults[0] if defaults else 0, ())
        raw, tok_seq = chosen
        for t in tok_seq:
            modi.remove(t)
        mods[f["bit_list"]] = raw

    # mode 字段只描述该字段自己的取值，不重复携带 opcode 载体的其它选择位。
    # 例如 IMAD.HI 的 mode 1 字段是 bit 1，但合法载体还要求 bit 0=1；只写
    # bit 1 会造出非法的 0x826。把所选载体的其余 select_bits 补齐，字段自身
    # 覆盖的选择位仍以 token 选出的 raw 为准。
    selected_mode = max((f.get("mode", 0) for f in efields), default=0)
    from cubin_sass import modes
    ent = modes().get(key, {})
    carriers = ent.get("carriers", [])
    if selected_mode < len(carriers):
        carrier = int(carriers[selected_mode], 16)
        own = {b for f in efields
               if f.get("mode", 0) == selected_mode for b in f["bit_list"]}
        for b in ent.get("select_bits", []):
            if b not in own:
                mods[(b,)] = (carrier >> b) & 1
    if profile is not None:
        mods.update({tuple(m['bit_list']): m['value']
                     for m in profile['mods']})
    # 剩下没认出来的 modi 项：助记符基名（'0_IMAD'）、跟着操作数值走的
    # 派生名字（'0_SHL'/'0_IADD'/'0_MOV'——实测这些没有独立的
    # 位，编不出来也不用编，值对了名字自然对）、符号标号（地址不在指令
    # 自己身上，留给分支目标处理）。宽松放过，编错的话回环校验会兜底。
    mod_bits = {b for bl in mods for b in bl}
    cells.update(_carry_cells(key, mod_bits))

    return {"cells": cells, "mods": mods, "reuse_slots": reuse_slots}


def values_to_text(key: str, values: dict, addr: int = 0) -> str:
    """语义值 -> SASS 文本。**oracle 渲染器**：先 `encode_spec()` 造出 128 位，再交给 `translate.to_sass()` ——
    那是 nvdisasm 的包装（`discache` 只落盘缓存，省进程不改判据）。decode 方向
    从来不用自己拼文本，这里也不重新发明一套规则去猜 nvdisasm 会怎么打印取反、
    地址形式这些边角写法。

    契约的三条后果，调用方按这个用：

    * 输出**就是** nvdisasm 对同一份编码的输出，一字不差；
    * 造出来的编码 nvdisasm 读不出时**抛 `TranslateError`**，不会凑一行文本
      出来（语义渲染器会——它只看段表，那样就出现「渲染得出但读不出」的中间
      状态，编辑器没法拿它当回显）；
    * 它只负责**回显**。一条编辑能不能落盘由 `assemble_at()` 定：它的
      `_assemble_spec()` 对每个候选 key 都把编码交回 nvdisasm 读一遍，与用户
      输入逐字不符就换下一个候选、全不符就整条拒绝。**nvdisasm 是最终权威**，
      这个函数不是。

    `addr` 同 `text_to_values()`：PC 相对分支的目标按这条指令实际所在的地址
    渲染成绝对地址（nvdisasm 单条反汇编时以为它在地址 0，见 `rebase()`）。
    """
    from nvisa.model.encode import encode_spec
    from nvisa.model.translate import to_sass
    return rebase(key, to_sass(encode_spec(key, values)), addr)
