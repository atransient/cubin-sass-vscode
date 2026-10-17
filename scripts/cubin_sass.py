#!/usr/bin/env python3
"""cubin -> JSON: SASS + 控制段解码 + 原始字节，供 VS Code 扩展渲染。

扩展本身不懂 ISA —— 位定义只有一份，在 nvisa.model.codec 里，这里复用它。

    python3 scripts/cubin_sass.py corpus/cubins/fma.sm_90.cubin
    python3 scripts/cubin_sass.py edited.cubin --diff original.cubin

输出（stdout，一行 JSON）：

    {"ok":true,"path":...,"sections":[{"name":".text.f","offset":1024,"size":...,
      "insns":[{"addr":160,"file_off":1184,"enc":"...","bytes":"0a0c...",
                "sass":"FFMA R12, R8, R6, R4 ;","ctrl":{...},"diff":false}]}]}

`file_off` 就是 `xxd -s <file_off> -l 16` 能直接用的偏移
（文件偏移 = .text 偏移 + 指令地址）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# Keep lazy backend imports on the same module, including Python isolated mode.
sys.modules.setdefault("cubin_sass", sys.modules[__name__])

from nvisa.model import asm                              # noqa: E402
from nvisa.model.codec import BLOCKS, decode             # noqa: E402
from nvisa.oracle.cubin import (Cubin, enc_to_bytes, enc_from_bytes,       # noqa: E402
                                enc_to_int, get_bits, set_bits)

INST_BYTES = 16
ARCH = "SM90"
_ADDR = re.compile(r"/\*([0-9a-f]{4,})\*/\s*(.*?);")

#: 控制段里值得逐条摆出来的字段（codec.BLOCKS 的子集）。加 reuse 的三位合成一个
#: 'ABC' 串 —— 逐位显示太碎，看手改 cubin 时想要的是「哪几个源命中了」。
_CTRL = ("stall", "yield", "wrbar", "rdbar", "waitmask")


#: 可编辑的字段。位置从 BLOCKS 来 —— 前端拿它做位运算，自己不硬编码任何 bit。
#: `kind` 只影响前端怎么问用户要值（寄存器可以填 RZ，掩码按二进制填）。
_EDITABLE = {
    "Rd": "reg", "Ra": "reg", "Rb": "reg", "Rc": "reg",
    "stall": "int", "yield": "int", "wrbar": "int", "rdbar": "int",
    "waitmask": "mask", "reuse.A": "bit", "reuse.B": "bit", "reuse.C": "bit",
}


def field_table() -> list[dict]:
    out = []
    for block, fields in BLOCKS:
        for f in fields:
            if f.name not in _EDITABLE:
                continue
            out.append({
                "name": f.name, "block": block, "lo": f.lo, "hi": f.hi,
                "width": f.width, "kind": _EDITABLE[f.name], "note": f.note,
            })
    return out


#: nvdisasm 的结果按输入缓存。**起一次 nvdisasm 约 0.3 秒**，而这套工装的
#: 每条路（identify -> probe_reuse_bits -> 回环 -> 复核）都会反复问同一批编码：
#: 一段里的 NOP 填充、回环校验前后同一条指令、插入/删除复核时整段逐条读回。
#: 三个函数都是**纯的**（同样的字节 -> 同样的文本，nvdisasm 不看别的），
#: 缓存不改变任何判据，只是不再为同一个问题重开一次进程。
_DIS_CACHE: dict[bytes, str] = {}
_SECTEXT_CACHE: dict[tuple[bytes, str], dict[int, str]] = {}
_CACHE_MAX = 1 << 16                    # 够装下整个语料，超了就整个丢掉重来


def _cache_put(cache: dict, key, value):
    if len(cache) >= _CACHE_MAX:
        cache.clear()
    cache[key] = value
    return value


def disasm_one(raw: bytes) -> str:
    """单条 16 字节 -> SASS。改完一条就重新问 nvdisasm，不必重扫整个文件。

    两层缓存（都只是省进程，不改判据）：进程内一张表，进程外 `discache`
    按 nvdisasm 版本落盘 —— 语料是固定的，同一批编码一天要问几十遍。
    """
    return disasm_answer(raw)[0]


def disasm_answer(raw: bytes) -> tuple[str, bool]:
    """`(文本, nvdisasm 真的回答了没有)`。要区分「解不出来」和「没法问」时用它。"""
    from nvisa.oracle import discache
    raw = bytes(raw)
    if raw in _DIS_CACHE:
        return _DIS_CACHE[raw], True
    hit = discache.get(ARCH, raw)
    if hit is not None:
        return _cache_put(_DIS_CACHE, raw, hit), True
    text, answered = _disasm_one_uncached(raw)
    if not answered:                  # nvdisasm 没装/超时的时候哪层缓存都别写 ——
        return text, False            # 那不是「这条解不出来」
    discache.put(ARCH, raw, text)
    return _cache_put(_DIS_CACHE, raw, text), True


def _disasm_one_uncached(raw: bytes) -> tuple[str, bool]:
    """`(文本, nvdisasm 真的回答了没有)`。跑不起来时第二项是 False。"""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="cubin-sass-") as d:
        p = Path(d) / "i.bin"
        p.write_bytes(raw)
        try:
            proc = subprocess.run(["nvdisasm", "-b", ARCH, str(p)],
                                  capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return "", False
        if proc.returncode != 0:
            # `nvdisasm fatal` 是工具自己不行（例如 CUDA 11.x 不认 SM90），
            # `nvdisasm error : Illegal instruction` 才是「这条读不出来」。
            if "fatal" in proc.stderr:
                return "", False
            return "", True                       # 读不出来，这也是个答案
        for line in proc.stdout.splitlines():
            m = _ADDR.search(line)
            if m:
                return " ".join(m.group(2).split()), True
    return "", True


def sass_by_addr(path: Path) -> dict[int, str]:
    """nvdisasm -c 的输出，按指令地址索引。失败返回空表（页面仍能显示字节）。

    实现在 `nvisa.oracle.discache`：按**文件内容**缓存（进程内一张表 + 按
    nvdisasm 版本落盘），因为编辑器和插入/删除都会把缓冲区写进临时文件再问一遍，
    同一个临时路径下一秒装的是别的内容 —— 按路径缓存会串味。`asm.py` 的
    模板搜索/回环校验问的是同一个问题，走的也是这一份。
    """
    from nvisa.oracle import discache
    return discache.text_by_addr(path)


def sass_by_sections(path: Path) -> dict[str, dict[int, str]]:
    """nvdisasm output keyed by section, then by section-relative address."""
    from nvisa.oracle import discache
    return discache.text_by_sections(path)


def ctrl_of(enc: str) -> dict:
    rows = {r["field"]: r for r in decode(enc)}
    ctrl = {name: {"raw": rows[name]["raw"], "effect": rows[name]["effect"]}
            for name in _CTRL if name in rows}
    bits = "".join(c for c, f in zip("ABC", ("reuse.A", "reuse.B", "reuse.C"))
                   if rows.get(f, {}).get("raw"))
    ctrl["reuse"] = {"raw": bits, "effect": f".reuse on {bits}" if bits else "none"}
    return ctrl


# ---------------------------------------------------------------------------
# segtable：把一条指令认回它的 InsKey，拿到逐格布局
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent
_SEGTABLE = _ROOT / "data" / "segtable-sm90.json"
_FIELDSCAN = _ROOT / "data" / "fieldscan-sm90.json"
_MODES = _ROOT / "data" / "modes-sm90.json"
_FORM_GRAMMAR = _ROOT / "data" / "form-grammar-sm90.json"
_seg_cache: dict | None = None
_fs_cache: dict | None = None
_mode_cache: dict | None = None
_grammar_cache: dict | None = None


def data_fingerprint() -> dict[str, str]:
    """三份 `data/` 数据的版本指纹。

    段表/fieldscan/modes 是可再生的扫描产物，重扫一次结论就可能变。回归门禁必须把当时用的是哪一版数据一起记下来，否则换了
    数据还拿旧阈值当验收依据。读不到的文件记 `"<缺失>"` —— 那本身也是一种版本。
    """
    out = {}
    for f in (_SEGTABLE, _FIELDSCAN, _MODES, _FORM_GRAMMAR):
        try:
            out[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
        except OSError:
            out[f.name] = "<缺失>"
    return out


def fieldscan() -> dict:
    """fieldscan 的取值表。它把「默认取值」记成空列表（`"4": []`），而 segtable
    把空条目丢掉了 —— 只看 segtable 会把默认值显示成「未标定」，那是误导。"""
    global _fs_cache
    if _fs_cache is None:
        try:
            _fs_cache = json.loads(_FIELDSCAN.read_text())
        except Exception:                                     # noqa: BLE001
            _fs_cache = {}
    return _fs_cache


# fieldscan 与段表的几处不一致，在这里一次抹平（下面的 R1/R2/R3/R5 是本文件内
# 引用这几条时用的标签）。段表是【显示用】的连续格子表，装不下下面这三样：
#
#   R1 字段可以不连续    FFMA 的 .FMZ/.FTZ 是 bit 76 与 bit 80 组成的 2 位字段
#                        （低位是 76），中间隔着 .SAT(77) 与舍入模式(78:79)。段表
#                        只能劈成 76:77 与 80:81，各自挂完整 4 值表 —— 1 位的格子
#                        里出现取值 2、3（放不下），且 .FTZ 被标成 .FMZ。
#   R3 取值是三态        `[]` = 合法但不加后缀（默认档）；`null` = 该取值 nvdisasm
#                        根本读不出来（非法编码）。段表把两者一起丢了，而含义正相反。
#   R5 opcode 区不是修饰符
#                        IMAD 的 bit 1 被段表标成 enum（`0_WIDE` / `0_HI`），而
#                        fieldscan 的 layout 说它是 {"kind": "opcode",
#                        "to": "IDP_R_R_R_R"} —— 翻它是**换成另一条指令**，
#                        不是给这条加后缀，因此不能给它下拉框。
#
#   R2 同一个 key 有多张子表（mode）
#                        mode 是**低 12 位 opcode 区的一个取值**（载体 carrier）：
#                        同一个 InsKey 在不同载体下修饰符字段的取值表不同。
#                        `ATOM_P_R_dARI_R` 的 `.F64` / `.BF16x4` 只在浮点载体上
#                        测得到，整数载体上根本不可见。fieldscan 只留了 mode 序号，
#                        载体编码没落盘 —— 另行实测后写进
#                        `data/modes-sm90.json`，这里按指令自己的选择位反查载体。

_LABEL_DEFAULT = "—（默认，无后缀）"
#: fieldscan 的 `null`：`names[v] = None if r is None or r[0] != key` ——
#: 读不出来**或者**变成了另一个 InsKey，两者都不属于本 key。
#: 实测 `CCTL` 87 位翻一下，`CCTL.IVALL` 变成 `CCTL.RS [RZ]`，属于后者。
_LABEL_ILLEGAL = "离开本 key（非法或成了另一条指令）"


def fs_layout(key: str, enc: str | None = None) -> dict[int, dict]:
    """fieldscan 的逐位分类；若有编码则选择对应的 mode 子表。"""
    ent = fieldscan().get(key, {})
    raw = ent.get("layout") or {}
    if enc is not None and ent.get("mode_layouts"):
        mode = pick_mode(key, enc)
        for row in ent["mode_layouts"]:
            if row.get("mode") == mode:
                raw = row.get("layout") or raw
                break
    return {int(b): c for b, c in raw.items()}


def modes() -> dict:
    """`data/modes-sm90.json`：每个 key 的模式载体与选择位。读不到就返回空。"""
    global _mode_cache
    if _mode_cache is None:
        try:
            _mode_cache = json.loads(_MODES.read_text())["keys"]
        except Exception:                                     # noqa: BLE001
            _mode_cache = {}
    return _mode_cache


def form_grammar() -> dict | None:
    """The optional, generated grammar artifact; absent means no extra filter."""
    global _grammar_cache
    if _grammar_cache is None:
        try:
            from nvisa.model.form_grammar import validate
            _grammar_cache = validate(json.loads(_FORM_GRAMMAR.read_text()))
        except FileNotFoundError:
            return None
    return _grammar_cache


def pick_mode(key: str, enc: str) -> int | None:
    """按指令自己的**选择位**反查它落在哪个模式载体上，认不出返回 None。

    载体之间只在低 12 位 opcode 区的若干位上有差异（`select_bits`），比这几位就够。
    `IMAD_R_R_R_R` 的选择位是 [0, 1]：`0x224` = `IMAD.MOV`、`0x225` = 普通 `IMAD`、
    `0x227` = `IMAD.HI`。
    """
    ent = modes().get(key)
    # segtable 自身也带一份 selector/carrier，便于把一份导出的表单独交给
    # 消费者。旧产物没有这两个字段时仍退回 modes.json，保持兼容。
    if not ent:
        row = segtable().get(key, {})
        if row.get("mode_carriers"):
            ent = {"select_bits": row.get("mode_select_bits", ()),
                   "carriers": row["mode_carriers"]}
    if not ent:
        return None
    sel = ent["select_bits"]
    if len(ent["carriers"]) < 2 or not sel:
        return 0
    want = [get_bits(enc, b, b) for b in sel]
    for i, c in enumerate(ent["carriers"]):
        # Mode-carrier records are emitted from the integer opcode table in
        # conventional high-to-low hex order, unlike cubin enc strings.  The
        # carrier's low selector bits therefore intentionally come from the
        # right-hand end here.
        v = int(c, 16)
        if [(v >> b) & 1 for b in sel] != want:
            continue
        # selector 只回答「这个 key 的第几张子表」，不能把别的 opcode 恰好
        # 撞上的 selector 模式误认成自己的 mode。B 槽寻址的 9:11 本来允许
        # 随 form 变化，故只核对真正 opcode 的 0:8 固定位。
        fixed = [b for b in range(_OPCODE_CORE) if b not in sel]
        if all(get_bits(enc, b, b) == ((v >> b) & 1) for b in fixed):
            return i
    return None


def cells_for(key: str, enc: str | None = None) -> list[dict]:
    """返回编码实际落入的 key/mode 子表；旧产物退回顶层 ``cells``。"""
    entry = segtable()[key]
    if enc is not None:
        mode = pick_mode(key, enc)
        row = (entry.get("mode_cells") or {}).get(str(mode))
        if row and row.get("cells"):
            return row["cells"]
    return entry["cells"]


def fs_enum_fields(key: str, enc: str | None = None) -> list[dict]:
    """fieldscan 的修饰符字段，规范化成 `{bit_list, values, illegal}`。

    `bit_list` 是**低位在前**的位序：FFMA 的 `[76, 80]` 意味着 bit 76 是这个
    2 位字段的第 0 位。实测四种组合与这个位序一致：

        bit76=0 bit80=0 -> FFMA            bit76=1 bit80=0 -> FFMA.FMZ
        bit76=0 bit80=1 -> FFMA.FTZ        bit76=1 bit80=1 -> FFMA.INVALID3
    """
    entries = [f for f in fieldscan().get(key, {}).get("fields", [])
               if not f.get("skipped") and f.get("values")]
    # 各 mode 的子表按**位是否重叠**取舍 —— 不能只看 bit_list 是否相同：
    # `ATOM_P_R_dARI_R` 的整数档是 73:76、浮点档是 73:77，位组不同但说的是同一批位，
    # 只按位组归拢会把两张表同时摆出来。
    #
    # `scan_key` 按 (bit_list, values) 去重：一个字段在多个载体下测出同一张表，
    # 就只留最低的那个 mode。于是取舍规则是
    #   · 本模式自己测了这些位  -> 用本模式的，别的模式碰这些位的一律丢掉
    #   · 本模式没测这些位      -> 用碰这些位的最低 mode 那条（去重留下的通用表）；
    #                              若碰这些位的 mode 不止一个，标 unresolved ——
    #     `IMAD` 的 bit 0 就是：mode 0（载体 `IMAD.MOV`）说取值 0 是 `.MOV`，
    #     而普通 `IMAD` 落在 mode 1，mode 1 没测这一位组，名字未必适用。
    items = [(tuple(f.get("bit_list") or range(*f["bits"])), f.get("mode", 0), f)
             for f in entries]
    mode = (pick_mode(key, enc) if enc is not None else 0) if modes() else 0
    own_bits = {b for bl, md, _ in items if md == mode for b in bl}
    # 去重后某个字段可能只保留在 mode 1；这不表示它能借给 mode 0。
    # 若 mode 0 已逐位测到 illegal / operand / opcode / dontcare，它是对
    # “该字段存在”的直接反证（ALD 的 a[URn]、I2F 的 F64/U8 正是如此）。
    # ``modifier`` 不能作为反证：逐位扫描只能说它们各自会改文本，而同 mode
    # 的取值表才证明这些位共同组成 enum。
    selected_layout = {}
    for row in fieldscan().get(key, {}).get("mode_layouts", []):
        if row.get("mode", 0) == mode:
            selected_layout = {int(b): c for b, c in
                               (row.get("layout") or {}).items()}
            break

    out = []
    for bl, md, f in items:
        if md == mode:
            unresolved = False
        else:
            if any(selected_layout.get(b, {}).get("kind") in
                   {"illegal", "operand", "opcode", "dontcare"} for b in bl):
                continue
            if own_bits & set(bl):
                continue                      # 本模式自己测过这些位
            touching = {md2 for bl2, md2, _ in items if set(bl2) & set(bl)}
            if md != min(touching):
                continue                      # 同一批位只留最低 mode 那条
            unresolved = len(touching) > 1 or mode is None
        values, illegal = {}, set()
        for raw, names in f["values"].items():
            if names is None:
                illegal.add(int(raw))        # 不属于本 key，不是「默认」
            else:
                values[int(raw)] = " ".join(names) if names else _LABEL_DEFAULT
        out.append({"bit_list": list(bl), "values": values, "illegal": illegal,
                    "unresolved": unresolved, "mode": f.get("mode", 0)})
    return out


def segtable() -> dict:
    """{key: {...}}，读不到就返回空 —— 页面退回通用解码，不报错。"""
    global _seg_cache
    if _seg_cache is None:
        try:
            _seg_cache = json.loads(_SEGTABLE.read_text())["keys"]
        except Exception:                                     # noqa: BLE001
            _seg_cache = {}
    return _seg_cache


_OPCODE_BITS = 12          # 低位 opcode 区；与 fieldscan 同一个常量
_OPCODE_CORE = 9           # 真正的操作码只有 0:8；bit 9:11 是 B 槽寻址模式（实测）
_opcode_index: dict[int, list[str]] | None = None
_opcode_core_index: dict[int, list[str]] | None = None


def opcode_index() -> dict[int, list[str]]:
    """{低 12 位取值: [InsKey, …]} —— 用模式载体建的 opcode 锚点表。

    `data/modes-sm90.json` 里每个 key 的 `carriers` 是**真实编码**，低 12 位就是
    它的 opcode 值（一个 key 可能有多个模式，各占一个取值）。实测判别力：

        不同的低 12 位取值 184（对 189 个 key）
        唯一确定一个 key 的 157 个，对应 2 个 key 的 21、3 个的 4、4 个的 2

    这张表解决的是 `identify()` 的一个死角：**没有 const 格的 key 永远认不出**。
    `NOP` 的 0:12 在段表里是 `assumed`（samples=1，证据不足，opcode 区整片降级成
    待证位）而不是 `const`，于是它一条 const 约束都没有，被 identify 直接跳过 ——
    实测 394 条认不出里 318 条是 NOP，就是这么来的。
    """
    global _opcode_index
    if _opcode_index is None:
        _opcode_index = _build_opcode_index(_OPCODE_BITS)
    return _opcode_index


def opcode_core_index() -> dict[int, list[str]]:
    """{低 9 位取值: [InsKey, …]} —— 12 位锚点认不出时的兜底。

    **12 位不全是操作码**：实测 bit 9:11 是 **B 槽寻址模式**
    （B 从 R / imm / `c[][]` / UR 哪条通路取）。载体表只覆盖了建库语料里出现过的
    b_mode 取值，于是同一条指令换一种 B 槽形态就整个查不到锚点 —— 生产库反汇编上
    实测这是认不出的**头号原因**（`SHFL` 的 `0x389`/`0x589` 对库里的
    `0x989`/`0xf89`，`WARPSYNC` 的 `0x348` 对 `0x948`，低 9 位都相同）。

    判别力比 12 位弱（120 个取值，候选最多 10 个，1 个取值的候选跨助记符），
    所以只当兜底：12 位命中就不走这里，候选照样要过 const / 谓词那两关。
    """
    global _opcode_core_index
    if _opcode_core_index is None:
        _opcode_core_index = _build_opcode_index(_OPCODE_CORE)
    return _opcode_core_index


def _build_opcode_index(width: int) -> dict[int, list[str]]:
    idx: dict[int, list[str]] = {}
    for key, v in modes().items():
        for c in v["carriers"]:
            idx.setdefault(int(c, 16) & ((1 << width) - 1), []).append(key)
    return {k: sorted(set(v)) for k, v in idx.items()}


#: const 格里**不承载身份**的位，打分时逐位跳过。两类都是实测出来的：
#:  - `9:12` —— B 槽寻址模式，不是操作码。同一条指令换一种 B 槽
#:    形态（R / imm / `c[][]` / UR）这几位就变，而建库语料只覆盖了其中几种，
#:    于是 `SHFL` 的 0:12 常量格锁死在 `0xf89`，生产库里的 `0x589` 一律匹配不上。
#:  - `>=105` —— 控制码区。那是**调度信息**，同一条指令在不同
#:    上下文里本来就不同；样本少时它恒定纯属偶然。实测 `IMAD_R_R_II_R_P` 的
#:    123:128 就是这么变成 const 的，然后挡掉了所有真实的 IMAD。
_NONIDENTITY = frozenset(range(9, 12)) | frozenset(range(105, 128))


def _const_score(enc: str, key: str) -> int | None:
    """该 key 的 const 格是否全部对得上；对得上返回命中的常量位数，否则 None。

    逐位比较而不是整格比较 —— 格子里可能混进 `_NONIDENTITY` 的位，那些跳过。
    """
    bits = 0
    # key/form 判别必须走稳定的 canonical 行。mode_cells 是已识别 key 后给
    # 格子展示用的局部语义覆盖；拿它反过来判身份既会循环依赖，也会把某个
    # mode 未量到的 const 从打分中抹掉。
    for c in segtable()[key]["cells"]:
        if c["kind"] != "const" or "value" not in c:
            continue
        lo, hi = c["bits"]
        for b in range(lo, hi):
            if b in _NONIDENTITY:
                continue
            if get_bits(enc, b, b) != ((c["value"] >> (b - lo)) & 1):
                return None
            bits += 1
    return bits


def _const_rank(enc: str, key: str) -> tuple[int, int, int] | None:
    """Return an evidence-aware rank for a matching key.

    ``_const_score`` counts physical bits, but those bits are private claims of
    one InsKey.  Comparing the count directly therefore lets a one-sample key
    with a wide, accidental ``const`` region beat a key whose smaller region
    was observed repeatedly.  Keep the bit count as the observation strength
    and scale it by the number of samples that support that key.  The remaining
    tuple members make ties deterministic without treating raw const width as
    evidence on its own.
    """
    bits = _const_score(enc, key)
    if bits is None:
        return None
    samples = int(segtable()[key].get("samples") or 1)
    return bits * samples, samples, bits


_CELL_BY_BIT: dict = {}
_PRED_W = 3                # 谓词寄存器 3 位；P.Guard 的第 4 位是取反
_PT = (1 << _PRED_W) - 1   # PT / UPT：谓词目的写这里 = 丢弃，nvdisasm 就不打印它


def _pred_dests(key: str, enc: str | None = None) -> list[int]:
    """该 key 声明的谓词【目的】格的起始位。`P.Guard` 是源谓词，不算。"""
    return sorted(c["bits"][0] for c in segtable()[key]["cells"]
                  if c["kind"] == "operand" and not c.get("implicit")
                  and c.get("tag") in ("P", "UP"))


def _pred_pair(enc: str, a: str, b: str) -> str | None:
    """两个 form 只差若干个谓词槽时，用那几位是不是 PT 决定选哪个。

    同 opcode 的 form 往往只差一个谓词输出，硬件上是同一条编码：

        IADD3_R_P_R_R_R / IADD3_R_R_R_R          多出来的是进位输出 P
        MATCH_P_R_R     / MATCH_R_R
        UIADD3_UR_UP_UR_II_UR / UIADD3_UR_UR_II_UR

    **谓词目的写 PT 等于丢弃，nvdisasm 就不打印它**，于是文本的 form 里也没有
    这一槽。所以多出来的那几槽全是 PT 就选短的，否则选长的。

    注意判据是「**全部**是 PT」而不是「有 PT」：`UIADD3.X` 的长 form 一次多出
    两槽 —— 进位输出 `UP0` 与进位输入 `!UPT` —— 后者是**源**谓词，写 PT 照样打印。
    互不包含（谁也不是谁的子集）时不猜，返回 None。

    **前提是那几位在短 form 里没被约束**（"同一条编码，只是多打印一槽"）。短
    form 把它们标成 `const` 而编码又正好对上时，前提就不成立 —— 而且答案是反的：
    那是短 form 的**直接正证据**（该 key 的样本在这几位上恒定，这条编码也恒定
    到同一个值），长 form 那边只是"谓词槽能装下任何值"这种恒真的不证伪。
    所以此时直接选短的，不看 PT。

    这条判据是自洽的，因为它按编码取值分流：`LDG.E R5, [RZ.U32+UR10]` 的
    bit 64-66 是 0，命中 `LDG_R_ARURI` 实测的 `const value=0` → 选短的（对，
    nvdisasm 没打印谓词）；而 `LDG.E R5, [RZ.U32+UR10], P6` 这几位是 1，
    对不上那个 const → 落回原判据选长的 `_P`（也对）。老判据只看"是不是 PT"，
    两条都判成长的，把前者凭空多打印了一个谓词操作数。
    """
    da, db = set(_pred_dests(a, enc)), set(_pred_dests(b, enc))
    if da > db:
        more, less, extra = a, b, da - db
    elif db > da:
        more, less, extra = b, a, db - da
    else:
        return None
    if _gated_by_const(enc, more, less):
        return less
    return less if all(get_bits(enc, lo, lo + _PRED_W - 1) == _PT
                       for lo in extra) else more


_SOFT_KINDS = ("enum", "operand", "modifier")


def _cell_by_bit(key: str) -> dict[int, dict]:
    """{位号: 该位所属的格}。按段表对象本身缓存 —— 换了表（测试里直接改
    `_seg_cache`）缓存自动失效，不会拿上一张表的格子作答。"""
    seg = segtable()
    if _CELL_BY_BIT.get("__owner__") is not seg:
        _CELL_BY_BIT.clear()
        _CELL_BY_BIT["__owner__"] = seg
    got = _CELL_BY_BIT.get(key)
    if got is None:
        got = {}
        for c in seg[key]["cells"]:
            for b in range(*c["bits"]):
                got[b] = c
        _CELL_BY_BIT[key] = got
    return got


def _gated_by_const(enc: str, more: str, less: str) -> bool:
    """`less` 有某一位是「const 且 `enc` 正好对上」，而 `more` 在同一位上只是
    enum/operand/modifier —— 那是 `less` 的**直接正证据**，`more` 只是装得下。

    这些位就是**门控位**：一个决定某个操作数打不打印的修饰符位。短 form 把它
    实测成了常量（"我这个 form 里它只能是这个值"），长 form 则把它归进自己多出
    来的那一槽。编码对上短 form 的常量，短 form 就被正面确认了。

    nvdisasm 验证过的两例，形状完全一样：
      `HFMA2_R_R_R_R_P` 的 bit 79 是 `.RELU` —— 翻它，
        `HFMA2.RELU R17, R13, R0, -RZ, P0` 变成 `HFMA2 R17, R13, R0, -RZ`；
      `UISETP_UP_UP_UR_II_UP_UP` 的 bit 72 是 `.EX` —— 翻它，
        `UISETP.GT.AND.EX UP0, …, UP0` 变成 `UISETP.GT.AND UP0, …`。
    两处的短 form 都把该位实测成 `const`，长 form 才把它算进操作数槽。

    原判据只问「多出来那几槽是不是全 `PT`」。它的前提是"同一条编码，只是多打印
    一槽"，门控位一存在这个前提就不成立：bit 79 = 0 既不是 `PT`(7)，也不代表
    那一槽存在，于是老判据一律选长的，凭空多打印一个操作数。
    """
    soft = _cell_by_bit(more)
    for b, c in _cell_by_bit(less).items():
        if c["kind"] != "const" or "value" not in c:
            continue
        other = soft.get(b)
        if other is None or other["kind"] not in _SOFT_KINDS:
            continue
        lo, hi = c["bits"]
        if get_bits(enc, lo, hi - 1) == c["value"]:
            return True
    return False


def _filter_gated_forms(enc: str, keys: list[str]) -> list[str]:
    """排除被较短 form 的匹配 const 直接否定的较长 form。

    `_gated_by_const()` 起初只在 `_pred_pair()` 中调用，因而只能修复“多一个
    谓词槽”的门控 form。相同的编码形状也出现在普通寄存器、立即数和 L 槽：短
    form 在该位有匹配的 const，长 form 却把它当作自己额外槽的 soft 格。前者是
    直接正证据，后者只是“装得下”，不应再交给跨 key 的 const 排名。

    只比较槽数不同的候选。相同槽数时 const/soft 的差异未必代表可选槽（例如
    IMAD 的 cAI/cxAI），仍留给原有的保守排序，避免把一个已知的窄规则扩张成猜测。
    """
    rejected = set()
    for more in keys:
        for less in keys:
            if _slot_count(more) <= _slot_count(less):
                continue
            if _gated_by_const(enc, more, less):
                rejected.add(more)
                break
    kept = [key for key in keys if key not in rejected]
    return kept or keys


def _typed_operands(key: str, enc: str) -> list[dict]:
    """Decode mode-aware operand cells into the small AST consumed by grammar.

    A semantic operand may be split across physical ranges.  Grouping by its
    parser column and semantic tag keeps form rules independent of those bit
    locations (and of mode-specific layout changes).
    """
    groups: dict[tuple[int | None, str], list[dict]] = {}
    for cell in cells_for(key, enc):
        if cell["kind"] != "operand":
            continue
        groups.setdefault((cell.get("slot"), cell.get("tag", "")), []).append(cell)
    out = []
    for (slot, tag), cells in groups.items():
        value, shift = 0, 0
        for cell in sorted(cells, key=lambda c: c["bits"][0]):
            lo, hi = cell["bits"]
            value |= get_bits(enc, lo, hi - 1) << shift
            shift += hi - lo
        out.append({"slot": slot, "tag": tag, "value": value})
    # The form grammar speaks about semantic modifier tokens (``0_X``,
    # ``0_HI`` and ``0_SX32``), never their physical bit positions.  The
    # fieldscan adapter already resolves the current mode and scattered bit
    # order, so emit just the active tokens alongside operand components.
    for field in fs_enum_fields(key, enc):
        raw = _gather(enc, field["bit_list"])
        label = field["values"].get(raw, "")
        for token in label.replace(" ", "+").split("+"):
            if token and token != _LABEL_DEFAULT:
                out.append({"kind": "modifier", "tag": token, "value": 1})
    return out


def _grammar_filter_forms(enc: str, keys: list[str]) -> list[str]:
    """Apply admitted form grammar rules without falling back to name branches."""
    grammar = form_grammar()
    if grammar is None:
        return keys
    from nvisa.model.form_grammar import filter_candidates
    return filter_candidates(keys, {key: _typed_operands(key, enc) for key in keys}, grammar)


def _grammar_filter_p3_columns(enc: str, keys: list[str]) -> list[str]:
    """Apply P3 modifier-controlled column rules."""
    grammar = form_grammar()
    if grammar is None:
        return keys
    from nvisa.model.form_grammar import filter_conditional_columns
    operands = {key: _typed_operands(key, enc) for key in keys}
    # A selector field is carried by the encoding, not by the candidate's
    # particular form layout.  One sibling may describe `.HI` while another
    # correctly leaves that bit implicit; share the decoded semantic token so
    # both forms are tested against the same modifier state.
    active = {item["tag"] for rows in operands.values() for item in rows
              if item.get("kind") == "modifier" and item.get("value") == 1}
    for rows in operands.values():
        have = {item.get("tag") for item in rows if item.get("kind") == "modifier"}
        rows.extend({"kind": "modifier", "tag": tag, "value": 1}
                    for tag in active - have)
    return filter_conditional_columns(keys, operands, grammar)


def _grammar_filter_p3_roles(enc: str, keys: list[str]) -> list[str]:
    """Apply P3 predicate source/destination roles after opcode filtering."""
    grammar = form_grammar()
    if grammar is None:
        return keys
    from nvisa.model.form_grammar import filter_role_aware_columns
    return filter_role_aware_columns(keys, {key: _typed_operands(key, enc) for key in keys}, grammar)


def _grammar_filter_gated_forms(enc: str, keys: list[str]) -> list[str]:
    """Data-driven replacement for the generic matching-short-const gate."""
    grammar = form_grammar()
    if grammar is None:
        return keys
    candidates = {}
    for key in keys:
        by_bit = {}
        for cell in segtable()[key]["cells"]:
            lo, hi = cell["bits"]
            fact = {"kind": cell["kind"]}
            if cell["kind"] == "const" and "value" in cell:
                fact["matches"] = get_bits(enc, lo, hi - 1) == cell["value"]
            for bit in range(lo, hi):
                by_bit[bit] = fact
        candidates[key] = {"slot_count": _slot_count(key), "cells_by_bit": by_bit}
    from nvisa.model.form_grammar import filter_matching_const_forms
    return filter_matching_const_forms(keys, candidates, grammar)


def _grammar_pick_optional_components(enc: str, keys: list[str]) -> str | None:
    """Data-driven compatibility selector for currently untyped P/UP roles."""
    grammar = form_grammar()
    if grammar is None:
        return None
    from nvisa.model.form_grammar import pick_optional_component_form
    # Preserve the legacy selector's semantic coordinate until P3 supplies
    # explicit source/destination roles: a predicate component is identified
    # by its physical field start, excludes implicit cells, and is three bits
    # wide.  The grammar still owns the visibility value and tag vocabulary.
    operands = {}
    for key in keys:
        operands[key] = [
            {"slot": cell["bits"][0], "tag": cell["tag"],
             "value": get_bits(enc, cell["bits"][0], cell["bits"][0] + _PRED_W - 1)}
            for cell in segtable()[key]["cells"]
            if (cell["kind"] == "operand" and not cell.get("implicit")
                and cell.get("tag") in ("P", "UP"))]
    return pick_optional_component_form(keys, operands, grammar)


def _slot_count(key: str) -> int:
    """InsKey 声明了几个操作数槽 —— `IADD3_R_P_R_R_R` 是 5。"""
    return len(key.split("_")) - 1


def _last_slot(key: str, enc: str | None = None) -> tuple[str, list[int]] | None:
    """该 key 编号最大的操作数槽：(tag, 它占的位)。`P.Guard` 是 slot 0，不算。"""
    best = None
    for c in segtable()[key]["cells"]:
        if c["kind"] != "operand" or c.get("slot") in (None, 0):
            continue
        if best is None or c["slot"] > best[0]:
            best = (c["slot"], c.get("tag", ""), list(range(*c["bits"])))
    return (best[1], best[2]) if best else None


def _drop_invisible_slot(enc: str, more: str, less: str) -> str | None:
    """槽多的那个赢了常量位数 —— 但它最后那个槽**看不见**时，该选槽少的。

    与 `_pred_pair` 同一条原理：**槽取到「不打印」的值时，文本里就没有这一槽**，
    form 也就少一格。谓词的不可见值是 `PT`，立即数的是 **0**。

        BAR.SYNC.DEFER_BLOCKING 0x0          bit 42:51 = 0     -> BAR_II（1 槽）
        BAR.SYNC.DEFER_BLOCKING 0x0, 0x80    bit 42:51 = 0x80  -> BAR_II_II（2 槽）

    只在「赢家槽更多」且「它最后一槽是立即数且为 0」时才改判，其余一律不动 ——
    赢家最后一槽是寄存器时（`LEA.HI R7, R7, R4, RZ, 0x4` 多出来的是 `RZ`，
    编码里是全 1 不是 0）本来就该选长的，实测 26,126 条都靠这一条保住。

    改不动就返回 None，由调用方维持原来的常量位数裁决。
    """
    if _slot_count(more) <= _slot_count(less):
        return None
    last = _last_slot(more, enc)
    if not last or last[0] != "II":
        return None
    if any(get_bits(enc, b, b) for b in last[1]):
        return None
    return less


def _implicit_form_filter(enc: str, keys: list[str]) -> list[str]:
    """Consume data-backed implicit-column and opcode-transition selectors.

    数据表已把 `.X`/`.SX32`/`.HI` 从 ``opcode`` 改回了真正的 enum 字段。这个
    语义分类是对的，但这些位还同时决定 nvdisasm 是否打印额外的操作数列：

    * bit 74（`.X`）决定末尾的 P/UP 进位输入是否出现；
    * LEA/ULEA 的 bit 73（`.SX32`）与 bit 80（`.HI`）异或时，才出现
      倒数第二个 R/UR 进位操作数。

    过去这些位被错当 const，``_const_score`` 偶然拿它们区分 form；改成 enum
    后同一 opcode 下的长短 form 会打平。这里把“字段语义”和“文本 form 选择”
    分开建模，不能为了保住 identify 又把字段退回 const。

    LEA/IMAD 的隐式槽规则只对已验证的四个家族生效；但 fieldscan 已确认的
    同候选集 ``opcode`` 跳转是所有家族的 form 证据，不能因前者不适用就跳过。
    过滤没有唯一信息时保留原候选，让后面的 const / 谓词规则继续裁决。
    """
    if not keys:
        return keys
    keys = _grammar_filter_p3_columns(enc, keys)

    # 非隐式的同助记符 opcode 跳转仍是真正的 form 选择器。LEA 的 bit 81
    # 决定谓词输出列是否存在；相邻的 HI/X 位改成 enum 后，不能再靠
    # const 分数偶然挡掉错误 form。只采用“目标也在当前候选集”的单步关系，
    # 避免把跨操作码/B-mode 的普通跳转混进来。
    fs = fieldscan()
    kept = []
    keyset = set(keys)
    for key in keys:
        ent = fs.get(key, {})
        base = (ent.get('repos') or {}).get('code')
        bad = False
        if base is not None:
            for b, cell in (ent.get('layout') or {}).items():
                to = cell.get('to')
                if cell.get('kind') != 'opcode' or to not in keyset:
                    continue
                b = int(b)
                if get_bits(enc, b, b) != ((base >> b) & 1):
                    bad = True
                    break
        if not bad:
            kept.append(key)
    if kept:
        keys = kept
    return keys


def _pick_by_pred(enc: str, keys: list[str]) -> str | None:
    """多个候选就两两淘汰；任何一步拆不开就整体不猜。"""
    cur = keys[0]
    for k in keys[1:]:
        cur = _pred_pair(enc, cur, k)
        if cur is None:
            return None
    return cur


def _bmode_known(enc: str, key: str) -> bool:
    """`enc` 的 B 槽寻址模式（bit 9:11）是不是该 key **见过的**载体之一。

    9:11 不承载操作码，但它承载 **form**：B 槽从 R / imm / `c[][]` / UR 哪条通路
    取，决定这条指令打印几个操作数。`_NONIDENTITY` 把这三位整体排除在 const 比对
    之外，于是 12 位锚点落空、退到 9 位真操作码时，一个**表里根本没有的 b_mode
    变体**会被并进唯一的邻居，`identify()` 给出一个自己无法自证的 form —— 这违背
    它自己的「宁缺毋滥」契约。

    实测：`SYNCS.EXCH.64 URZ, [UR8], UR6` 的低 12 位是 `0x5b2`，表里
    只有 `0x9b2` 的 `SYNCS_UR_AURI`；两者只差 bit 10/11，而把这两位翻回去，
    nvdisasm 打印的操作数从 3 个变成 2 个 —— 是两个不同的 form。生产库上因此产生
    8,069 条 form 错。

    12 位锚点命中时这一关按构造必过（低 12 位相等则 9:11 相等），所以它只在 9 位
    兜底和全局 const 打分那两条路上起作用，正是出错的那两条。载体表缺失时不拦。
    """
    v = modes().get(key)
    if not v or not v.get("carriers"):
        return True
    want = get_bits(enc, 9, 11)
    return any((int(c, 16) >> 9) & 0x7 == want for c in v["carriers"])


def identify(enc: str) -> str | None:
    """认出这条编码属于哪个 InsKey。**宁缺毋滥**：出答案就是对的，不确定返回 None。

    出答案前还要过 `_bmode_known()`：答案的 B 槽寻址模式必须是该 key 见过的，
    否则这是个表外变体，认不出比认错好。
    """
    key = _identify_by_anchor(enc)
    return key if key is not None and _bmode_known(enc, key) else None


def _identify_by_anchor(enc: str) -> str | None:
    """锚点 + const/谓词打分。**出口一律经 `identify()` 的 b_mode 复核。**

    两级：
      1. **opcode 锚点**（`opcode_index()`，12 位；认不出再退 `opcode_core_index()`
         的 9 位真操作码，见那里的注释）把候选缩到 1~4 个。唯一就直接给答案 ——
         这是 `NOP` / `EXIT` 这类没有 const 格的 key 唯一的出路。
      2. 候选多于一个时，用 const 格在候选内打分（同一 opcode 的不同 form，
         例如 `IADD3_R_R_R_R` 与 `IADD3_R_P_R_R_R`）。仍然平局就返回 None。
         常量位数这个 tiebreak **只对同槽数的候选有效**，见下面的注释。

    锚点表缺失（没有 `data/modes-sm90.json`）时退回原来的全局 const 打分。
    """
    seg = segtable()
    c12 = opcode_index().get(get_bits(enc, 0, _OPCODE_BITS - 1))
    c9 = opcode_core_index().get(get_bits(enc, 0, _OPCODE_CORE - 1))
    cands = _implicit_form_filter(
        enc, [k for k in (c12 or c9 or ()) if k in seg])

    # 锚点候选里**一个 const 格都对不上**，说明这批候选本身就不对。
    # 12 位表是按载体建的，只覆盖建库时见过的 b_mode 组合，很容易只剩一个候选
    # 而那个候选恰恰是错的 —— `F2I.U64.TRUNC R18, R18` 的低 12 位只映射到
    # `F2I_R_UR`，正确答案 `F2I_R_R` 的载体 b_mode 不同，压根没进候选。
    # 依次放宽：9 位真操作码 -> 全局 const 扫描。
    if cands and not any(_const_score(enc, k) is not None for k in cands):
        wider = _implicit_form_filter(enc, [k for k in (c9 or ()) if k in seg])
        if any(_const_score(enc, k) is not None for k in wider):
            cands = wider
        else:
            got = _global_const_pick(enc)
            if got:
                return got
            # 全局也没有：**别硬要求 const 格对上**。const 格本身可能过约束 ——
            # `CS2R R2, SR_CLOCKLO` 的 `L` 槽（特殊寄存器号）有几位被判成了常量，
            # 换一个 SR 就对不上，可它的答案是对的。锚点唯一就仍旧交给锚点。
            return cands[0] if len(cands) == 1 else None

    if cands:
        if len(cands) == 1:
            return cands[0]
        scored = [k for k in cands if _const_score(enc, k) is not None]
        if len(scored) == 1:
            return scored[0]
        if scored:
            scored = _grammar_filter_p3_roles(enc, scored)
            if len(scored) == 1:
                return scored[0]
            scored = _grammar_filter_gated_forms(enc, scored)
            if len(scored) == 1:
                return scored[0]
            scored = _grammar_filter_forms(enc, scored)
            if len(scored) == 1:
                return scored[0]
            # 同 opcode 的候选多半只差谓词槽，先用谓词判据；它拆不开再看
            # 经过样本数校正的 const 证据。
            got = _grammar_pick_optional_components(enc, scored)
            if got:
                return got
            order = sorted(scored, key=lambda k: _const_rank(enc, k), reverse=True)
            if _const_rank(enc, order[0]) != _const_rank(enc, order[1]):
                # 槽数不同的两个 form，仍不能只看裸 const 位数；位数多只说明
                # 它把更多位划给了常量。`_const_rank` 还要求这些位由更多样本
                # 支撑，避免低样本 form 的宽格压过高样本 form。
                # 若证据仍分不开，交给专门的不可见槽规则，否则宁缺毋滥。
                got = _drop_invisible_slot(enc, order[0], order[1])
                if got is not None:
                    return got
                return order[0]
        return None

    # 锚点认不出（模式没枚举到这个 opcode 取值）：退回全局 const 打分。
    return _global_const_pick(enc)


def _global_const_pick(enc: str) -> str | None:
    """全库按样本校正后的 const 证据取唯一最高分。

    **没有 const 格的 key 匹配一切，排除。**
    """
    best_key, best_evidence, tie = None, -1, False
    for key, v in segtable().items():
        if not any(c["kind"] == "const" and "value" in c for c in v["cells"]):
            continue
        rank = _const_rank(enc, key)
        if rank is None:
            continue
        if rank[0] > best_evidence:
            best_key, best_evidence, tie = key, rank[0], False
        elif rank[0] == best_evidence:
            tie = True
    return None if tie else best_key
def _cell_label(cell: dict, raw: int) -> str:
    kind = cell["kind"]
    if kind == "const":
        return f"= {raw:#x}"
    if kind == "enum":
        names = cell.get("values", {})
        if str(raw) in names:
            return names[str(raw)]
        return "—" if raw == 0 else f"{raw} (未标定)"
    if kind == "opcode_sel":
        targets = cell.get("to") or []
        suffix = " → " + ", ".join(targets) if targets else ""
        return f"选择值 {raw:#x}{suffix}"
    if kind == "operand":
        tag = cell.get("tag", "")
        if tag in ("R", "R.Addr"):
            return "RZ" if raw == 255 else f"R{raw}"
        if tag in ("UR", "UR.Addr", "UR.CBank", "UR.Desc"):
            return "URZ" if raw == 63 else f"UR{raw}"
        if tag == "P.Guard":
            return f"@{'!' if raw >> 3 else ''}{'PT' if raw & 7 == 7 else 'P%d' % (raw & 7)}"
        if tag in ("P", "UP") and raw < 8:
            prefix = "UP" if tag == "UP" else "P"
            return f"{prefix}T" if raw == 7 else f"{prefix}{raw}"
        return f"{raw:#x}"
    return f"{raw:#x}" if raw else ""


def _gather(enc: str, bit_list: list[int]) -> int:
    """按 `bit_list` 的顺序（低位在前）把散落的位拼成一个取值。"""
    return sum((get_bits(enc, b, b) & 1) << i for i, b in enumerate(bit_list))


def _is_dubious(label: str) -> bool:
    """dubious：token 本身就是 `INVALID*` —— nvdisasm 照样读得出、照样打印，但这不是
    一条有意义的指令。跟"非法编码，nvdisasm 根本读不出来"（`illegal`/R3）性质
    不同，那个连解都解不出；这个解得出，只是解出来的东西没有意义。两者过去
    在页面上长得一样，看不出区别——`LDC` 73:75 填 6，`LDC.INVALID6` 照常显示，
    像是一条正常指令。"""
    return "INVALID" in label


def _field_cell(enc: str, bit_list: list[int], values: dict[int, str],
                illegal: set[int], kind: str, to: list[str],
                unresolved: bool = False) -> dict:
    raw = _gather(enc, bit_list)
    dubious = False
    if raw in illegal:
        label = _LABEL_ILLEGAL
    elif raw in values:
        label = values[raw]
        dubious = _is_dubious(label)
    else:
        label = "—" if raw == 0 else f"{raw} (未标定)"
    cell = {"lo": min(bit_list), "hi": max(bit_list), "kind": kind, "raw": raw,
            "tag": "→ " + ", ".join(to) if to else "", "label": label,
            "bit_list": list(bit_list),
            "values": {str(v): n for v, n in sorted(values.items())},
            "illegal": [str(v) for v in sorted(illegal)]}
    if unresolved:
        cell["unresolved"] = True            # 多 mode 未解析，名字未必适用（见上文 R2）
    if dubious:
        cell["dubious"] = True               # 解得出 ≠ 合法
    if kind == "enum":
        cell["editable"] = True          # opcode 位不给下拉框：改它是换指令（见上文 R5）
    return cell


#: 宽过这个就额外发一份十进制字符串 —— JSON 数字到了 JS 是 double，
#: 53 位以上会被悄悄改值（段表里最宽的 operand 槽 81 位）。前端一律读 `raw_str`。
_WIDE_BITS = 32


def _wide(cell: dict) -> dict:
    """给宽字段补一份 `raw_str`。窄的不补 —— 免得每格都多一个字段。"""
    bl = cell.get("bit_list") or list(range(cell["lo"], cell["hi"] + 1))
    if len(bl) > _WIDE_BITS:
        cell["raw_str"] = str(cell["raw"])
    return cell


def _pc_relative(key: str, cell: dict, enc: str, addr: int | None) -> None:
    """PC 相对的分支目标槽：标出来，并把绝对目标算给前端。

    编码里存的是「相对下一条指令的偏移 / scale」，直接当立即数显示会骗人 ——
    `BRA` 那格显示 0x3f...ff（负偏移的两补码）而不是它真正跳去哪。这类槽
    **不给就地改**：偏移的 scale/符号位/位散布是 `slot_facts` 的规则，跟这一格
    的 `bit_list` 不是同一件事；要改目标就点 SASS 文本整条重敲，那条路
    （`asm_spec.text_to_values`）本来就吃绝对地址。
    """
    from nvisa.model import asm_spec
    fact = asm_spec.pc_offset_fact(key)
    if not fact:
        return
    bits = set(asm_spec._fact_bits(fact))
    if not bits & set(cell["bit_list"]):
        return
    cell["pc_relative"] = True
    cell["editable"] = False
    off = asm_spec.read_offset(fact, enc)
    cell["offset"] = off                          # 相对下一条指令，已解两补码
    coordinate = fact.get("text_coordinate", "absolute_target")
    cell["coordinate"] = coordinate
    if coordinate == "relative_offset":
        # BRX/BRXU 的寄存器提供动态基址/索引，单条指令不能把它解析成
        # 一个静态绝对目标；显示 nvdisasm 的相对偏移本身。
        cell["label"] = f"{off:+#x}（相对偏移）"
    elif addr is not None:
        target = addr + fact["insn_len"] + off
        cell["target"] = target
        cell["label"] = f"→ {target:#x}"
    else:
        cell["label"] = f"{off:+#x}（相对下一条）"


def cell_map(enc: str, key: str | None, addr: int | None = None) -> list[dict] | None:
    """逐格拆解。认不出 key 就返回 None。

    修饰符格子以 **fieldscan 为准**（它按 `bit_list` 测，且区分默认档与非法档），
    段表只负责 const / operand / ctrl / dontcare 那些它测得准的格子。

    `addr` 是这条指令的段内地址，只有 PC 相对的分支目标槽用得上 ——
    没给就退回显示相对偏移。
    """
    if not key:
        return None
    # mode 不是显示上的注脚：同一 key 的这些位在不同 selector 下确实可
    # 能是非法、枚举或操作数。拿到编码时必须同时选择 fieldscan 与段表子行。
    layout = fs_layout(key, enc)
    fields = fs_enum_fields(key, enc)
    samples = segtable()[key].get("samples")
    covered = {b for f in fields for b in f["bit_list"]}
    out = []

    # 同一个操作数被段表劈成几段时（`IMAD.MOV` 的立即数就是），
    # 逐段显示会让就地编辑没法用 —— 用户想改的是「那个立即数」，
    # 不是它的低 2 位。按 (slot, tag) 合并成一格，`bit_list` 低位在前。
    op_bits: dict[tuple, list[int]] = {}
    active_cells = cells_for(key, enc)
    for c in active_cells:
        if c["kind"] == "operand":
            lo, hi = c["bits"]
            op_bits.setdefault((c.get("slot"), c.get("tag")), []).extend(range(lo, hi))
    for bl in op_bits.values():
        bl.sort()
    seen_op: set[tuple] = set()

    for c in active_cells:
        lo, hi = c["bits"]
        bits = list(range(lo, hi))
        if c["kind"] in ("enum", "modifier", "opcode_sel"):
            if set(bits) <= covered:
                # 整体交给 fieldscan 的字段。`opcode_sel` 也要走这一关 ——
                # 段表把 `IMAD` bit 1 从 enum 改判成 opcode_sel 之后，这一位
                # 会同时冒出两格：段表那格没有取值表也没有 `illegal`，
                # fieldscan 那格才是能选能改的。页面上一位显示两格，先撞见的
                # 还是空的那个。
                continue
            opc = [b for b in bits if layout.get(b, {}).get("kind") == "opcode"]
            if opc:
                vals = {int(v): n for v, n in c.get("values", {}).items()}
                width = len(bits)
                illegal = {v for v in range(1 << width) if v not in vals}
                out.append(_field_cell(
                    enc, bits, vals, illegal,
                    "opcode_sel",
                    sorted({layout[b]["to"] for b in opc if layout[b].get("to")})))
                continue
        if c["kind"] == "operand":
            ok = (c.get("slot"), c.get("tag"))
            if ok in seen_op:
                continue                              # 已经并进第一段那一格了
            seen_op.add(ok)
            bits = op_bits[ok]
            raw = _gather(enc, bits)
            cell = {"lo": min(bits), "hi": max(bits), "kind": "operand", "raw": raw,
                    "tag": c.get("tag", ""), "label": _cell_label(c, raw),
                    "bit_list": bits, "slot": c.get("slot"),
                    "editable": not c.get("implicit", False)}
            if c.get("trust"):
                cell["trust"] = c["trust"]
            _pc_relative(key, cell, enc, addr)
            out.append(_wide(cell))
            continue
        raw = get_bits(enc, lo, hi - 1)
        label = _cell_label(c, raw)
        cell = {"lo": lo, "hi": hi - 1, "kind": c["kind"], "raw": raw,
                "tag": c.get("tag", ""), "label": label}
        if c["kind"] == "ctrl":
            # 控制段这一格过去是只读的：页面上它和别的格子长得一模一样，点下去
            # 却什么都不发生 —— 而同样这几位，上面那排 chip 和 `.nvsass` 源码都
            # 改得动。逐字段改仍然推荐走 chip（那里有字段名和取值），这一格给的
            # 是「整段按原始值改」，跟 16 字节字面量那一格一个性质。
            cell["editable"] = True
        elif c["kind"] == "illegal":
            cell["editable"] = False
            cell["label"] = _LABEL_ILLEGAL
        if c["kind"] == "opcode_sel" and c.get("to"):
            cell["tag"] = "→ " + ", ".join(c["to"])
        # 可信度随格子下发。`thin` = 样本不足推出来的，`borrowed` = 从别的
        # key 借来的。生产库实测过这不是虚惊：样本少时「恒定」可能纯属偶然，
        # 那样的 const 格其实是操作数槽。
        if c.get("trust"):
            cell["trust"] = c["trust"]
        if c["kind"] == "enum" and _is_dubious(label):
            cell["dubious"] = True           # 解得出 ≠ 合法
        out.append(cell)

    for f in fields:
        bl = f["bit_list"]
        opc = [b for b in bl if layout.get(b, {}).get("kind") == "opcode"]
        out.append(_field_cell(
            enc, bl, f["values"], f["illegal"],
            "opcode_sel" if opc else "enum",
            sorted({layout[b]["to"] for b in opc if layout[b].get("to")}),
            f["unresolved"]))

    for c in out:
        c.setdefault("samples", samples)
        _wide(c)
    out.sort(key=lambda c: (c["lo"], c["hi"]))
    return out


def instructions(cub: Cubin, sec, sass: dict[int, str], other: bytes | None,
                 include_cells: bool = True) -> list[dict]:
    """Render one executable section for the editor.

    ``identify``/``cell_map`` are deliberately optional: on large kernels they
    dominate both CPU time and JSON size, while the VS Code view hides cells by
    default.  CLI callers keep the historical full result; the extension asks
    for the light result first and reloads details only when the user enables
    the cell layer.
    """
    out = []
    for addr in range(0, sec.size - sec.size % INST_BYTES, INST_BYTES):
        off = sec.offset + addr
        raw = bytes(cub.data[off:off + INST_BYTES])
        enc = cub.read(addr, sec.name)
        # diff 按【同一文件偏移】比 —— 这套工装的变体全是原地拷字节，地址不会挪
        differs = other is not None and (
            len(other) < off + INST_BYTES or other[off:off + INST_BYTES] != raw)
        row = {
            "addr": addr,
            "file_off": off,
            "enc": enc,
            "bytes": raw.hex(),
            "sass": sass.get(addr, ""),
            "ctrl": ctrl_of(enc),
            "diff": differs,
        }
        if include_cells:
            key = identify(enc)
            row.update({"key": key, "cells": cell_map(enc, key, addr)})
        out.append(row)
    return out


def _mnemonic(sass: str) -> str:
    toks = sass.split()
    if toks and toks[0].startswith("@"):
        toks.pop(0)
    return toks[0] if toks else ""


def _pool_from_cubin(cub: Cubin, sass: dict[str, dict[int, str]], label) \
        -> list[tuple[str, str, str, int, bool]]:
    out = []
    for sec in cub.sections:
        for addr, text in sass.get(sec.name, {}).items():
            if addr not in sec:
                continue
            mn = _mnemonic(text)
            if mn:
                ops = [o.strip() for o in text.split(None, 1)[1].split(",")
                       if o.strip()] if " " in text else []
                # 带取反/绝对值的模板要剔掉：那是 modifier 区的位，会跟着继承下来，
                # 补完寄存器变成 'IADD3 R12, -R8, R8, RZ'，不是想要的那条
                plain = not any(o.startswith(("-", "|", "~", "!")) for o in ops)
                out.append((mn, cub.read(addr, sec.name), label(sec, addr),
                            len(ops), plain))
    return out


def _corpus_pool(d: Path) -> list[tuple[str, str, str, int, bool]]:
    """corpus 目录的模板表。按目录内容的 mtime 缓存 —— 每换一次 opcode 都重扫
    18 个 cubin 的话，一次编辑要好几秒。"""
    import hashlib
    import os
    files = sorted(d.glob("*.cubin"))
    stamp = hashlib.sha1(
        # Invalidate old pools whose flat address maps mixed different kernels.
        ("section-templates-v2\n" + "".join(
            f"{f.name}:{os.stat(f).st_mtime_ns}" for f in files)).encode()).hexdigest()[:16]
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "nvisa-cubin-sass"
    cf = cache / f"templates-{stamp}.json"
    if cf.is_file():
        try:
            return [tuple(r) for r in json.loads(cf.read_text())]
        except Exception:                                     # noqa: BLE001
            pass
    out = []
    for f in files:
        try:
            other = Cubin.load(f)
        except Exception:                                     # noqa: BLE001
            continue
        out += _pool_from_cubin(other, sass_by_sections(f),
                               lambda sec, addr, n=f.name: f"{n} {sec.name}+0x{addr:x}")
    try:
        cache.mkdir(parents=True, exist_ok=True)
        for stale in cache.glob("templates-*.json"):
            stale.unlink()
        cf.write_text(json.dumps(out))
    except OSError:
        pass                                                  # 缓存写不了不影响结果
    return out


def template_pool(cur: bytes, pool_dirs: list[Path]) -> list[tuple[str, str, str, int, bool]]:
    """(助记符, 编码, 出处) 列表。当前 cubin 排最前 —— 同一份编译产物里的模板
    最不容易带进意外的修饰符差异。"""
    import tempfile
    cub = Cubin(cur)
    with tempfile.TemporaryDirectory(prefix="cubin-sass-") as td:
        tmp = Path(td) / "cur.cubin"
        tmp.write_bytes(cur)
        out = _pool_from_cubin(cub, sass_by_sections(tmp),
                              lambda sec, addr: f"本文件 {sec.name}+0x{addr:x}")
    for d in pool_dirs:
        out += _corpus_pool(d)
    return out


#: 换 opcode / 换指令时控制段沿用【原指令】而不是模板或默认值 —— 模板是从别的
#: cubin 抠出来的，它的 stall/yield/barrier 是那边的调度结果，带过来会悄悄毁掉
#: 时序实验。
_INHERIT = ("stall", "yield", "wr", "rd_bar", "wait")


def _inherit_ctrl(enc: str, cur_enc: str) -> str:
    for key in _INHERIT:
        lo, hi = asm.FIELDS[key]
        enc = set_bits(enc, lo, hi, get_bits(cur_enc, lo, hi))
    return enc


def _disasm_many(encs: list[str]) -> list[str]:
    """一次问完几条（`nvdisasm --binary` 吃多条），缓存命中的不进这一批。

    起进程是这套工装最贵的一步（~0.3 秒），而三次 `.reuse` 探测、整段复核
    这类地方本来就是**一批**问题。逐条问和一次问答案相同 —— `disassemble_raw`
    会把 PC 相对目标归一化回「这条在地址 0」并拿一条真的单条解码复核，对不上
    就整批退回逐条（挡住批量解码时分支目标带出的地址泄漏）。
    """
    from nvisa.oracle.discache import get as _cget
    from nvisa.oracle.nvdisasm import Nvdisasm
    out: list[str] = [""] * len(encs)
    todo = []
    for i, e in enumerate(encs):
        hit = _DIS_CACHE.get(enc_to_bytes(e))
        if hit is None:
            hit = _cget(ARCH, enc_to_bytes(e))
        if hit is None:
            todo.append(i)
        else:
            out[i] = hit
    if todo:
        from nvisa.oracle import discache
        got = Nvdisasm().disassemble_raw([enc_to_int(encs[i]) for i in todo], ARCH)
        ran = any(x is not None for x in got)     # 全 None = nvdisasm 根本没跑
        for i, inst in zip(todo, got):
            text = " ".join(inst.text.split()).rstrip(";").strip() if inst else ""
            out[i] = _cache_put(_DIS_CACHE, enc_to_bytes(encs[i]), text)
            if ran:                               # 逐条也存一份，单条那条路能命中
                discache.put(ARCH, enc_to_bytes(encs[i]), text)
    return out


def probe_reuse_bits(enc: str, slots: list[int]) -> int | None:
    """122:124 里哪一位管哪个源 —— **问 nvdisasm，不猜**。

    `.reuse` 位与操作数的对应**不是**「寄存器号编码在哪个字段」：生产库
    52.8 万条带 `.reuse` 的指令里那条规则错 1,255 条（10 个 key），而且两个
    方向的例外都有 —— `FADD_R_R_R`/`HADD2_R_R_R` 的第二个源在 `rb`(32:39)
    却用 124 位，`IMAD_R_R_R_II`/`FFMA_R_R_R_FI` 的操作数在 `rc`(64:71)
    却用 123 位。真正的对应是**操作数收集器端口**，逐 opcode
    不同，段表里没有这个信息。

    所以逐位试：把 `enc`（reuse 清零）的第 i 位单独打开，看 nvdisasm 把
    `.reuse` 打在第几个操作数上，反查回 slot（文本第 n 个操作数 = slot n+1，
    谓词前缀占 slot 0）。三次 nvdisasm，只在文本真带 `.reuse` 时才走。
    对不上（某位非法、或没有一位对应得上某个 slot）返回 None。
    """
    lo, hi = asm.FIELDS["reuse"]
    base = set_bits(enc, lo, hi, 0)
    # 探测用自己的控制码：**`.reuse` 只在 yield=1（不让出）且 stall>=1 时才被
    # nvdisasm 打印出来**——reuse cache 只有下一条指令背靠背发射才有意义，
    # nvdisasm 把这个约束编进了渲染。拿被编辑指令自己的控制码探测会误判成
    # 「这一位非法」（stall=0）或「这一位不管任何操作数」（yield=0）。
    base = set_bits(set_bits(base, *asm.FIELDS["stall"], 4), *asm.FIELDS["yield"], 1)
    slot_of_bit: dict[int, int] = {}
    for i, got in enumerate(_disasm_many(
            [set_bits(base, lo + i, lo + i, 1) for i in range(3)])):
        if not got:
            continue                              # 这一位在这个 opcode 上非法
        body = got.split(None, 1)[1] if " " in got else ""
        ops = [o.strip() for o in body.rstrip(";").split(",")]
        hit = [n for n, o in enumerate(ops) if ".reuse" in o]
        if len(hit) == 1:
            slot_of_bit[hit[0] + 1] = i
    out = 0
    for s in slots:
        if s not in slot_of_bit:
            return None
        out |= 1 << slot_of_bit[s]
    return out


# ---------------------------------------------------------------------------
# 统一的编辑位置校验与保存安全闸
# ---------------------------------------------------------------------------


class SiteError(ValueError):
    """写入位置不合法 —— ELF 头、非可执行段、不在指令边界或越过段末。"""


def edit_site(data: bytes, file_off: int) -> dict:
    """所有写入路径共用的位置校验：`file_off` 必须是某个**可执行段**里的一条
    完整 16 字节指令。返回 `{section, sec_off, sec_size, addr, file_off}`。

    单独摆一层是因为原来每条写入路径各查各的：`assemble_at()` 只按偏移切 16
    字节（ELF 头也照切），`apply_patch()` 只比文件长度，只有插入/删除的 `_reflow()`
    查了段和边界。位置判据只该有一份 —— 就是这里。
    """
    from nvisa.model.reflow import ReflowError, section_of
    if file_off < 0:
        raise SiteError(f"文件偏移不能是负的：{file_off}")
    try:
        _idx, name, sec_off, sec_size = section_of(data, file_off)
    except ReflowError as e:
        raise SiteError(str(e)) from None
    addr = file_off - sec_off
    if addr % INST_BYTES:
        raise SiteError(f"文件偏移 {file_off:#x}（{name} +{addr:#x}）不在指令边界上 —— "
                        f"指令是 {INST_BYTES} 字节对齐的")
    if addr + INST_BYTES > sec_size:
        raise SiteError(f"文件偏移 {file_off:#x} 那条指令越过了 {name} 的末尾"
                        f"（段大小 {sec_size:#x}）")
    return {"file_off": file_off, "section": name, "addr": addr,
            "sec_off": sec_off, "sec_size": sec_size}


def check_save(data: bytes, base: bytes | None = None) -> dict:
    """保存安全闸：改动过的每条指令都必须能被 nvdisasm 解出来。

    只查**改动过的**那些（`base` 是上次落盘的内容）—— 原文件里本来就解不出的
    位（对齐填充、非指令数据）不该拦着用户存自己的改动。`base` 为空（另存为
    新文件）时查全部可执行段。

    `bad` 是硬拦：nvdisasm 读不出来，普通保存必须被阻止。`dubious` 只是提醒：
    读得出、但 token 是 `INVALID*`，探索非法编码本来就是这个工具的用途。
    """
    bad, dubious, changed = [], [], 0
    for sec in Cubin(data).sections:
        n = sec.size - sec.size % INST_BYTES
        for a in range(0, n, INST_BYTES):
            off = sec.offset + a
            cur = bytes(data[off:off + INST_BYTES])
            if base is not None and len(base) == len(data) \
                    and bytes(base[off:off + INST_BYTES]) == cur:
                continue
            changed += 1
            was = (bytes(base[off:off + INST_BYTES])
                   if base is not None and len(base) == len(data) else None)
            row = {"file_off": off, "addr": a, "section": sec.name,
                   "enc": enc_from_bytes(cur)}
            got, answered = disasm_answer(cur)
            if not answered:
                # 问不了 nvdisasm 时什么都判不了：不能把合法编码报成非法，
                # 让用户去选「实验性保存」。
                return {"ok": False, "infrastructureError": True,
                        "changed": changed, "bad": [], "dubious": [],
                        "error": "保存安全闸需要支持 sm_90 的 nvdisasm（CUDA 12+），"
                                 "但它不在 PATH 上、版本太旧或没有响应；编码合法性未检查，"
                                 "保存已停止。请把 CUDA Toolkit 的 bin 目录加入扩展宿主的 "
                                 "PATH 后重试。"}
            if not got:
                bad.append((row, cur, was))
            elif _is_dubious(got):
                dubious.append({**row, "sass": got})
    err = None
    if bad:
        err = (f"{len(bad)} 条改动后的编码 nvdisasm 解不出来（"
               + ", ".join(f"{r['section']}+{r['addr']:#x}" for r, _, _ in bad[:4])
               + "）；确认要留着这些编码就走实验性保存")
        # 能指到字段上就别只说「解不出来」——「只改了个 stall 就再也存不进去」
        # 的时候，用户要找的其实是另一个字段。
        hints = sorted({h for _, cur, was in bad if (h := _ctrl_hint(cur, was))})
        if hints:
            err += "。" + "；".join(hints)
    bad = [r for r, _, _ in bad]
    return {"ok": not bad, "changed": changed, "bad": bad, "dubious": dubious,
            "error": err}


#: 控制段：stall/yield/barrier/wait/reuse 全在这 20 位里。
_CTRL_SPAN = (105, 124)


def _ctrl_hint(cur: bytes, base: bytes | None) -> str:
    """解不出来的这条，锅是不是在控制段？是的话把话说到字段上。

    只改控制段本来不该让 nvdisasm 罢工，但 **yield 和 stall 是一个 5 位码**：
    nvdisasm 拿 `yield<<4 | stall` 去查 `TABLES_opex_0`，yield=1（不切走）时只有
    stall 1..11 有定义（实测 stall 字段也只在 1..11 线性）。
    页面上这两个是各自独立的 chip，单改 stall 极容易掉进这个洞里 —— 报错只说
    「解不出来」的话，没人猜得到问题出在另一个字段上。

    先把控制段按基底还原一遍：还原后能解出来，才说明确实是控制段的锅。整条被
    改烂的编码（字节编辑、模板凑歪）往往也顺带带着一个非法的 yield/stall，
    不加这道判据就会把锅栽给控制段。
    """
    if base is None or len(base) != INST_BYTES:
        return ""
    lo, hi = _CTRL_SPAN
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    c, b = int.from_bytes(cur, "little"), int.from_bytes(base, "little")
    if c == b or disasm_one(cur):        # 没改、或压根解得出来：没什么可解释的
        return ""
    restored = (c & ~mask) | (b & mask)
    if not disasm_one(restored.to_bytes(INST_BYTES, "little")):
        return ""                                   # 换回原控制段也解不出：不是它的锅
    stall, yld = (c >> 105) & 0xF, (c >> 109) & 1
    if yld == 1 and not 1 <= stall <= 11:
        return (f"控制段：yield=1（不切走）时 stall 只有 1..11 有定义，现在是 "
                f"{stall} —— nvdisasm 把 yield+stall 当一个 5 位码查表，"
                f"这个组合查不到。要停这么久就把 yield 也改成 0")
    return "改动只落在控制段（bit 105:124）里 —— 这一段的取值组合不是随便填都有定义"


def _addr_of(data: bytes, file_off: int) -> int:
    """文件偏移 -> 段内地址（编辑器 addr 列那一套坐标）。

    只有 PC 相对分支用得上：文本里写的是目标地址，编码里存的是相对下一条指令
    的偏移。段头读不出来就当 0 —— 那样分支目标会按「这条指令在地址 0」
    解释，回环校验照样会挡住写错的编码。
    """
    try:
        for sec in Cubin(data).sections:
            if sec.offset <= file_off < sec.offset + sec.size:
                return file_off - sec.offset
    except Exception:                                         # noqa: BLE001
        pass
    return 0


def _assemble_spec(cur_enc: str, text: str, addr: int = 0) -> dict | None:
    """段表构造路径：段表 + fieldscan 从零构造，不要模板。

    段表认识这条文本的 key 就走这里；认不出（全新助记符 / 段表没学会的 form）
    返回 None，交回模板补丁兜底 —— 模板在「corpus 里凑得出但段表还没学会」
    的场景仍然有用（段表样本库里没有的助记符）。

    控制段不由段表构造决定：`asm.py:FIELDS` 才是权威，stall/yield/wr/rd_bar/wait
    一律沿用原指令，`.reuse` 从文本里来（`asm_spec.reuse_bits()`）。
    每个候选 key 都过 nvdisasm 回环 —— 猜错 key、猜错 reuse 位都在这里被挡住。
    候选**不截断**：`spec_keys` 现在把段表里同助记符的 form 全给出来，
    最多 15 个（LEA），猜错的会被回环拦下，截断反而可能把对的那个切掉。
    """
    from nvisa.model import asm_spec
    from nvisa.model.encode import encode_spec

    hint = identify(cur_enc)
    try:
        keys = asm_spec.spec_keys(text, hint)
    except asm_spec.AsmSpecError:
        return None                                   # 连解析都过不去，别占着路
    errors = []
    for key in keys:
        try:
            values = asm_spec.text_to_values(key, text, addr)
            enc = encode_spec(key, values)
        except Exception as e:                        # noqa: BLE001
            errors.append(f"{key}: {e}")
            continue
        slots = values.get("reuse_slots") or []
        reuse = probe_reuse_bits(enc, slots) if slots else 0
        if reuse is None:
            errors.append(f"{key}: .reuse 位对不上任何操作数（nvdisasm 探测）")
            continue
        lo, hi = asm.FIELDS["reuse"]
        enc = _inherit_ctrl(set_bits(enc, lo, hi, reuse), cur_enc)
        raw = enc_to_bytes(enc)
        got = disasm_one(raw)
        # 单条反汇编时 nvdisasm 以为这条指令在地址 0，分支目标打印的是
        # `off + 16`；用户填的是这条指令实际所在地址上的绝对目标，差一个 addr。
        shown = asm_spec.rebase(key, got, addr)
        if _norm_sass(shown) != _norm_sass(text):
            hint = ""
            if slots and ".reuse" not in got:
                # `.reuse` 只在 yield=1 且 stall>=1 时才打印（见 probe_reuse_bits）。
                # 控制段沿用原指令，原指令让出的话这条 `.reuse` 永远读不回来。
                hint = "（原指令 yield=0/stall=0，nvdisasm 不会打印 .reuse）"
            errors.append(f"{key}: 回环不符，读回 {shown!r}{hint}")
            continue
        return {"ok": True, "bytes": raw.hex(), "enc": enc, "sass": shown,
                "template": f"段表构造（{key}）", "ctrl": ctrl_of(enc),
                "ctrl_inherited": True, "spec_key": key}
    return {"ok": False, "spec_errors": errors} if errors else None


def _norm_sass(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").replace(" ,", ",").strip().rstrip(";").strip()


def assemble_at(data: bytes, file_off: int, text: str, pool_dirs: list[Path]) -> dict:
    """把某个文件偏移上的指令换成 `text`。

    两条路：先试段表构造 ——
    立即数、常量 bank、地址形式、枚举修饰符都在它的语法里；段表不认识这个
    key 时才退回模板 + 补丁。两条路最后都过 nvdisasm 回环校验。
    """
    site = edit_site(data, file_off)             # 位置校验，所有写入路径共用
    cur_enc = enc_from_bytes(data[file_off:file_off + INST_BYTES])

    spec = _assemble_spec(cur_enc, text, site["addr"])
    if spec and spec.get("ok"):
        return {**spec, "section": site["section"], "addr": site["addr"]}
    spec_errors = (spec or {}).get("spec_errors") or []

    try:
        want = asm.parse(text)
    except asm.AsmError as e:
        if spec_errors:
            return {"ok": False, "error":
                    "段表构造没通过回环，模板补丁也解析不了这条文本。\n  "
                    + "\n  ".join(spec_errors[:4]) + f"\n  模板补丁：{e}"}
        return {"ok": False, "error": str(e)}

    cur_mn = _mnemonic(disasm_one(enc_to_bytes(cur_enc)))
    # 同助记符：拿它自己当模板，修饰符原样留着，不去碰 corpus
    if cur_mn and cur_mn.split(".")[0] == want.mnemonic.split(".")[0]:
        candidates = [(cur_enc, "原指令自身")]
    else:
        pool = template_pool(data, pool_dirs)
        want_ops = len([v for v in ("rd",) if v in want.fields]) + \
            len([s for s in ("ra", "rb", "rc") if s in want.fields])
        # 预筛：助记符全等 + 操作数个数相同。IADD3 有一堆变体（带谓词输出的、
        # .X 的、立即数形式的），不筛的话前几条候选补完寄存器会读回成
        # 'IADD3 R12, P0, R8, R8, RZ'，被回环挡掉，白起一串 nvdisasm。
        exact = [(enc, src) for mn, enc, src, nops, plain in pool
                 if mn == want.mnemonic and nops == want_ops and plain]
        loose = [(enc, src) for mn, enc, src, nops, plain in pool
                 if mn.split(".")[0] == want.mnemonic.split(".")[0]]
        candidates = exact + [c for c in loose if c not in exact]
        if not candidates:
            have = sorted({mn for mn, _, _, _, _ in pool})
            return {"ok": False, "error":
                    f"找不到 {want.mnemonic} 的模板指令。\n"
                    f"换 opcode 需要一条同助记符的真实指令当模板（modifier 区 72:90 "
                    f"是逐 opcode 的含义，不能通用编码）。\n"
                    f"可用的助记符：{', '.join(have)}\n"
                    f"想要别的，就用 inline PTX 逼 ptxas 生成一条放进模板目录。"}

    # 先打完补丁再按编码去重：几十条同助记符的模板，补完寄存器往往就是同一条，
    # 没必要为每条都起一个 nvdisasm 做回环
    errors = []
    seen: dict[str, str] = {}
    for tmpl, src in candidates:
        try:
            enc = asm.assemble(tmpl, text)
        except asm.AsmError as e:
            errors.append(f"{src}: {e}")
            continue
        if src != "原指令自身":
            enc = _inherit_ctrl(enc, cur_enc)
        seen.setdefault(enc, src)

    norm = _norm_sass
    for enc, src in list(seen.items())[:8]:          # 去重后仍不唯一才多试几条
        raw = enc_to_bytes(enc)
        got = disasm_one(raw)
        # 回环：nvdisasm 把我们造的编码读回来，必须就是想要的那条
        if norm(got) != norm(want.render()):
            errors.append(f"{src}: 回环不符，读回 {got!r}")
            continue
        return {"ok": True, "bytes": raw.hex(), "enc": enc, "sass": got,
                "template": src, "ctrl": ctrl_of(enc),
                "ctrl_inherited": src != "原指令自身",
                "section": site["section"], "addr": site["addr"]}

    return {"ok": False, "error":
            "回环校验都没过 —— 造出来的编码不是想要的那条指令。\n"
            "多半是这条指令有未标定的字段，或模板选到了别的 opcode 变体。\n  "
            + "\n  ".join((spec_errors + errors)[:4])}


# ---------------------------------------------------------------------------
# 批量编辑 —— 导出/应用 JSON patch
# ---------------------------------------------------------------------------

#: 带版本的 patch schema。v2 相对 v1 多了 `arch`/`mode` 和逐条的 `op`，
#: 并把「位置」的权威从 `file_off` 换成 `(section, addr)` —— 文件偏移是**这个**
#: cubin 的坐标，换一个 cubin 就不成立了（section 在文件里的位置不一样）。
#: v1 仍然读得进来（缺的字段按 in-place/replace 补），只是不会再导出。
PATCH_FORMAT = "nv_isa-cubin-patch/2"
PATCH_FORMATS = {"nv_isa-cubin-patch/1", "nv_isa-cubin-patch/2"}
PATCH_MODE = "in-place"                 # 这套 schema 只表达**原地替换**
PATCH_OPS = {"replace"}                 # insert/delete/rebase 还没进 schema


class PatchError(ValueError):
    """patch 本身不合法 —— 版本、架构、模式、操作类型对不上。"""


def _layout(data: bytes) -> list[tuple]:
    """ELF 布局指纹：段名 + 文件偏移 + 大小。原地编辑不该动它里面任何一项。"""
    from nvisa.model.reflow import _headers
    return [(n, off, size) for n, _t, _f, _a, off, size in _headers(data)]


def _outside_exec(data: bytes) -> list[tuple[int, int]]:
    """可执行段之外的区间 —— patch 表达不了这些字节的变化。"""
    spans = sorted((s.offset, s.offset + s.size) for s in Cubin(data).sections)
    out, pos = [], 0
    for lo, hi in spans:
        if lo > pos:
            out.append((pos, lo))
        pos = max(pos, hi)
    if pos < len(data):
        out.append((pos, len(data)))
    return out


def export_patch(path: Path, data: bytes, base: bytes) -> dict:
    """把「改过的缓冲区 vs 原文件」的差异导成 patch。

    每条改动记 `enc` + `origin`，跟批量扫描工具的 JSONL 产出
    （`{enc, origin, ...}`）说同一种话，两个方向都能互喂。
    额外记的 `file_off`/`addr`/`section`/`key` 是**位置**，`before` 是应用时
    的安全闸（目标不是这条指令就拒绝，除非 `--force`）。
    """
    # schema 只说得出「原地替换第 N 条指令」。布局一变（插入/删除改了
    # `.nv.info` 的指令偏移、section 大小变了、文件长度变了）就**拒绝导出** ——
    # 导出一份只带指令字节的 patch，打到副本上会得到一个 `.nv.info` 指错地方的
    # 文件，比报错糟得多。
    if len(data) != len(base):
        return {"ok": False, "error":
                f"文件长度变了（{len(base)} → {len(data)}）；patch 只表达原地替换，"
                f"扩容/缩容请直接分发改完的 cubin"}
    try:
        same_layout = _layout(data) == _layout(base)
    except Exception as e:                                    # noqa: BLE001
        return {"ok": False, "error": f"改过的内容已经不是一份读得出的 ELF：{e}"}
    if not same_layout:
        return {"ok": False, "error":
                "ELF 布局变了（段的偏移或大小不一样了）；patch 只表达原地替换"}
    for lo, hi in _outside_exec(data):
        if data[lo:hi] != base[lo:hi]:
            return {"ok": False, "error":
                    f"可执行段之外的字节变了（文件偏移 {lo:#x}..{hi:#x}，"
                    f"多半是插入/删除挪指令时改了 `.nv.info` 里的指令偏移）；"
                    f"patch 只表达原地替换的指令，表达不了这些 —— "
                    f"要分发这类改动就直接给改完的 cubin"}
    cur = build(path, None, data)
    old = build(path, None, base)
    old_by_off = {i["file_off"]: i
                  for s in old["sections"] for i in s.get("insns", [])}
    edits = []
    for sec in cur["sections"]:
        for i in sec.get("insns", []):
            o = old_by_off.get(i["file_off"])
            if o is not None and o["bytes"] == i["bytes"]:
                continue
            edits.append({
                "op": "replace",
                "file_off": i["file_off"], "addr": i["addr"], "section": sec["name"],
                "key": i.get("key"), "enc": i["enc"], "sass": i.get("sass") or "",
                "origin": f"edit:{path.name}@+0x{i['file_off']:x}",
                "before": {"enc": o["enc"] if o else None,
                           "sass": (o.get("sass") or "") if o else None},
            })
    return {"ok": True, "format": PATCH_FORMAT, "arch": ARCH, "mode": PATCH_MODE,
            "file": path.name, "count": len(edits), "edits": edits}


def _check_schema(patch: dict) -> None:
    """版本 / 架构 / 模式 / 操作类型，逐项校验，对不上就整份拒绝。"""
    fmt = patch.get("format")
    if fmt not in PATCH_FORMATS:
        raise PatchError(f"不认识的 patch 版本 {fmt!r}（认得：{sorted(PATCH_FORMATS)}）")
    arch = patch.get("arch")
    if arch is not None and arch != ARCH:
        raise PatchError(f"这份 patch 是 {arch} 的，这个工装只认 {ARCH}")
    mode = patch.get("mode", PATCH_MODE)
    if mode != PATCH_MODE:
        raise PatchError(f"不支持的 patch 模式 {mode!r} —— schema 只表达 "
                         f"{PATCH_MODE}（插入/删除请用 --insert/--delete）")
    for e in patch.get("edits") or []:
        op = e.get("op", "replace")
        if op not in PATCH_OPS:
            raise PatchError(f"不支持的操作 {op!r} —— schema 只有 "
                             f"{sorted(PATCH_OPS)}；insert/delete/rebase 还没进 schema")


def _patch_edits(patch: object, at: int | None) -> list[dict]:
    """接受两种输入：本工装导出的 patch 对象，或 `probe()` 那种
    `{enc, origin}` 的 JSONL 记录列表（后者没有位置，得用 `--at` 补）。"""
    if isinstance(patch, dict) and "edits" in patch:
        _check_schema(patch)
        return list(patch["edits"])
    recs = patch if isinstance(patch, list) else [patch]
    if at is None:
        raise ValueError("这是一份没有位置信息的扫描记录（只有 enc），"
                         "要配 --at <文件偏移> 说明打到哪条指令上")
    return [{"file_off": at, "enc": r["enc"], "sass": r.get("sass") or "",
             "origin": r.get("origin", "")} for r in recs if r.get("enc")]


def _resolve_site(data: bytes, e: dict, force: bool) -> tuple[int, bool]:
    """patch 里的位置该怎么落到**这个** cubin 上。

    权威是 `(section, addr)` 而不是 `file_off` —— 文件偏移是导出那个 cubin 的
    坐标，换一个 cubin（哪怕是同一份源码换个编译单元）section 在文件里的位置
    就变了。section 名同时就是**函数身份**：ptxas 给每个 kernel/device function
    单独出一个 `.text.<mangled>`，名字对上才是同一个函数。

    返回 `(file_off, 重定位过没有)`。目标里没有这个 section 就拒绝（`--force`
    才退回照抄 `file_off`）。
    """
    off = e.get("file_off")
    name, addr = e.get("section"), e.get("addr")
    if not name or addr is None:
        if off is None:
            raise PatchError("这条改动既没有 (section, addr) 也没有 file_off")
        return off, False
    for sec in Cubin(data).sections:
        if sec.name == name:
            return sec.offset + addr, sec.offset + addr != off
    if force or off is None:
        if off is None:
            raise PatchError(f"目标 cubin 里没有 section {name!r}，也没有 file_off 兜底")
        return off, False
    raise PatchError(
        f"目标 cubin 里没有 section {name!r}（patch 里这条在它的 +{addr:#x} 处）—— "
        f"section 名就是函数身份，对不上就不是同一个函数；"
        f"确认要按文件偏移硬打就加 --force")


def _relocate_sass(e: dict, dst_addr: int, need_text: bool) -> tuple[str, bool]:
    """patch 里记的**绝对**分支目标，换个地址就得重定位。

    `sass` 是从源 cubin 的 `nvdisasm -c` 来的，分支目标是**那个** cubin 里的
    绝对地址。同一条指令摆到别处（别的 cubin、或同一段的别的地址）时，PC 相对
    分支该保的是「跳多远」不是「跳到哪个绝对地址」——
    新目标 = 旧目标 − 源地址 + 目标地址。

    返回 `(该指令在目标位置上应有的文本, 能不能拿它做回环比对)`。明确拒绝
    两类：符号标号（目标地址不在指令身上，得有汇编器的符号表）和 `.ABS`
    （绝对目标属于源 cubin 的地址空间，自动搬过去只会指错）。
    """
    from nvisa.model import asm_spec
    text = (e.get("sass") or "").strip()
    if not text:
        return "", False
    src_addr, key = e.get("addr"), e.get("key")
    if asm_spec._LABEL.search(text):
        if need_text:
            raise PatchError(f"目标是符号标号（{text}）—— 地址不在指令身上，"
                             f"跨 cubin 按文本重汇编表达不了；改用照抄编码")
        return text, False                      # 照抄编码可以，但没法逐字比对
    fact = asm_spec.pc_offset_fact(key) if key else None
    if not fact or src_addr is None or src_addr == dst_addr:
        return text, True                       # 不是 PC 相对分支，或位置没变
    if asm_spec._is_absolute(text):
        raise PatchError(f"`.ABS` 的目标是源 cubin 的绝对地址（{text}），"
                         f"挪到 +{dst_addr:#x} 之后指的不是同一个地方 —— "
                         f"这类分支不自动重定位")
    tgt = asm_spec.target_of(text)
    if tgt is None:
        return text, False
    m = asm_spec._TAIL_NUM.search(text.rstrip(";").strip())
    new = tgt - src_addr + dst_addr
    body = text.rstrip(";").strip()
    return body[:m.start(1)] + f"{new:#x}" + body[m.end(1):], True


def apply_patch(path: Path, data: bytes, patch: object, *, at: int | None = None,
                by_sass: bool = False, force: bool = False, partial: bool = False,
                pool_dirs: list[Path] | None = None) -> dict:
    """把 patch 打到 `data` 上。返回逐条结果 + 打完的字节。

    两种打法：
      - 默认**照抄编码**（`enc`）—— 精确复现，连没被解释的位都一样；
      - `by_sass=True` **按文本重新汇编**（走 `assemble_at()`）——
        跨 cubin 复现时用：目标那条指令的**控制段会被沿用**，不会把源 cubin
        的调度结果搬过来（理由同 `_INHERIT`）。

    安全闸：schema 版本/架构/模式/操作类型先整份校验；位置按
    `(section, addr)` 落到这个 cubin 上（section 名就是函数身份），再过
    `edit_site()`；`before.enc` 对不上就跳过这条（`force=True` 才照打）；
    打完用 nvdisasm 读回，与 patch 里记的 `sass`（分支目标已重定位）不符也
    算失败 —— 与 `assemble_at()` 同一条判据。

    **默认 all-or-nothing**：有一条没打成就整份不落地（`data` 返回 None），
    免得留下一个「改了一半」的 cubin。`partial=True` 才允许部分成功。
    """
    from nvisa.model import asm_spec
    buf = bytearray(data)
    results, applied = [], 0
    try:
        edits = _patch_edits(patch, at)
    except PatchError as err:
        return {"ok": False, "applied": 0, "failed": 0, "results": [],
                "data": None, "error": str(err)}
    for e in edits:
        row = {"file_off": e.get("file_off"), "origin": e.get("origin", ""),
               "op": e.get("op", "replace"), "ok": False}
        try:
            off, moved = _resolve_site(bytes(buf), e, force)
            site = edit_site(bytes(buf), off)     # 位置校验，--force 也不放行
        except (PatchError, SiteError) as err:
            row["error"] = str(err)
            results.append(row)
            continue
        row.update(file_off=off, section=site["section"], addr=site["addr"])
        if moved:
            row["relocated"] = True               # 按 (section, addr) 重新落的位
        try:
            want_sass, comparable = _relocate_sass(e, site["addr"], by_sass)
        except PatchError as err:
            row["error"] = str(err)
            results.append(row)
            continue
        if want_sass != (e.get("sass") or "").strip():
            row["sass_relocated"] = want_sass     # 分支目标按新地址改写过
        cur = enc_from_bytes(bytes(buf[off:off + INST_BYTES]))
        want_before = (e.get("before") or {}).get("enc")
        if want_before and cur != want_before and not force:
            row["error"] = (f"这个偏移上不是 patch 记的那条指令"
                            f"（现在是 {disasm_one(enc_to_bytes(cur))!r}）"
                            f"；确认要照打就加 --force")
            results.append(row)
            continue
        if by_sass:
            if not want_sass:
                row["error"] = "--by-sass 需要 patch 里有 sass 文本"
                results.append(row)
                continue
            res = assemble_at(bytes(buf), off, want_sass, pool_dirs or [])
            if not res.get("ok"):
                row["error"] = res.get("error", "汇编失败")
                results.append(row)
                continue
            enc = res["enc"]
        else:
            enc = e.get("enc")
            if not enc:
                row["error"] = "这条改动没有 enc，也没开 --by-sass"
                results.append(row)
                continue
        raw = enc_to_bytes(enc)
        got = disasm_one(raw)
        # 单条反汇编时 nvdisasm 以为这条在地址 0，分支目标要换回真实坐标
        shown = asm_spec.rebase(e["key"], got, site["addr"]) if e.get("key") else got
        if want_sass and comparable and _norm_sass(shown) != _norm_sass(want_sass):
            row["error"] = f"回环不符：读回 {shown!r}，patch 记的是 {want_sass!r}"
            results.append(row)
            continue
        if not got and not force:
            # patch 没记 sass 时上面那道回环闸是空的。安全模式下至少要求
            # 打进去的编码 nvdisasm 解得出来；探索非法编码走 --force。
            row["error"] = ("这条编码 nvdisasm 解不出来（patch 里也没有 sass "
                            "可供回环校验）；确认要照打就加 --force")
            results.append(row)
            continue
        buf[off:off + INST_BYTES] = raw
        row.update(ok=True, enc=enc, bytes=raw.hex(), sass=shown)
        applied += 1
        results.append(row)
    failed = len(results) - applied
    # all-or-nothing：默认一条不成就整份不落地
    keep = applied and (not failed or partial)
    return {"ok": failed == 0, "applied": applied, "failed": failed,
            "partial": bool(partial), "results": results,
            "data": bytes(buf).hex() if keep else None}


# --- 插入 / 删除指令（定长，不动 ELF 布局）------------------------------


def _section_encs(data: bytes, sec_off: int, sec_size: int) -> dict[int, str]:
    n = sec_size - sec_size % INST_BYTES
    return {a: enc_from_bytes(data[sec_off + a:sec_off + a + INST_BYTES])
            for a in range(0, n, INST_BYTES)}


def _section_texts(data: bytes, name: str) -> dict[int, str]:
    """整段的反汇编文本（`nvdisasm -c`，标号形式）。只用来判 `.ABS`、认助记符。

    按内容缓存：一次插入/删除会为同一份字节问三遍（挪之前、复核、报里的
    `sass`）。缓存键必须包含 section 名：每个 kernel 的地址都从零开始。不能拿
    section 名当临时文件名 —— 模板生成的 C++ 符号很容易超过 Linux 的 NAME_MAX。
    """
    key = (data, name)
    if key in _SECTEXT_CACHE:
        return _SECTEXT_CACHE[key]
    return _cache_put(_SECTEXT_CACHE, key, _section_texts_uncached(data, name))


def _section_texts_uncached(data: bytes, name: str) -> dict[int, str]:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="cubin-sass-") as d:
        tmp = Path(d) / "input.cubin"
        tmp.write_bytes(data)
        return sass_by_sections(tmp).get(name, {})


def _nop_enc(encs: dict[int, str]) -> str:
    """段里现成的一条 `NOP`（尾部对齐填充里一定有）。找不到就自己造一条。"""
    for a in sorted(encs, reverse=True):
        if _mnemonic(disasm_one(enc_to_bytes(encs[a]))) == "NOP":
            return encs[a]
    r = _assemble_spec("0" * 32, "NOP")
    if r and r.get("ok"):
        return r["enc"]
    raise reflow_error("段里没有现成的 NOP，也造不出一条")


def reflow_error(msg: str):
    from nvisa.model.reflow import ReflowError
    return ReflowError(msg)


def _reflow(data: bytes, file_off: int, delta: int, text: str | None,
            pool_dirs: list[Path], force: bool = False) -> dict:
    """插入（`delta=+16`）/删除（`delta=-16`）的公共骨架。

    做的事按顺序：切出窗口 -> 整段分支重定位 -> 挪字节 -> 填/装那一条 ->
    改 `.nv.info` 的指令偏移 -> 交回 nvdisasm 全量复核。任何一步不确定都
    **拒绝**并说清楚原因，不留半个改坏的文件。
    """
    from nvisa.model import reflow

    site = edit_site(data, file_off)             # 位置校验，所有写入路径共用
    sec_idx, sec_name, sec_off, sec_size = reflow.section_of(data, file_off)
    addr = site["addr"]
    wend = reflow.window_end(data, sec_idx, sec_size, addr)
    shift = reflow.Shift(addr, wend, delta)

    encs = _section_encs(data, sec_off, sec_size)
    texts = _section_texts(data, Path(sec_name).name or "sec.cubin")

    if delta > 0:
        tail = wend - INST_BYTES
        if tail <= addr:
            raise reflow_error("窗口里只剩这一条，插不进去")
        if _mnemonic(disasm_one(enc_to_bytes(encs[tail]))) != "NOP":
            raise reflow_error(
                f"窗口末尾（{tail:#x}，下一个函数起点/段末之前的最后一条）不是 NOP —— "
                f"插入要吃掉它。预览里的插入不扩容 `.text`，也不跨函数边界挪，"
                f"所以只能用尾部对齐填充的 NOP 额度")

    moved_encs, log = reflow.relocate_branches(encs, shift, texts)

    new_sec: dict[int, str] = {}
    for a, enc in encs.items():
        na = shift.map(a)
        if na is None:
            continue
        new_sec[na] = moved_encs.get(a, enc)

    buf = bytearray(data)
    for a, enc in new_sec.items():
        buf[sec_off + a:sec_off + a + INST_BYTES] = enc_to_bytes(enc)

    hole = addr if delta > 0 else wend - INST_BYTES
    if delta > 0:
        # 空出来的那一格先摆上原来在这儿的那条 —— 下面 assemble_at() 的控制段
        # 沿用规则于是拿到的是紧邻这条的调度参数，而不是别的 cubin 的。
        buf[sec_off + hole:sec_off + hole + INST_BYTES] = enc_to_bytes(encs[addr])
        r = assemble_at(bytes(buf), sec_off + hole, text or "", pool_dirs)
        if not r.get("ok"):
            return r
        buf[sec_off + hole:sec_off + hole + INST_BYTES] = bytes.fromhex(r["bytes"])
    else:
        buf[sec_off + hole:sec_off + hole + INST_BYTES] = enc_to_bytes(_nop_enc(encs))

    nvinfo, _suspect = reflow.relocate_nvinfo(buf, sec_idx, shift, force)

    check = _verify_reflow(bytes(buf), sec_off, sec_name, shift, texts, encs)
    if check:
        raise reflow_error(check)

    return {"ok": True, "data": bytes(buf).hex(), "section": sec_name,
            "addr": addr, "window": [shift.start, shift.end],
            "moved": len(list(shift.moved())),
            "dropped": shift.dropped,
            "relocated": log, "nvinfo": nvinfo,
            "sass": _section_texts(bytes(buf), sec_name).get(hole, "")}


def _verify_reflow(data: bytes, sec_off: int, sec_name: str, shift,
                   texts: dict, encs: dict) -> str:
    """交回 nvdisasm 复核，复核不过就整个拒绝：

    - 挪过的每条（分支除外）文本必须逐字没变；
    - 每条分支挪完之后指向的，必须正好是它原来那个目标的新地址；
    - 全段每条都还读得出来。

    目标是**用 nvdisasm 读回来的**（单条反汇编 + `rebase()` 换坐标），不是拿
    自己刚写进去的位再算一遍 —— 后者等于自己给自己判卷。
    """
    from nvisa.model import asm_spec
    now = _section_texts(data, Path(sec_name).name or "sec.cubin")
    for a in shift.moved():
        na = a + shift.delta
        was, got = texts.get(a, ""), now.get(na, "")
        if not got:
            return f"挪完之后 {na:#x} 上这条 nvdisasm 读不出来了"
        if _is_branch_text(was):
            continue                       # 分支的目标本来就该变，下面单独验
        if _norm_sass(was) != _norm_sass(got):
            return f"挪完之后 {a:#x} 的指令变了：{was!r} -> {got!r}"

    for a, old_enc in sorted(encs.items()):
        na = shift.map(a)
        if na is None:
            continue
        key = identify(old_enc)
        fact = asm_spec.pc_offset_fact(key) if key else None
        if not fact:
            continue
        absolute = ".ABS" in (texts.get(a) or "").upper()
        old_off = asm_spec.read_offset(fact, old_enc)
        old_target = old_off if absolute else a + INST_BYTES + old_off
        want = shift.map(old_target)
        enc = enc_from_bytes(data[sec_off + na:sec_off + na + INST_BYTES])
        lone = disasm_one(enc_to_bytes(enc))
        got = asm_spec.target_of(lone if absolute
                                 else asm_spec.rebase(key, lone, na))
        if got != want:
            return (f"{a:#x} 的分支挪到 {na:#x} 之后目标不对："
                    f"应该指到 {want:#x}，nvdisasm 读回 {got}")
    return ""


def _is_branch_text(text: str) -> bool:
    mn = _mnemonic(text or "")
    return mn.split(".")[0] in ("BRA", "CALL", "RET", "JMP", "BRX", "JMX")


def insert_at(data: bytes, file_off: int, text: str,
              pool_dirs: list[Path] | None = None, force: bool = False) -> dict:
    """在这个文件偏移上**插入**一条指令，后面的整体下移一格，吃掉窗口末尾的
    一条 NOP。"""
    return _reflow(data, file_off, INST_BYTES, text, pool_dirs or [], force)


def delete_at(data: bytes, file_off: int, force: bool = False) -> dict:
    """**删掉**这个文件偏移上的指令，后面的整体上移一格，窗口末尾补一条 NOP。"""
    return _reflow(data, file_off, -INST_BYTES, None, [], force)


def build(path: Path, diff: Path | None, data: bytes | None = None,
          include_cells: bool = True) -> dict:
    """`data` 非空时用它代替磁盘内容 —— 编辑器里改了还没保存的缓冲区走这条路。"""
    import tempfile
    if data is None:
        cub, sass = Cubin.load(path), sass_by_sections(path)
    else:
        cub = Cubin(data)
        with tempfile.TemporaryDirectory(prefix="cubin-sass-") as d:
            tmp = Path(d) / "input.cubin"
            tmp.write_bytes(data)
            sass = sass_by_sections(tmp)
    other = Cubin.load(diff).data if diff else None
    secs = []
    for sec in cub.sections:
        secs.append({
            "name": sec.name,
            "offset": sec.offset,
            "size": sec.size,
            "insns": instructions(cub, sec, sass.get(sec.name, {}),
                                    bytes(other) if other else None,
                                    include_cells=include_cells),
        })
    return {
        "ok": True,
        "path": str(path),
        "diff_against": str(diff) if diff else None,
        "have_nvdisasm": bool(sass),
        "cells_loaded": include_cells,
        "fields": field_table(),
        "sections": secs,
    }


def _debug_request(a):
    """调试 section 策略的命令行请求 → `DebugRequest`；没给任何调试选项就返回 None（走兼容路径）。"""
    from nvisa.model.debug_policy import DebugRequest
    per = {}
    for item in a.debug_section:
        if "=" not in item:
            raise ValueError(f"--debug-section 要写成 NAME=POLICY，收到 {item!r}")
        name, policy = item.split("=", 1)
        per[name] = policy
    if not a.debug_policy and not per:
        return None
    if a.strip_debug:
        raise ValueError("--strip-debug 和 --debug-policy/--debug-section 说的是"
                         "同一件事，只给一种")
    return DebugRequest(default=a.debug_policy, per_section=per)


def _image(data: bytes, image: int | None):
    """Select the editable cubin from standalone bytes or a host fatbinary."""
    from nvisa.model.fatbin import open_cubin_image
    return open_cubin_image(data, image=image, sm=90)


def _read_image(a, *, stdin: bool | None = None):
    use_stdin = a.stdin if stdin is None else stdin
    raw = sys.stdin.buffer.read() if use_stdin else a.cubin.read_bytes()
    return _image(raw, a.image)


def _offset_body(body: dict, image, payload_only: bool = False) -> dict:
    """Map cubin-relative result offsets/data back to the outer host ELF.

    With ``payload_only`` an embedded image's ``data`` stays the inner cubin and
    ``data_scope`` says so: the caller already holds the host file, and sending
    the whole executable back as hex would double its size on the pipe.
    """
    if not image.embedded:
        body.setdefault("container", image.info())
        return body
    delta = image.payload_offset
    for sec in body.get("sections") or []:
        if isinstance(sec, dict):
            if isinstance(sec.get("offset"), int):
                sec["offset"] += delta
            for row in sec.get("insns") or []:
                if isinstance(row.get("file_off"), int):
                    row["file_off"] += delta
    for key in ("bad", "dubious", "results", "edits"):
        for row in body.get(key) or []:
            if isinstance(row, dict) and isinstance(row.get("file_off"), int):
                row["file_off"] += delta
                if key == "edits" and isinstance(row.get("origin"), str):
                    row["origin"] = re.sub(
                        r"@\+0x[0-9a-fA-F]+$", f"@+0x{row['file_off']:x}",
                        row["origin"])
    if body.get("data"):
        if payload_only:
            image.replace(bytes.fromhex(body["data"]))   # 只校验等长，不拼整份
            body["data_scope"] = "payload"
        else:
            body["data"] = image.replace(bytes.fromhex(body["data"])).hex()
    body["container"] = image.info()
    return body


def _inner_patch_offsets(patch, image):
    """Translate fallback file offsets; section+addr entries need no rewrite."""
    if not image.embedded:
        return patch
    # Work on JSON-shaped input without mutating the caller's decoded object.
    patch = json.loads(json.dumps(patch))
    rows = patch.get("edits", []) if isinstance(patch, dict) else \
        (patch if isinstance(patch, list) else [patch])
    for row in rows:
        if not isinstance(row, dict) or row.get("section"):
            continue
        off = row.get("file_off")
        if isinstance(off, int):
            row["file_off"] = image.inner_offset(off)
    return patch


def _read_stdin_text() -> str:
    """Source text from stdin as UTF-8 (the extension's encoding), not the locale's."""
    buf = getattr(sys.stdin, "buffer", None)
    return buf.read().decode("utf-8") if buf is not None else sys.stdin.read()


def _outer_bytes(body: dict, image) -> bytes:
    """The whole output file for ``--out``, whatever ``data_scope`` says."""
    data = bytes.fromhex(body["data"])
    return image.replace(data) if body.get("data_scope") == "payload" else data


def _atomic_write(path: Path, data: bytes) -> None:
    """Write beside the target and atomically replace it, preserving its mode.

    A symlinked target keeps its link: the file it points to is replaced.
    """
    import os
    import tempfile
    path = Path(os.path.realpath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    old_mode = (path.stat().st_mode & 0o7777) if path.exists() else None
    fd, name = tempfile.mkstemp(prefix=".cubin-sass-", dir=str(path.parent))
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if old_mode is not None:
            os.chmod(tmp, old_mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cubin", type=Path)
    ap.add_argument("--image", type=int, default=None,
                    help="宿主 ELF 有多个 sm_90 cubin 时，选择 fatbin image 编号")
    ap.add_argument("--diff", type=Path, default=None,
                    help="另一个 cubin：按文件偏移逐条比，不同的标 diff=true")
    ap.add_argument("--stdin", action="store_true",
                    help="cubin 内容从 stdin 读（编辑器里未保存的缓冲区），"
                         "位置参数只用来取文件名")
    ap.add_argument("--no-cells", action="store_true",
                    help="预览轻量模式：跳过逐条 InsKey/格子分析；VS Code 在用户"
                         "勾选格子时再请求完整结果")
    ap.add_argument("--inspect", metavar="HEX32", default=None,
                    help="只解一条指令：给 32 个十六进制字符，返回 sass + ctrl")
    ap.add_argument("--assemble", metavar="SASS", default=None,
                    help="把 --at 处的指令换成这条 SASS 文本（模板+补丁+回环校验）")
    ap.add_argument("--at", type=lambda s: int(s, 0), default=None,
                    help="--assemble 的目标文件偏移")
    ap.add_argument("--templates", metavar="DIR", action="append", default=None,
                    help="额外的模板 cubin 目录，可给多次（默认 corpus/cubins）")
    ap.add_argument("--insert", metavar="SASS", default=None,
                    help="在 --at 处插入一条指令，后面的整体下移一格，"
                         "吃掉窗口末尾的一条 NOP")
    ap.add_argument("--delete", action="store_true",
                    help="删掉 --at 处的指令，后面的整体上移一格，末尾补 NOP")
    ap.add_argument("--emit-source", action="store_true",
                    help="把一个 .text section 导成 .nvsass 源码；"
                         "配 --section 指定是哪一个")
    ap.add_argument("--all-sections", action="store_true",
                    help="配 --emit-source：把所有 .text section 导进同一份可折叠源码")
    ap.add_argument("--assemble-source", metavar="FILE", type=Path, default=None,
                    help="把一份 .nvsass 源码整段汇编回这个 cubin；"
                         "支持增删指令（重排 section 并更新符号、重定位和 .nv.info）。给 `-` 就从标准"
                         "输入读源码，重绑后的文本只在响应的 source 字段里回给"
                         "调用方（虚拟文档模式：源码根本不在磁盘上）")
    ap.add_argument("--smoke", action="store_true",
                    help="--assemble-source 保存前把产物交给驱动 cuModuleLoad 一次"
                         "（只加载不发射；没 GPU 记「跳过」而不是「通过」）")
    ap.add_argument("--strip-debug", action="store_true",
                    help="--assemble-source 变长时剥离行号类调试信息"
                         "（手写 SASS 之后它证明不了还对；默认是拒绝）。"
                         "等价于 --debug-policy strip，两者只能给一个")
    ap.add_argument("--debug-policy", choices=("preserve", "strip", "rewrite"),
                    help="所有调试 section 的策略。preserve 需要 proof（布局"
                         "没变，或证明不引用被改范围）；rewrite 只有 .debug_frame "
                         "支持")
    ap.add_argument("--debug-section", action="append", metavar="NAME=POLICY",
                    default=[], help="给单个调试 section 指定策略，"
                                     "覆盖 --debug-policy（可重复）")
    ap.add_argument("--section", metavar="NAME", default=None,
                    help="--emit-source 的目标 section（多 .text 时必给）")
    ap.add_argument("--check-save", action="store_true",
                    help="保存安全闸：改动过的每条指令都必须能被 nvdisasm 解出；"
                         "配 --diff <上次落盘的内容> 说明改动是相对谁算的")
    ap.add_argument("--export-patch", action="store_true",
                    help="把「当前内容 vs --diff 给的原文件」的差异导成 JSON patch")
    ap.add_argument("--apply-patch", metavar="FILE", type=Path, default=None,
                    help="把一份 patch（或 probe 的 JSONL 扫描记录）打到这个 cubin 上")
    ap.add_argument("--by-sass", action="store_true",
                    help="--apply-patch 时按文本重新汇编，而不是照抄编码"
                         "（跨 cubin 复现：目标的控制段沿用原指令）")
    ap.add_argument("--partial", action="store_true",
                    help="--apply-patch 时允许部分成功（默认 all-or-nothing："
                         "有一条没打成就整份不落地）")
    ap.add_argument("--force", action="store_true",
                    help="--apply-patch 时即使目标偏移上不是 patch 记的那条也照打；"
                         "--insert/--delete 时跳过 .nv.info 里认不出的属性那道闸")
    ap.add_argument("--payload-only", action="store_true",
                    help="宿主 ELF 时，JSON 的 data 只回内嵌 cubin（data_scope=payload），"
                         "由调用方自己回填；--out 仍写完整文件")
    ap.add_argument("--out", type=Path, default=None,
                    help="--apply-patch / --insert / --delete 的结果写到这个文件"
                         "（默认只回 JSON）")
    a = ap.parse_args()
    try:
        if a.assemble is not None:
            if a.at is None:
                raise ValueError("--assemble 需要配 --at <文件偏移>")
            image = _read_image(a)
            dirs = [Path(d) for d in (a.templates or [])]
            default_pool = Path(__file__).resolve().parent.parent / "corpus" / "cubins"
            if not dirs and default_pool.is_dir():
                dirs = [default_pool]
            body = assemble_at(image.cubin, image.inner_offset(a.at), a.assemble, dirs)
            body = _offset_body(body, image)
        elif a.insert is not None or a.delete:
            if a.at is None:
                raise ValueError("--insert/--delete 需要配 --at <文件偏移>")
            image = _read_image(a)
            dirs = [Path(d) for d in (a.templates or [])]
            default_pool = Path(__file__).resolve().parent.parent / "corpus" / "cubins"
            if not dirs and default_pool.is_dir():
                dirs = [default_pool]
            at = image.inner_offset(a.at)
            body = (insert_at(image.cubin, at, a.insert, dirs, a.force)
                    if a.delete is False else delete_at(image.cubin, at, a.force))
            body = _offset_body(body, image, a.payload_only)
            if a.out and body.get("data"):
                _atomic_write(a.out, _outer_bytes(body, image))
                body["written"] = str(a.out)
        elif a.emit_source:
            from nvisa.model.sass_source import emit_all_sources, emit_source
            if a.all_sections and a.section:
                raise ValueError("--all-sections 和 --section 只能给一个")
            image = _read_image(a)
            data = image.cubin
            if a.all_sections:
                src = emit_all_sources(data)
                body = {"ok": True, "section": "__all_text_sections__",
                        "sections": src.sections, "base": src.base_hash,
                        "source": src.text, "warnings": src.warnings}
            else:
                src = emit_source(data, a.section)
                body = {"ok": True, "section": src.section, "base": src.base_hash,
                        "source": src.text, "labels": {f"{k:#x}": v
                                                       for k, v in src.labels.items()},
                        "warnings": src.warnings}
            body["container"] = image.info()
            if a.out:
                _atomic_write(a.out, src.text.encode("utf-8"))
                body["written"] = str(a.out)
        elif a.assemble_source is not None:
            # 整条链是一次事务 —— 解析→汇编→打包→全量验证，全过才落盘。
            # 给了 --out 就走 `save_source()`（临时文件 + 原子替换）；没给就只
            # 汇编+验证，把字节回给调用方，磁盘上一个字节不动。
            from nvisa.model.sass_asm import Diagnostic, SourceAsmError
            from nvisa.model.sass_save import dry_run, save_source
            from_stdin = str(a.assemble_source) == "-"
            if from_stdin and a.stdin:
                raise ValueError("--assemble-source - 已经占了标准输入，"
                                 "基底不能再走 --stdin")
            src_text = (_read_stdin_text() if from_stdin
                        else a.assemble_source.read_text(encoding="utf-8"))
            debug_req = _debug_request(a)
            try:
                # Source on stdin occupies stdin, so its base always comes from
                # the path.  Otherwise --stdin may carry an unsaved editor buffer.
                image = _read_image(a, stdin=(a.stdin and not from_stdin))
                if a.out and not image.embedded:
                    # Keep the standalone path's full external verification and
                    # optional cuModuleLoad smoke exactly as before.
                    rep = save_source(
                        a.cubin, src_text, out_path=a.out, force=a.force,
                        strip_debug=a.strip_debug and not debug_req,
                        debug=debug_req, smoke=a.smoke,
                        base_data=image.cubin if a.stdin else None)
                    out_data = outer_data = None
                else:
                    if image.embedded and a.smoke:
                        raise ValueError(
                            "宿主 ELF 的 --smoke 暂不支持；请先提取 cubin 单独做 cuModuleLoad")
                    out_data, rep = dry_run(
                        image.cubin, src_text, force=a.force,
                        strip_debug=a.strip_debug and not debug_req,
                        debug=debug_req)
                    if not rep.ok:
                        raise SourceAsmError([Diagnostic(0, 0, 1,
                            "保存前验证没过：" + "；".join(
                                c.line for c in rep.checks if c.ok is False))])
                    outer_data = image.replace(out_data)
                    if a.out:
                        _atomic_write(a.out, outer_data)
                        rep.written = str(a.out)
                        if a.out.resolve() != a.cubin.resolve():
                            rep.new_source = ""
            except SourceAsmError as e:
                body = {"ok": False, "error": str(e),
                        "diagnostics": [vars(d) for d in e.diagnostics]}
            else:
                body = {"ok": rep.ok, "section": rep.section, "count": rep.count,
                        "sections": rep.sections,
                        "size": rep.count * 16, "old_bytes": rep.old_size,
                        "new_bytes": rep.new_size, "unchanged": rep.unchanged,
                        "warnings": rep.warnings,
                        "debug_decisions": [d.to_json()
                                            for d in rep.debug_decisions],
                        "checks": [vars(c) for c in rep.checks],
                        "summary": rep.summary(),
                        "hardware_verified": rep.hardware_verified}
                if rep.written:
                    body["written"] = rep.written
                    # 写回的是源码自己的基底 -> 基底 hash 变了，源码头里的
                    # `.base`（还有行尾的 `// @0x....`）得跟着换，否则下一次
                    # 保存会被冲突闸当成「基底被外部改过」挡下来。
                    # 源码在磁盘上就地重绑；从 stdin 来的（虚拟文档）没有落
                    # 脚点，把文本回给调用方，由它写进自己的缓冲区。
                    if rep.new_source and from_stdin:
                        body["source"] = rep.new_source
                    elif rep.new_source:
                        _atomic_write(a.assemble_source, rep.new_source.encode("utf-8"))
                        body["rebased_source"] = str(a.assemble_source)
                    body["base"] = rep.new_base
                elif out_data is not None:
                    # 缓冲区往返：字节回给调用方（编辑器收进 cubin 缓冲区），
                    # 源码同时重绑到这份新字节 —— 「新基底」就是它，不是磁盘。
                    if a.payload_only and image.embedded:
                        body["data"] = out_data.hex()
                        body["data_scope"] = "payload"
                    else:
                        body["data"] = outer_data.hex()
                    if rep.new_base:
                        body["base"] = rep.new_base
                    if rep.new_source and from_stdin:
                        body["source"] = rep.new_source
                body["container"] = image.info()
                if rep.new_base:
                    body["container"]["cubin_base"] = rep.new_base
        elif a.check_save:
            image = _read_image(a)
            base = _image(a.diff.read_bytes(), a.image).cubin if a.diff else None
            body = _offset_body(check_save(image.cubin, base), image)
        elif a.export_patch:
            if a.diff is None:
                raise ValueError("--export-patch 需要配 --diff <原文件> 说明跟谁比")
            image = _read_image(a)
            base = _image(a.diff.read_bytes(), a.image).cubin
            body = _offset_body(export_patch(a.cubin, image.cubin, base), image)
        elif a.apply_patch is not None:
            image = _read_image(a)
            text = a.apply_patch.read_text(encoding="utf-8")
            try:
                patch = json.loads(text)
            except json.JSONDecodeError:            # JSONL：probe() 的扫描产出
                patch = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
            dirs = [Path(d) for d in (a.templates or [])]
            default_pool = Path(__file__).resolve().parent.parent / "corpus" / "cubins"
            if not dirs and default_pool.is_dir():
                dirs = [default_pool]
            patch = _inner_patch_offsets(patch, image)
            at = image.inner_offset(a.at) if a.at is not None else None
            body = apply_patch(a.cubin, image.cubin, patch, at=at, by_sass=a.by_sass,
                               force=a.force, partial=a.partial, pool_dirs=dirs)
            body = _offset_body(body, image, a.payload_only)
            if a.out and body.get("data"):
                _atomic_write(a.out, _outer_bytes(body, image))
                body["written"] = str(a.out)
        elif a.inspect is not None:
            enc = a.inspect.strip()
            if len(enc) != 32 or not all(c in "0123456789abcdefABCDEF" for c in enc):
                raise ValueError("--inspect 需要 32 个十六进制字符")
            raw = enc_to_bytes(enc)
            body = {"ok": True, "enc": enc, "bytes": raw.hex(),
                    "sass": disasm_one(raw), "ctrl": ctrl_of(enc)}
        else:
            image = _read_image(a)
            other = _image(a.diff.read_bytes(), a.image).cubin if a.diff else None
            # build() accepts a path for diff, but embedded images only exist in
            # memory.  Render first, then mark same-offset differences here.
            body = build(a.cubin, None, image.cubin,
                         include_cells=not a.no_cells)
            if other is not None:
                for sec in body.get("sections", []):
                    for row in sec.get("insns", []):
                        off = row["file_off"]
                        row["diff"] = (len(other) < off + INST_BYTES or
                                       other[off:off + INST_BYTES].hex() != row["bytes"])
                body["diff_against"] = str(a.diff)
            body = _offset_body(body, image)
    except Exception as e:                        # 扩展侧只认 JSON，别让它读到 traceback
        body = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if a.check_save:                           # 闸本身没跑成，不是「编码非法」
            body["infrastructureError"] = True
        if getattr(e, "sections", None):           # 让扩展弹选择框，不解析错误文本
            body["sections"] = list(e.sections)
        if getattr(e, "images", None):
            body["images"] = list(e.images)
    json.dump(body, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0 if body.get("ok") else 1)


if __name__ == "__main__":
    main()
