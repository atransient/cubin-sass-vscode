"""canonical key —— 样本分组键的唯一定义。

`key` 是分析分组依据，不是不可变的原始事实。`collect/harvest.py` 早期的
`operand_shape()` 靠字符串前缀猜操作数形态：`@P0 FFMA ...` 的谓词前缀会被当成
第一个操作数、`c[0x0][0x28]` 和 `c[0x0][R2+0x28]` 混成同一个 `C`、立即数不分
整数/浮点。这样分出来的组做 XOR 差分，差出来的位会横跨两种编码布局。

canonical key 的**唯一来源**是结构化 parser：

    canonical_key(text) == sass_parser.lower(parse_instruction(text)).key

这不是随便挑的对齐点 —— `data/fieldscan-sm90.json`、段表和 `slot_facts` 的 InsKey
本来就是这个格式（`LDC_R_cAI` / `ATOM_P_R_dARI_R` / `S2R_R_L`）。让采样的 key
与解码层同源，按 key 聚合的产物才不用两套索引互相翻译。

规则：

- 谓词前缀 `@P0` / `@!P1` 不进 key（它是 `vals[0]` 的 `P.Guard` 字段值），无谓词
  按 `PT` 处理 —— 所以带谓词与不带谓词的同一条指令落进同一个 key。
- 寄存器号、谓词号、立即数数值不进 key；它们正是同 key 内要观察的变化。
- opcode 修饰符（`.WIDE` / `.E` / `.RN`）不进 key，它们是 opcode 位上的字段值，
  由 fieldscan 的 `values` 表解释；按 bit length 给立即数取名（`I8`/`I24`）更是
  被明令禁止的做法。
- 形态由**编码布局**区分而非文本类别：`R`/`UR`/`P`/`II`/`FI`/`cAI`/`cARI`/
  `ARI`/`dARI`/`L`……布局不同就是不同 key。
- **分支目标的标号形态归一到立即数形态**：
  ``BRA `(.L_x_0)`` 与 `BRA 0x190` 是同一条 PC 相对分支的两种源码写法，
  编码布局只有一种，所以正式 key 都是 `BRA_II`。见 `normalize_key()`。
- `X` 只在真正无法分类时出现：这里的实现是「parser 认不出来就没有 key」，
  失败记录带 `key_error` 保留，绝不猜。
"""
from __future__ import annotations

from nvisa.model.sass_parser import (ADDR_FUNCS, SassSyntaxError, lower,
                                     parse_instruction)

#: 目标写成符号标号时 parser 摊平出来的操作数形态。
LABEL_FORM = "L"
#: 归一之后的形态：PC 相对立即数。
BRANCH_IMM_FORM = "II"
#: 目标是「本指令地址的相对量」的 opcode —— 只有这些的 `_L` 才是分支标号。
#: `S2R_R_L` 的 `L` 是特殊寄存器名，不是地址，必须留在 key 里。
BRANCH_TARGET_OPCODES = frozenset(ADDR_FUNCS)

#: 迁移时写进记录的字段名。
LEGACY_FIELD = "legacy_key"
CHANGED_FIELD = "key_changed"
ERROR_FIELD = "key_error"


def normalize_key(key: str) -> str:
    """parser 的源码形态 key -> 正式编码 key。

    parser 保留 `L` 是对的：``BRA `(.L_x_0)`` 的目标地址不在指令身上，AST 层
    必须能表达「这是个还没解析的标号」。但**编码布局层没有这个区分** —— 标号
    在符号表解析之后就是一个 PC 相对立即数，落的是同一批位（`slot_facts` 的
    `pc_offset`）。所以正式 key 把末列的 `L` 归一成 `II`：

        BRA_L      -> BRA_II
        BRA_P_L    -> BRA_P_II      （谓词分支同一条规则）
        BSSY_B_L   -> BSSY_B_II
        S2R_R_L    -> S2R_R_L       （`L` 是 `SR_TID.X`，不是地址，不动）

    只改**最后一列**：`ADDR_FUNCS` 里只有目标那一列可能是标号，前面的
    `R`/`UR`/`P`/`B` 是真操作数。
    """
    mn, _, rest = key.partition("_")
    if not rest or mn not in BRANCH_TARGET_OPCODES:
        return key
    head, _, last = rest.rpartition("_")
    if last != LABEL_FORM:
        return key
    tail = f"{head}_{BRANCH_IMM_FORM}" if head else BRANCH_IMM_FORM
    return f"{mn}_{tail}"


def canonical_key(text: str) -> str:
    """SASS 文本 -> canonical key。认不出来抛 `SassSyntaxError`。

    `addr` 不传：PC 相对跳转的偏移只影响 `vals`，不影响 key。
    分支标号按 `normalize_key()` 归一，所以标号写法与数值写法同 key。
    """
    return normalize_key(lower(parse_instruction(text)).key)


def try_canonical_key(text: str | None) -> tuple[str | None, str | None]:
    """`(key, err)` —— 不抛异常的版本，给批量迁移用。"""
    if not text:
        return None, "no text"
    try:
        return canonical_key(text), None
    except SassSyntaxError as e:
        return None, str(e)
    except Exception as e:                      # parser 内部的其它失败也要记账
        return None, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# 命名空间门禁
# ---------------------------------------------------------------------------
#
# canonical key 与解码层同源，这个「同源」必须是可执行的断言而不是口头约定：
# 一条 `ok=true` 的样本，它的 key 如果不在正式段表里，那么按 key 聚合的字段
# 分析、`identify()` 反查和编码往返都会在这条样本上失去对照，而且是无声失去
# （`BRA_L` 就这么活了很久：语料里有、段表里没有，谁也没报错）。
# 所以这里把它变成一条会失败的检查。


def spec_namespace() -> dict:
    """正式段表 `{key: ...}`。读不出来返回空 dict —— 调用方自己决定是跳过
    还是判失败（`migrate_keys.py` 判失败，pytest 跳过）。"""
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    if str(root / "scripts") not in sys.path:
        sys.path.insert(0, str(root / "scripts"))
    from cubin_sass import segtable
    return segtable()


def namespace_violations(rows: list[dict],
                         namespace: dict | None = None) -> list[dict]:
    """`ok=true` 但 key 不在正式段表里的样本。

    返回 `[{key, text, origin}]`（同 key 只留第一条样本作证据），空列表 = 通过。
    没有 key 的记录不算违规：它们带 `key_error`，本来就不参加按 key 的分析。
    """
    seg = spec_namespace() if namespace is None else namespace
    out: dict[str, dict] = {}
    for r in rows:
        if not r.get("ok", False):
            continue
        key = r.get("key")
        if key is None or key in seg or key in out:
            continue
        out[key] = {"key": key, "text": r.get("text"), "origin": r.get("origin")}
    return [out[k] for k in sorted(out)]


def migrate_record(rec: dict) -> dict:
    """就地把一条样本迁到 canonical key，返回同一个 dict。

    - `ok=true` 且有 `text`：重算 `key`，旧值存 `legacy_key`，标 `key_changed`。
    - `ok=false` 或没有 `text`：**不猜**。保留原 `key` 作 `legacy_key`，
      删掉 `key` 让它不参加按 key 的字段差分，并记下 `key_error`。
    """
    legacy = rec.get("key")
    if legacy is not None and LEGACY_FIELD not in rec:
        rec[LEGACY_FIELD] = legacy

    if not rec.get("ok", False):
        key, err = None, "ok=false"
    else:
        key, err = try_canonical_key(rec.get("text"))

    if key is None:
        rec.pop("key", None)
        rec[ERROR_FIELD] = err
        rec[CHANGED_FIELD] = legacy is not None
        return rec

    rec.pop(ERROR_FIELD, None)
    rec["key"] = key
    rec[CHANGED_FIELD] = key != legacy
    return rec
