"""Locate bit fields by XOR-diffing samples that share a key."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def load(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def by_key(records: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        if r.get("ok") and r.get("key"):   # 无 key 的记录不参加同 key XOR 差分
            groups[r["key"]].append(r)
    return dict(groups)


def enc_to_int(enc: str) -> int:
    """`enc` is stored low-half-first (as nvdisasm prints it), so swap the two
    64-bit halves to get a value whose bit 0 is the real LSB of the instruction."""
    lo, hi = enc[:16], enc[16:]
    return (int(hi, 16) << 64) | int(lo, 16)


def varying_bits(encs: list[str]) -> list[int]:
    """Bit positions (0 = LSB of the 128-bit word) that differ across samples."""
    if len(encs) < 2:
        return []
    vals = [enc_to_int(e) for e in encs]
    mask = 0
    for v in vals[1:]:
        mask |= v ^ vals[0]
    return [b for b in range(128) if mask >> b & 1]


def constant_bits(encs: list[str]) -> list[int]:
    if not encs:
        return []
    var = set(varying_bits(encs))
    return [b for b in range(128) if b not in var]


def group_runs(bits: list[int]) -> list[tuple[int, int]]:
    """Collapse a sorted bit list into (lo, hi) contiguous runs."""
    runs: list[tuple[int, int]] = []
    for b in sorted(bits):
        if runs and b == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], b)
        else:
            runs.append((b, b))
    return runs


def report(path: Path, min_samples: int = 2) -> None:
    groups = by_key(load(path))
    ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    for key, rows in ranked:
        if len(rows) < min_samples:
            continue
        encs = [r["enc"] for r in rows]
        runs = group_runs(varying_bits(encs))
        print(f"\n{key}  ({len(rows)} samples)")
        print(f"  example : {rows[0]['text']}")
        print(f"  varying : {runs}")

# ---------------------------------------------------------------------------
# 跨 key 差分 → 操作码定位 → per-opcode spec
# ---------------------------------------------------------------------------

#: sm_90 的通用槽骨架。**先验，不是 schema**——只用来给差分出来的
#: 位区间贴标签；对不上的区间照实标成 unknown，留给后续 fuzz 解。
SLOTS: list[tuple[str, int, int]] = [
    ("pred_guard", 12, 15),  # 12-14 谓词号 + 15 取反；样本全为 0x7 = PT
    ("Rd", 16, 23),
    ("Ra", 24, 31),
    ("Rb", 32, 39),
    ("imm24", 40, 63),
    ("Rc", 64, 71),
    # 调度控制段，与操作数无关，单独标出来免得混进字段里
    ("sched.stall", 105, 108),
    ("sched.yield", 109, 109),
    ("sched.wrbar", 110, 112),
    ("sched.rdbar", 113, 115),
    ("sched.waitmask", 116, 121),
]

#: 操作码内部结构（位注入实验验证过）：低 9 位是操作本体，
#: 高 3 位是 **operand-form 选择器**。决定性证据是 IMAD 的两个形态 [8:0] 同为
#: 0x024，只有 [11:9] 从 100 变 110；直接 patch 这三位，可以看到 B/C 槽
#: 的操作数通路随之切换。
OP_BITS = (0, 8)
B_MODE_BITS = (9, 11)

#: operand-form 取值 → 标签。⚠️ 这不是一张平表——真实含义**依赖 base
#: 操作码所在的数据通路**：vector base（FFMA 0x223）的 100/101 是 imm/c[][]，
#: uniform base（IMAD 0xc24）的 110/111 才是 UR。下表按"最常见观测"贴标签，
#: 仅供人读。没见过的取值不猜，由 `b_mode_label` 标 unknown。
B_MODES: dict[int, str] = {
    0b001: "R",         # B=reg C=reg：FFMA / LOP3 / VIMNMX
    0b100: "imm|none",  # B=立即数，或无 B 操作数（NOP / EXIT / BRA / S2R）
    0b101: "c[][]",     # B=constant bank（vector）/ cx[UR][]（uniform）
    0b110: "UR",        # B=uniform 寄存器：IMAD R9, R9, UR4, R0（仅 uniform base）
}


def field(value: int, bits: tuple[int, int]) -> int:
    lo, hi = bits
    return (value >> lo) & ((1 << (hi - lo + 1)) - 1)


def b_mode_label(mode: int) -> str:
    return B_MODES.get(mode, f"unknown_{mode:03b}")


def mask_of(bits: list[int]) -> int:
    m = 0
    for b in bits:
        m |= 1 << b
    return m


def opcode_bits(groups: dict[str, list[dict]], min_samples: int = 2) -> tuple[list[int], list[int]]:
    """跨 key 差分：找出操作码候选位。

    返回 ``(opcode_bits, invariant_bits)``：

    - **opcode_bits** —— 在每个 key 内部恒定（同 key 差分说它不随操作数变），
      但跨 key 取值不同。译码器必须先从固定位置取出操作码才知道后面怎么解释，
      所以这批位存在本身不是假设，是定长 ISA 的必然结论；这里只是把它测出来。
    - **invariant_bits** —— 所有 key 里都恒定且**全局同值**的位。它们不区分指令，
      可能是固定前缀，也可能是样本没覆盖到的字段（如未使用的谓词槽）。

    只有样本数 >= ``min_samples`` 的 key 能提供「同 key 内恒定」的证据；单样本 key
    对交集不设限（它的 128 位全都“恒定”），但仍参与跨 key 取值比较。
    """
    multi = {k: v for k, v in groups.items() if len(v) >= min_samples}
    stable = set(range(128))
    for rows in multi.values():
        stable &= set(constant_bits([r["enc"] for r in rows]))

    values = [enc_to_int(rows[0]["enc"]) for rows in groups.values()]
    differing = set()
    if len(values) >= 2:
        for v in values[1:]:
            differing |= {b for b in range(128) if (v ^ values[0]) >> b & 1}

    return sorted(stable & differing), sorted(stable - differing)


def separating_runs(groups: dict[str, list[dict]], runs: list[tuple[int, int]]) -> list[dict]:
    """在 opcode 候选区间里挑出**单独一段就能区分助记符**的那些。

    跨 key 差分给出的候选区间必然偏大：槽位没被样本用到的高位（寄存器号只用到低
    4-5 位）在每个 key 内也恒定、跨 key 也不同，会被一并选进来。真正的操作码段
    应该自己就能把不同助记符分开——同助记符的不同修饰符（``LDC`` / ``LDC.64``）
    共享一个值是允许的，修饰符编在别处。仍是启发式，最终要靠位注入实验验证。
    """
    keys = list(groups)
    out = []
    for lo, hi in runs:
        m = ((1 << (hi - lo + 1)) - 1) << lo
        buckets: dict[int, set[str]] = defaultdict(set)
        for k in keys:
            buckets[enc_to_int(groups[k][0]["enc"]) & m].add(groups[k][0]["mnemonic"])
        mixed = {f"{v >> lo:#x}": sorted(ms) for v, ms in buckets.items() if len(ms) > 1}
        if not mixed:
            out.append({"range": [lo, hi], "values": len(buckets)})
    return out


def annotate(runs: list[tuple[int, int]]) -> list[dict]:
    """给差分出来的位区间贴槽名。落不进任何已知槽的照实标 unknown。"""
    out = []
    for lo, hi in runs:
        hits = [(n, s_lo, s_hi) for n, s_lo, s_hi in SLOTS if not (hi < s_lo or lo > s_hi)]
        rec = {"observed": [lo, hi]}
        if len(hits) == 1:
            name, s_lo, s_hi = hits[0]
            rec["name"] = name
            # 槽宽是骨架给的假说，实测只看到 observed 这几位在动；
            # 宽度要靠注入扫描到高编号寄存器/大立即数才能确认
            rec["hypothesis"] = [s_lo, s_hi]
        else:
            rec["name"] = f"unknown_{lo}_{hi}"
            if hits:
                rec["candidates"] = [n for n, _, _ in hits]
        out.append(rec)
    return out


def _opcode_split(base: int, opval_src: list[int] | None) -> dict:
    """把 12 位操作码拆成 op / b_mode。

    只在操作码确实落在 bit 0:11 时才拆——退回宽掩码时拆出来的是噪声，宁可不给。
    """
    if opval_src != [0, 11]:
        return {}
    mode = field(base, B_MODE_BITS)
    return {
        "op": f"{field(base, OP_BITS):#05x}",
        "b_mode": f"{mode:03b}",
        "b_mode_label": b_mode_label(mode),
    }


def build_spec(groups: dict[str, list[dict]], min_samples: int = 2) -> dict:
    """按 key 组装 per-opcode 布局表。

    每条指令一个条目——骨架只是大多数条目**恰好长得一样**，不是全局 schema。
    将来遇到另起炉灶的布局（WGMMA / descriptor 类），加条目即可，不动已有的。
    """
    opbits, invariant = opcode_bits(groups, min_samples)
    opruns = group_runs(opbits)
    separating = separating_runs(groups, opruns)
    opmask = mask_of(opbits)
    # opcode 值取「单独可区分助记符」的那一段；没有唯一的一段就退回整个候选掩码，
    # 并在 spec 里如实标出来——宁可标成不确定，也别把噪声位当操作码写死
    if len(separating) == 1:
        s_lo, s_hi = separating[0]["range"]
        opval_mask = ((1 << (s_hi - s_lo + 1)) - 1) << s_lo
        opval_src = separating[0]["range"]
    else:
        opval_mask, opval_src = opmask, None

    entries = []
    for key, rows in sorted(groups.items()):
        encs = [r["enc"] for r in rows]
        base = enc_to_int(encs[0])
        runs = group_runs(varying_bits(encs))
        entries.append(
            {
                "key": key,
                "mnemonic": rows[0]["mnemonic"],
                "modifiers": rows[0].get("modifiers", []),
                "opcode": f"{base & opval_mask:#x}",
                **_opcode_split(base, opval_src),
                "samples": len(rows),
                "example": rows[0]["text"],
                # 单样本 key 差分不出任何东西，字段留空并标出来，别装作已解
                "confidence": "diffed" if len(rows) >= min_samples else "single-sample",
                "fields": annotate(runs),
            }
        )

    # 操作码位必须能唯一区分 key，否则说明这批位选错了或样本不足
    collisions: dict[str, list[str]] = defaultdict(list)
    for e in entries:
        collisions[e["opcode"]].append(e["key"])

    return {
        "arch": next((r["arch"] for rows in groups.values() for r in rows if "arch" in r), "unknown"),
        "opcode_bits": opruns,
        "opcode_separating_runs": separating,
        "opcode_mask": f"{opmask:#034x}",
        "opcode_value_bits": opval_src,
        "opcode_split": {
            "status": "verified",  # ✅ 位注入实验证实 bit 9:11 = operand-form
            "op_bits": list(OP_BITS),
            "b_mode_bits": list(B_MODE_BITS),
            "b_modes": {f"{m:03b}": n for m, n in sorted(B_MODES.items())},
        } if opval_src == [0, 11] else None,
        "invariant_bits": group_runs(invariant),
        "slots": [{"name": n, "range": [lo, hi]} for n, lo, hi in SLOTS],
        "instructions": entries,
        "opcode_collisions": {k: v for k, v in collisions.items() if len(v) > 1},
    }


def write_spec(path: Path, out: Path, min_samples: int = 2) -> dict:
    groups = by_key(load(path))
    spec = build_spec(groups, min_samples)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
    return spec


if __name__ == "__main__":
    import argparse

    root = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description="XOR 差分 → 位域定位")
    ap.add_argument("samples", nargs="?", default=root / "corpus" / "samples" / "seed-sm_90.jsonl")
    ap.add_argument("--spec", type=Path, help="额外写出 per-opcode spec.json")
    ap.add_argument("--min-samples", type=int, default=2)
    args = ap.parse_args()

    samples = Path(args.samples)
    report(samples, args.min_samples)

    groups = by_key(load(samples))
    opbits, invariant = opcode_bits(groups, args.min_samples)
    print("\n跨 key 差分")
    print(f"  opcode 候选位 : {group_runs(opbits)}")
    print(f"  单独可区分的段: {separating_runs(groups, group_runs(opbits))}")
    print(f"  全局恒定位    : {group_runs(invariant)}")

    if args.spec:
        spec = write_spec(samples, args.spec, args.min_samples)
        n = len(spec["instructions"])
        bad = spec["opcode_collisions"]
        print(f"  → {args.spec}  ({n} 条指令" + (f", {len(bad)} 组操作码碰撞)" if bad else ")"))
        for op, keys in bad.items():
            print(f"    碰撞 {op}: {keys}")
