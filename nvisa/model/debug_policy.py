"""调试信息按**策略**处理。

以前这里只有一个布尔 `strip_debug`：行号类 section 默认拒绝，置真就清空。那是
一条**隐式**规则 —— 报告说不出「每个调试 section 各自被怎么处置、凭什么」。这里要
的是显式三选一，并且每条决策都带理由：

| 策略 | 允许条件 | 结果 |
|---|---|---|
| `preserve` | 布局没变，或**能证明**该 section 不引用被改范围 | 原字节保留，报告记下这条 proof |
| `strip` | 调用方显式选择 | 清空该 section **及其关联重定位**，报告写「已剥离，不是仍然有效」 |
| `rewrite` | 该格式已有 parser + 地址映射 + golden test | 只改被定义的字段 |

## 本轮只有 `.debug_frame` 能 rewrite

`.debug_frame` 的 FDE 记着 `initial_location + address_range`，两个值本项目自己
算得出来（`elf_rewrite._update_debug_frame()`，有回归测试），所以它是唯一进入
`rewrite` 的格式。`.debug_line` / `.debug_info` / `.nv.debug*` **没有格式级证明**：
既不能原样声称有效，也不能在 `rewrite` 模式下悄悄 strip —— 请求 rewrite 直接拒绝。

## 三种会失败的检查

1. **`preserve` 要有 proof**：布局变了又选 preserve，除非能证明这个 section 既没有
   指向被改 section 的重定位，也没有和被改函数长度对上的 FDE range；证不出就拒绝。
2. **`strip` 连带重定位**：`.rela.debug_line` 留着而 `.debug_line` 清空了，等于留下
   一批指向空段的加数。按 `sh_info` 找到关联 RELA 一起清。
3. **未知 debug 重定位类型拒绝**：语料里只见过 `R_CUDA_ABS64`(2)。认不出的类型
   在 preserve/rewrite 下拒绝（strip 会把它一起删掉，因此不拦）。
"""
from __future__ import annotations

from dataclasses import dataclass, field

PRESERVE, STRIP, REWRITE = "preserve", "strip", "rewrite"
POLICIES = (PRESERVE, STRIP, REWRITE)

#: 行号类：手写 SASS 之后证明不了还对，没有格式级 parser。
LINE_DEBUG = (".debug_line", ".debug_info", ".debug_abbrev", ".debug_str",
              ".debug_pubnames", ".debug_ranges")
#: NVIDIA 私有调试段，同样没有格式级证明。
NV_DEBUG = (".nv.debug",)
#: 唯一有 parser + 地址映射 + 回归测试的格式。
FRAME = ".debug_frame"

#: 语料里出现过的 debug 重定位类型。认不出的不放行（strip 除外）。
KNOWN_DEBUG_RELA_TYPES = {2: "R_CUDA_ABS64"}


class DebugPolicyError(ValueError):
    """策略缺失、不被允许，或 proof 不成立。"""


def classify(name: str) -> str | None:
    """`frame` / `line` / `nv` / None（不是调试 section）。"""
    if name == FRAME:
        return "frame"
    if any(name.startswith(p) for p in LINE_DEBUG):
        return "line"
    if any(name.startswith(p) for p in NV_DEBUG):
        return "nv"
    return None


@dataclass(frozen=True)
class DebugRequest:
    """调用方对调试信息的**显式**请求。

    `default` 作用于所有调试 section，`per_section` 逐个覆盖。两者都没给到某个
    section 时，`policy_for()` 返回 None —— 那是「没有决策」，由 `plan()` 报错，
    不是「默认保留」。
    """
    default: str | None = None
    per_section: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for p in [self.default, *self.per_section.values()]:
            if p is not None and p not in POLICIES:
                raise DebugPolicyError(
                    f"未知策略 {p!r}，只能是 {'/'.join(POLICIES)}")

    def policy_for(self, name: str) -> str | None:
        return self.per_section.get(name, self.default)

    @classmethod
    def from_legacy(cls, strip_debug: bool) -> "DebugRequest":
        """旧的布尔开关 → 等价请求。

        旧语义是「`.debug_frame` 按新函数长度更新；行号类默认拒绝，
        `strip_debug=True` 时剥离」。写成策略就是下面这两条，一字不多。
        """
        return cls(default=STRIP if strip_debug else None,
                   per_section={FRAME: REWRITE})


@dataclass
class Decision:
    """一个调试 section 的处置结论 —— 报告要逐条讲出来。"""
    section: str
    kind: str
    policy: str
    reason: str
    relocations: list[str] = field(default_factory=list)

    @property
    def clears(self) -> bool:
        return self.policy == STRIP

    def to_json(self) -> dict:
        return {"section": self.section, "kind": self.kind,
                "policy": self.policy, "reason": self.reason,
                "relocations": list(self.relocations)}

    @property
    def line(self) -> str:
        extra = ("，连带清空 " + "、".join(self.relocations)
                 if self.relocations and self.clears else "")
        return f"{self.section}: {self.policy}（{self.reason}）{extra}"


def plan(debug_sections: list[dict], *, request: DebugRequest,
         layout_changed: bool) -> list[Decision]:
    """逐个调试 section 定策略，定不下来就抛错。**只做决策，不改字节。**

    `debug_sections` 每项至少要有：`name`、`rela`（关联 RELA section 名字列表）、
    `rela_types`（其中出现的重定位类型集合）、`touches_target`（是否引用被改的
    section —— 这是 `preserve` 的 proof 依据，由调用方算，不在这里猜）。
    """
    out: list[Decision] = []
    for sec in debug_sections:
        name = sec["name"]
        kind = classify(name)
        if kind is None:
            continue
        policy = request.policy_for(name)
        relas = list(sec.get("rela", []))
        unknown = sorted(set(sec.get("rela_types", ())) - set(KNOWN_DEBUG_RELA_TYPES))
        if policy is None:
            raise DebugPolicyError(
                f"{name} 没有调试策略：必须显式选择 "
                f"{'/'.join(POLICIES)} 之一，没有「默认保留」这条路"
                + ("；行号类 section 手写 SASS 之后证明不了还对"
                   if kind != "frame" else ""))
        if policy == REWRITE and kind != "frame":
            raise DebugPolicyError(
                f"{name} 不支持 rewrite：本项目对该格式没有 parser、地址映射和 "
                f"golden test，rewrite 能力不对外宣布支持（也不许在 rewrite 名义下"
                f"偷偷剥离）—— 要么 strip，要么别改布局")
        if policy in (PRESERVE, REWRITE) and unknown:
            raise DebugPolicyError(
                f"{name} 关联的重定位里有认不出的类型 "
                f"{'、'.join(hex(t) for t in unknown)}：改不动也证不了，拒绝")
        if policy == PRESERVE:
            if not layout_changed:
                reason = "布局没有变化，原字节即有效"
            elif not sec.get("touches_target", True):
                reason = ("布局变了，但该 section 既没有指向被改 section 的重定位、"
                          "也没有与被改函数长度对上的引用")
            else:
                raise DebugPolicyError(
                    f"{name} 选了 preserve，但布局变了而且它引用了被改范围 —— "
                    f"preserve 需要 proof，不是「先留着再说」。"
                    f"改用 strip，或"
                    + ("用 rewrite" if kind == "frame" else "别改条数"))
        elif policy == STRIP:
            reason = "调用方显式剥离：已剥离，不是「仍然有效」"
        else:
            reason = ("按新函数长度重写 FDE 的 address_range"
                      if layout_changed else "布局没变，没有需要改的字段")
        out.append(Decision(section=name, kind=kind, policy=policy,
                            reason=reason, relocations=relas))
    return out
