"""架构档案。

这里回答一个此前没人正式回答过的问题：**手上这份 cubin 是哪个架构的，我们对它
有什么能力**。以前答案是隐式的「反正都是 sm_90」：`elf_rewrite._check()` 见到
`e_flags` 低字节不是 90 就抛错，`identify()`/段表则默认自己面对的就是 sm_90。
那套隐式约定在只有一个架构时能用，多一个就会变成「拿 sm_90 段表去猜别人」。

## 三条不肯让步的规矩

1. **架构由容器元数据认定**：ELF header 的 `e_machine`(EM_CUDA) 与 `e_flags`
   低字节就是 SM 号。CLI 的 `--arch` 只能用来**核对**，冲突即拒绝 —— 它不是
   覆盖开关，否则「我说它是 sm_90」就能骗过所有下游门禁。
2. **能力按 profile 显式列出**：`read` / `identify` / `assemble` / `rewrite`。
   没有该架构的正式数据产物（段表、fieldscan、modes）时，最多给 `read`；
   不回退到 sm_90 的 `identify()` 或编码器。
3. **数据产物按 profile 命名和加载**：`artifact()` 只会指向本 profile 的文件，
   不存在「找不到就用 sm90 那份」这条路径。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

EM_CUDA = 190

#: 仓库根（`nvisa/model/arch.py` → 上溯两级）。
ROOT = Path(__file__).resolve().parents[2]

#: 四种能力，粒度就是「可以对这个架构做什么」。
CAPABILITIES = ("read", "identify", "assemble", "rewrite")


class ArchError(ValueError):
    """架构识别失败、能力不足或 `--arch` 与容器冲突。"""


@dataclass(frozen=True)
class ArchitectureProfile:
    """一个架构的不可变档案。没有登记的架构不会凭空得到写入能力。"""

    arch: str                      # "sm_90"
    sm: int                        # e_flags 低字节
    inst_bytes: int                # 一条指令多少字节；0 = 未知（只能 read）
    capabilities: frozenset[str]
    #: 正式数据产物：逻辑名 → 相对仓库根的路径。缺项就是「这个架构没有」。
    artifacts: dict[str, str] = field(default_factory=dict)
    #: 可用的 oracle（`nvdisasm` / `execute` / ...），仅作报告用。
    oracles: tuple[str, ...] = ()
    #: 为什么能力只到这一档 —— 报告里要说得出理由。
    note: str = ""

    def has(self, cap: str) -> bool:
        if cap not in CAPABILITIES:
            raise ArchError(f"未知能力 {cap!r}，可选：{', '.join(CAPABILITIES)}")
        return cap in self.capabilities

    def require(self, cap: str) -> None:
        if not self.has(cap):
            raise ArchError(
                f"{self.arch} 没有 {cap} 能力（当前：{sorted(self.capabilities)}）"
                + (f"；{self.note}" if self.note else ""))

    def artifact(self, name: str) -> Path:
        """本 profile 的正式产物路径。没有就报错，**不回退到别的架构**。"""
        rel = self.artifacts.get(name)
        if rel is None:
            raise ArchError(
                f"{self.arch} 没有登记 {name!r} 产物 —— "
                f"不存在「借用其他架构那份」这条路径")
        return ROOT / rel

    def missing_artifacts(self) -> list[str]:
        return [n for n in self.artifacts if not (ROOT / self.artifacts[n]).exists()]

    def to_json(self) -> dict:
        return {"arch": self.arch, "sm": self.sm, "inst_bytes": self.inst_bytes,
                "capabilities": sorted(self.capabilities),
                "artifacts": dict(self.artifacts),
                "oracles": list(self.oracles), "note": self.note}


SM90 = ArchitectureProfile(
    arch="sm_90", sm=90, inst_bytes=16,
    capabilities=frozenset(CAPABILITIES),
    artifacts={"fieldscan": "data/fieldscan-sm90.json",
               "segtable": "data/segtable-sm90.json",
               "modes": "data/modes-sm90.json",
               "evidence": "data/evidence-sm90.json",
               "hardware_facts": "data/hardware-facts-sm90.json"},
    oracles=("nvdisasm", "execute"),
    note="本项目的正式验收架构")

#: 登记表：只有这里出现的架构才可能拥有 read 以外的能力。
PROFILES: dict[str, ArchitectureProfile] = {SM90.arch: SM90}


def unknown_profile(arch: str, sm: int) -> ArchitectureProfile:
    """没登记的架构：只读，不带任何产物，也不假装知道指令宽度。"""
    return ArchitectureProfile(
        arch=arch, sm=sm, inst_bytes=0, capabilities=frozenset({"read"}),
        oracles=("nvdisasm",),
        note="未登记架构：没有本架构的段表/fieldscan/modes，只允许原始 ELF inspect")


def detect_arch(data: bytes) -> tuple[str, int, int]:
    """从容器元数据认架构，返回 `(arch, sm, e_flags)`。不看文件名、不看参数。"""
    if data[:4] != b"\x7fELF":
        raise ArchError("不是 ELF")
    if data[4] != 2 or data[5] != 1:
        raise ArchError("只支持 ELF64 little-endian")
    e_machine, = struct.unpack_from("<H", data, 18)
    if e_machine != EM_CUDA:
        raise ArchError(f"e_machine={e_machine}，不是 EM_CUDA({EM_CUDA})")
    e_flags, = struct.unpack_from("<I", data, 48)
    sm = e_flags & 0xFF
    return f"sm_{sm}", sm, e_flags


def profile_for(data: bytes, requested: str | None = None) -> ArchitectureProfile:
    """认架构并取 profile；`requested` 只做核对，冲突即拒绝。"""
    arch, sm, _flags = detect_arch(data)
    if requested is not None and requested != arch:
        raise ArchError(
            f"--arch {requested} 与容器不符：ELF 里写的是 {arch}"
            f"（e_flags 低字节 = {sm}）—— `--arch` 只用于核对，不覆盖检测")
    return PROFILES.get(arch) or unknown_profile(arch, sm)
