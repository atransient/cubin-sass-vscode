"""源码模式的保存事务与验收。

`Ctrl+S`（以及 CLI 的 `--assemble-source`）是一次**事务**：解析 → 汇编 → ELF 打包
→ 全量验证，**全部通过**才一次性替换目标文件；任何一步不过就保留源码与诊断，
基底一个字节不动。这里是这条链的最后一环。

## 报告要分清两件事

驱动收下这个 cubin ≠ 它算得对。所以 `SaveReport` 把检查逐条列出来，并且
`hardware_verified` **永远是 False**：本模块最多做到 `cuModuleLoad`（结构合法、
驱动愿意加载），真正的执行结果正确性要在 GPU 上实际运行才能验证，不在这里冒充。

## 五项检查

| 检查 | 判据 | 没有工具时 |
|---|---|---|
| `structure` | 自己解 ELF：偏移/大小不越界、file-backed section 不重叠、SHT/PHT 在文件内、`p_align` 同余、目标段大小 = 条数 × 16 | 总是做（不依赖外部工具） |
| `readelf` / `cuobjdump` | 外部工具退出码为 0 | 工具不在 PATH 就记「跳过」，不算通过 |
| `disasm` | 整段交回 nvdisasm，逐条与源码文本一致（标号按「指向第几条」比 —— 插删之后地址会变，序号不会） | 总是做 |
| `control` | 每条最终编码的 bits 105:121 与源码行前缀**逐字段相等**；`.reuse` 与 bits 122:124 一致（`probe_reuse_bits()` 的逐 opcode 映射） | 总是做 |
| `load` | `cuModuleLoad` 收下它（**不发射 kernel**） | 没 GPU 记「跳过」；`ok=None` 是「没测」，不是「通过」 |

“跳过”与“通过”在报告里是两个状态，不合并 —— 保存成功的报告要说得出
自己验过什么。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from nvisa.model.sass_asm import Diagnostic, SourceAsmError, assemble_into
from nvisa.model.sass_parser import parse_line
from nvisa.model.sass_source import (base_hash, emit_source, refresh_source,
                                     is_source_bundle, refresh_source_bundle,
                                     source_section_names)

_INST = 16
_CTRL_BITS = {"stall": (105, 108), "yield": (109, 109), "wr": (110, 112),
              "rd_bar": (113, 115), "wait": (116, 121)}
_REUSE = (122, 124)
_LBL = re.compile(r"\.L_[0-9a-f]+")


@dataclass
class Check:
    name: str
    ok: bool | None            # None = 跳过（没做），**不等于通过**
    detail: str = ""

    @property
    def line(self) -> str:
        mark = {True: "通过", False: "失败", None: "跳过"}[self.ok]
        return f"{self.name}: {mark}" + (f"（{self.detail}）" if self.detail else "")


@dataclass
class SaveReport:
    section: str
    count: int
    old_size: int
    new_size: int
    unchanged: bool
    written: str | None = None
    #: 落盘成功后**新基底**的 hash。写回的是源码自己的基底时，源码头里的
    #: `.base` 必须跟着换成它，否则下一次保存会被冲突闸挡下来（第一次能存、
    #: 第二次报「基底对不上」就是这个）。
    new_base: str = ""
    #: 重新绑到新基底之后的源码文本（`.base` 与行尾 `// @0x....` 已更新）。
    #: 写回的目标就是源码的基底时，调用方应当把它写回 `.nvsass` 文件。
    new_source: str = ""
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: 每个调试 section 的策略决策（`debug_policy.Decision`）。
    debug_decisions: list = field(default_factory=list)
    #: **永远 False**：这里最多验到「nvdisasm 读得回 + 驱动加载得了」。
    #: 真正跑对不对要在 GPU 上实际运行才知道。
    hardware_verified: bool = False
    #: Multi-kernel source documents list their independently assembled sections.
    sections: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok is not False for c in self.checks)

    def summary(self) -> str:
        head = (f"{self.section}：{self.count} 条指令，"
                f"{self.old_size} -> {self.new_size} 字节"
                + ("（与基底逐字节一致）" if self.unchanged else ""))
        return head + "；" + "，".join(c.line for c in self.checks) + \
            "；硬件语义未验证"


def canonical_texts(src_text: str) -> list[str]:
    """源码的指令文本序列，标号换成「指向第几条指令」。

    插删之后地址会变、标号名（`.L_<地址>`）跟着变，但「跳到第几条」不会 ——
    要比的是这个，不是字面量。
    """
    lines = [parse_line(line) for line in src_text.splitlines()]
    idx, n = {}, 0
    for line in lines:
        if line.label is not None:
            idx[line.label.name] = n
        elif line.insn is not None:
            n += 1
    out = []
    for line in lines:
        if line.insn is None:
            continue
        body = line.text[line.insn.col:line.insn.end]
        body = " ".join(body.split()).rstrip(";").strip()
        out.append(_LBL.sub(lambda m: f"#{idx.get(m.group(), '?')}", body))
    return out


def _ctrl_lines(src_text: str) -> list:
    return [line.insn.ctrl for raw in src_text.splitlines()
            if (line := parse_line(raw)).insn is not None]


def _reuse_slots(src_text: str) -> list[list[int]]:
    """每条指令上写了 `.reuse` 的操作数槽（谓词前缀占 slot 0，同段表列坐标）。"""
    out = []
    for raw in src_text.splitlines():
        line = parse_line(raw)
        if line.insn is None:
            continue
        ins = line.insn
        out.append([i + 1 for i, op in enumerate(ins.operands)
                    if "reuse" in getattr(op, "modifiers", [])] if ins else [])
    return out


def _declared_base(src_text: str) -> str:
    for raw in src_text.splitlines():
        if not re.match(r"^\s*\.base\s+", raw):
            continue
        directive = parse_line(raw).directive
        if directive is not None and directive.name == ".base":
            return directive.args[0] if directive.args else ""
    return ""


# --- 逐项检查 ---------------------------------------------------------------

def check_structure(data: bytes, section: str, count: int) -> Check:
    """自己解 ELF：越界、重叠、表位置、对齐同余、目标段大小。不依赖外部工具。"""
    import struct as _s

    from nvisa.model.elf_rewrite import _phdrs, _sections
    try:
        secs = _sections(data)
        phs = _phdrs(data)
    except (ValueError, IndexError, _s.error) as e:   # RewriteError 是 ValueError
        return Check("structure", False, f"解不开：{e}")
    bad = []
    spans = []
    for s in secs:
        if not s.idx or not s.in_file:
            continue
        if s.offset + s.size > len(data):
            bad.append(f"{s.name} 越过文件末尾（{s.offset:#x}+{s.size:#x}）")
        if s.align and s.offset % s.align:
            bad.append(f"{s.name} 偏移 {s.offset:#x} 不满足 align={s.align}")
        spans.append((s.offset, s.offset + s.size, s.name))
    spans.sort()
    for (a0, a1, na), (b0, _b1, nb) in zip(spans, spans[1:]):
        if b0 < a1:
            bad.append(f"{na} 与 {nb} 重叠")
    e_phoff, e_shoff = _s.unpack_from("<QQ", data, 0x20)
    phnum, = _s.unpack_from("<H", data, 0x38)
    shnum, = _s.unpack_from("<H", data, 0x3C)
    if e_shoff + shnum * 64 > len(data):
        bad.append("section header table 越过文件末尾")
    if e_phoff + phnum * 56 > len(data):
        bad.append("program header table 越过文件末尾")
    for i, p in enumerate(phs):
        if p[2] + p[5] > len(data):
            bad.append(f"program header #{i} 越过文件末尾")
        if p[7] and (p[2] - p[3]) % p[7]:
            bad.append(f"program header #{i} 不满足 p_align 同余")
    tgt = next((s for s in secs if s.name == section), None)
    if tgt is None:
        bad.append(f"找不到 {section}")
    elif tgt.size != count * _INST:
        bad.append(f"{section} 大小 {tgt.size} ≠ {count} 条 × {_INST}")
    return Check("structure", not bad, "；".join(bad) if bad else
                 f"{len(spans)} 个 section、{len(phs)} 个 segment 自洽")


def check_external(path: Path) -> list[Check]:
    """`readelf -a` / `cuobjdump -elf` —— 有就跑，没有就记「跳过」。"""
    out = []
    for tool, args in (("readelf", ["-a"]), ("cuobjdump", ["-elf"])):
        exe = shutil.which(tool)
        if not exe:
            out.append(Check(tool, None, "不在 PATH 上"))
            continue
        proc = subprocess.run([exe, *args, str(path)], capture_output=True,
                              text=True, timeout=60)
        err = (proc.stderr or "").strip().splitlines()
        out.append(Check(tool, proc.returncode == 0,
                         err[0] if proc.returncode else ""))
    return out


def check_disasm(data: bytes, section: str, want: list[str]) -> Check:
    """整段交回 nvdisasm，逐条与源码比（标号按「指向第几条」比）。"""
    try:
        got = canonical_texts(emit_source(data, section).text)
    except Exception as e:                                        # noqa: BLE001
        return Check("disasm", False, f"读不回来：{e}")
    if len(got) != len(want):
        return Check("disasm", False, f"读回 {len(got)} 条，源码 {len(want)} 条")
    for i, (a, b) in enumerate(zip(got, want)):
        if a != b:
            return Check("disasm", False, f"第 {i} 条读回 {a!r}，源码写的是 {b!r}")
    return Check("disasm", True, f"{len(got)} 条逐条一致")


def check_control(data: bytes, section: str, ctrls: list,
                  reuse_slots: list[list[int]]) -> Check:
    """bits 105:121 必须与源码行前缀逐字段相等；`.reuse` 与 122:124 一致。

    判据：控制码跟着**源码行**走，不是跟着原地址留。
    `.reuse` 的位由 `probe_reuse_bits()` 逐 opcode 问 nvdisasm，
    问不出来（该 opcode 上这几位不是 reuse）就只要求「没写就别乱设」。
    """
    import cubin_sass
    from nvisa.oracle.cubin import Cubin, get_bits

    cub = Cubin(data)
    for i, ctrl in enumerate(ctrls):
        enc = cub.read(i * _INST, section)
        want = {"stall": ctrl.stall, "yield": int(ctrl.yield_), "wr": ctrl.wr_bar,
                "rd_bar": ctrl.rd_bar, "wait": ctrl.wait}
        for name, (lo, hi) in _CTRL_BITS.items():
            if get_bits(enc, lo, hi) != want[name]:
                return Check("control", False,
                             f"第 {i} 条的 {name}：编码里是 {get_bits(enc, lo, hi)}，"
                             f"源码写的是 {want[name]}")
        slots = reuse_slots[i]
        bits = get_bits(enc, *_REUSE)
        if slots:
            probed = cubin_sass.probe_reuse_bits(enc, slots)
            if probed is not None and bits != probed:
                return Check("control", False,
                             f"第 {i} 条的 .reuse：编码 {bits:#05b}，"
                             f"按操作数探出来应当是 {probed:#05b}")
    return Check("control", True, f"{len(ctrls)} 条的控制段与源码一致")


def check_regcount(data: bytes, src_text: str, section: str) -> Check:
    """The per-kernel EIATTR_REGCOUNT must equal the source directive."""
    declared = None
    for line in src_text.splitlines():
        parsed = parse_line(line)
        if parsed.directive is not None and parsed.directive.name == ".regcount":
            try:
                declared = int(parsed.directive.args[0], 0)
            except (IndexError, ValueError):
                return Check("regcount", False, ".regcount 解析失败")
            break
    if declared is None:
        return Check("regcount", None, "源码未显式声明")
    from nvisa.oracle.cubin import Cubin
    actual = Cubin(data).regcount_for_section(section)
    if actual is None:
        return Check("regcount", False, f"{section} 没有 EIATTR_REGCOUNT")
    if actual != declared:
        return Check("regcount", False,
                     f"元数据是 {actual}，源码写的是 {declared}")
    return Check("regcount", True, f"EIATTR_REGCOUNT={actual}")


def check_load(path: Path, data: bytes, smoke: bool) -> Check:
    """`cuModuleLoad` smoke —— 只加载不发射。没开或没 GPU 都记「跳过」。"""
    if not smoke:
        return Check("load", None, "没开（--smoke 才做）")
    from nvisa.model.reflow import _symbols
    from nvisa.oracle.execute import load_check
    names = [s["name"] for s in _symbols(data) if not s["name"].startswith("$")]
    r = load_check(path, names)
    if r.get("ok") is None:
        return Check("load", None, f"跑不了（{r.get('stage')}: {r.get('err')}）")
    return Check("load", bool(r["ok"]),
                 "驱动收下了（未发射任何 kernel）" if r["ok"]
                 else f"{r['stage']}: {r['err']}")


def verify(data: bytes, src_text: str, section: str, *,
           path: Path | None = None, smoke: bool = False) -> list[Check]:
    """对**已经打包好的 cubin 字节**跑完整验收。`path` 是给外部工具用的落地文件。"""
    want = canonical_texts(src_text)
    checks = [check_structure(data, section, len(want)),
              check_disasm(data, section, want),
              check_control(data, section, _ctrl_lines(src_text),
                            _reuse_slots(src_text)),
              check_regcount(data, src_text, section)]
    if path is not None:
        checks += check_external(path)
        checks.append(check_load(path, data, smoke))
    return checks


# --- 事务 -------------------------------------------------------------------

def _save_mode(base_path: Path, target: Path) -> int | None:
    for path in (target, base_path):
        if path.exists():
            return path.stat().st_mode & 0o7777
    return None


def save_source(base_path: Path, src_text: str, *, out_path: Path | None = None,
                force: bool = False, strip_debug: bool = False,
                debug=None, smoke: bool = False, base_data: bytes | None = None) -> SaveReport:
    """一次保存事务：全部通过才落盘，失败抛 `SourceAsmError`，基底一位不动。

    落盘用「同目录临时文件 + `os.replace`」—— 同一个文件系统上 `replace` 是原子
    的，不会留下写了一半的 cubin。外部工具检查也在这个临时文件上跑，跑完才改名。

    **保存前重读磁盘上的基底**：源码头里的 `.base` 是导出那一刻的内容 hash，两者
    对不上说明基底被外部改过，按冲突拒绝，而不是拿旧假设覆盖它。
    显式提供 base_data 时以这些字节为基底（CLI --stdin），不重新读取磁盘版本。
    """
    if is_source_bundle(src_text) or len(source_section_names(src_text)) > 1:
        return save_source_bundle(
            base_path, src_text, out_path=out_path, force=force,
            strip_debug=strip_debug, debug=debug, smoke=smoke, base_data=base_data)

    base = base_path.read_bytes() if base_data is None else bytes(base_data)
    declared = _declared_base(src_text)
    if declared and declared != base_hash(base):
        raise SourceAsmError([Diagnostic(
            0, 0, 1,
            f"基底对不上：源码写的是 .base {declared}，提供的 "
            f"{base_path.name} 基底是 {base_hash(base)} —— 按基底冲突处理，不覆盖")])

    data, asm = assemble_into(base, src_text, force=force,
                              strip_debug=strip_debug, debug=debug)
    # 符号链接保留：替换的是它指向的文件，不是把链接换成普通文件。
    target = Path(os.path.realpath(out_path or base_path))
    mode = _save_mode(base_path, target)
    rep = SaveReport(section=asm.section or "", count=len(asm.encodings),
                     old_size=len(base), new_size=len(data),
                     unchanged=data == base, warnings=list(asm.warnings),
                     debug_decisions=list(asm.debug_decisions))

    tmp = None
    try:
        fd, name = tempfile.mkstemp(prefix=".nvsass-", suffix=".cubin",
                                    dir=str(target.parent))
        tmp = Path(name)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        rep.checks = verify(data, src_text, rep.section, path=tmp, smoke=smoke)
        if not rep.ok:
            raise SourceAsmError([Diagnostic(0, 0, 1, "保存前验证没过：" + "；".join(
                c.line for c in rep.checks if c.ok is False))])
        if base_data is None and base_path.read_bytes() != base:
            raise SourceAsmError([Diagnostic(0, 0, 1, "基底在验证期间被外部修改，不覆盖")])
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, target)                 # 同一文件系统：原子替换
        tmp = None
        rep.written = str(target)
        rep.new_base = base_hash(data)
        # 只有「写回源码自己的基底」才需要重绑：--out 指向别的 cubin 时，
        # 源码的 .base 还对着原来那份基底，不该动。
        if target.resolve() == base_path.resolve():
            rep.new_source = refresh_source(src_text, rep.new_base, asm.addr_map)
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()
    return rep


def dry_run(base: bytes, src_text: str, *, force: bool = False,
            strip_debug: bool = False, debug=None) -> tuple[bytes, SaveReport]:
    """只汇编 + 验证，不落盘。给「保存前先看看」、**编辑器的缓冲区往返**和测试用。

    `new_base`/`new_source` 跟 `save_source()` 一个意思，只是这里的「新基底」是
    **回给调用方的这份字节**而不是磁盘上的文件：编辑器把它收进 cubin 缓冲区之后，
    源码就得跟着重绑到它，否则下一次汇编又要撞「基底对不上」。
    """
    if is_source_bundle(src_text) or len(source_section_names(src_text)) > 1:
        return dry_run_bundle(base, src_text, force=force,
                              strip_debug=strip_debug, debug=debug)

    data, asm = assemble_into(base, src_text, force=force,
                              strip_debug=strip_debug, debug=debug)
    rep = SaveReport(section=asm.section or "", count=len(asm.encodings),
                     old_size=len(base), new_size=len(data),
                     unchanged=data == base, warnings=list(asm.warnings),
                     debug_decisions=list(asm.debug_decisions))
    rep.checks = verify(data, src_text, rep.section)
    if rep.ok:
        rep.new_base = base_hash(data)
        rep.new_source = refresh_source(src_text, rep.new_base, asm.addr_map)
    return data, rep


def _bundle_chunks(src_text: str) -> list[tuple[str, str]]:
    """Split a bundle while retaining original line numbers for diagnostics."""
    lines = src_text.splitlines()
    starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = re.match(r"^\s*\.section\s+(\S+)\s*(?://.*)?$", line)
        if m:
            starts.append((i, m.group(1)))
    seen: set[str] = set()
    for line, name in starts:
        if name in seen:
            raise SourceAsmError([Diagnostic(
                line, 0, len(lines[line]), f"section {name} 重复定义")])
        seen.add(name)

    chunks: list[tuple[str, str]] = []
    for n, (start, name) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        kept: list[str] = []
        for i, line in enumerate(lines):
            # Keep global architecture/comments for context, but validate the
            # shared .base once against the original input instead of once per
            # sequentially rewritten cubin.
            global_arch = i < starts[0][0] and line.lstrip().startswith(".arch ")
            kept.append(line if global_arch or start <= i < end else "")
        chunks.append((name, "\n".join(kept) + ("\n" if src_text.endswith("\n") else "")))
    return chunks


def _check_bundle_base(base: bytes, src_text: str) -> None:
    declared = _declared_base(src_text)
    if declared and declared != base_hash(base):
        raise SourceAsmError([Diagnostic(
            0, 0, 1, f"基底对不上：源码写的是 .base {declared}，"
            f"给的 cubin 是 {base_hash(base)} —— 基底在导出之后被改过，"
            "按外部修改冲突处理")])


def _assemble_bundle(base: bytes, src_text: str, *, force: bool = False,
                     strip_debug: bool = False, debug=None):
    """Assemble every source section into one evolving cubin transaction."""
    _check_bundle_base(base, src_text)
    chunks = _bundle_chunks(src_text)
    from nvisa.oracle.cubin import Cubin
    expected = [s.name for s in Cubin(base).sections if s.name.startswith(".text")]
    got = [name for name, _chunk in chunks]
    if set(got) != set(expected):
        missing = [name for name in expected if name not in got]
        extra = [name for name in got if name not in expected]
        detail = []
        if missing:
            detail.append("缺少 " + "、".join(missing))
        if extra:
            detail.append("基底中不存在 " + "、".join(extra))
        raise SourceAsmError([Diagnostic(
            0, 0, 1, "整份源码必须保留基底的全部 .text section（不支持新增/删除）："
            + "；".join(detail))])
    data = base
    assembled = []
    for name, chunk in chunks:
        data, asm = assemble_into(data, chunk, force=force,
                                  strip_debug=strip_debug, debug=debug)
        if asm.section != name:
            raise SourceAsmError([Diagnostic(
                0, 0, 1, f"源码块 {name} 被解析成了 {asm.section}")])
        assembled.append((name, chunk, asm))
    return data, assembled


def _bundle_report(base: bytes, data: bytes, src_text: str, assembled,
                   *, path: Path | None = None, smoke: bool = False) -> SaveReport:
    names = [name for name, _chunk, _asm in assembled]
    count = sum(len(asm.encodings) for _name, _chunk, asm in assembled)
    warnings = [w for _name, _chunk, asm in assembled for w in asm.warnings]
    decisions = [d for _name, _chunk, asm in assembled for d in asm.debug_decisions]
    rep = SaveReport(section=f"{len(names)} 个 .text section", sections=names,
                     count=count, old_size=len(base), new_size=len(data),
                     unchanged=data == base, warnings=warnings,
                     debug_decisions=decisions)
    for name, chunk, _asm in assembled:
        for check in verify(data, chunk, name):
            check.name = f"{name}:{check.name}"
            rep.checks.append(check)
    if path is not None:
        rep.checks += check_external(path)
        rep.checks.append(check_load(path, data, smoke))
    if rep.ok:
        rep.new_base = base_hash(data)
        maps = {name: asm.addr_map for name, _chunk, asm in assembled}
        rep.new_source = refresh_source_bundle(src_text, rep.new_base, maps)
    return rep


def dry_run_bundle(base: bytes, src_text: str, *, force: bool = False,
                   strip_debug: bool = False, debug=None) -> tuple[bytes, SaveReport]:
    data, assembled = _assemble_bundle(
        base, src_text, force=force, strip_debug=strip_debug, debug=debug)
    return data, _bundle_report(base, data, src_text, assembled)


def save_source_bundle(base_path: Path, src_text: str, *,
                       out_path: Path | None = None, force: bool = False,
                       strip_debug: bool = False, debug=None,
                       smoke: bool = False, base_data: bytes | None = None) -> SaveReport:
    """Atomically assemble and verify a multi-kernel source document."""
    base = base_path.read_bytes() if base_data is None else bytes(base_data)
    data, assembled = _assemble_bundle(
        base, src_text, force=force, strip_debug=strip_debug, debug=debug)
    # 符号链接保留：替换的是它指向的文件，不是把链接换成普通文件。
    target = Path(os.path.realpath(out_path or base_path))
    mode = _save_mode(base_path, target)
    tmp = None
    try:
        fd, name = tempfile.mkstemp(prefix=".nvsass-", suffix=".cubin",
                                    dir=str(target.parent))
        tmp = Path(name)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        rep = _bundle_report(base, data, src_text, assembled, path=tmp, smoke=smoke)
        if not rep.ok:
            raise SourceAsmError([Diagnostic(0, 0, 1, "保存前验证没过：" + "；".join(
                c.line for c in rep.checks if c.ok is False))])
        if base_data is None and base_path.read_bytes() != base:
            raise SourceAsmError([Diagnostic(0, 0, 1, "基底在验证期间被外部修改，不覆盖")])
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, target)
        tmp = None
        rep.written = str(target)
        if target.resolve() != base_path.resolve():
            rep.new_source = ""
        return rep
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()
