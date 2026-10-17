"""变长 `.text` 与 cubin 打包 —— `nvisa/model/elf_rewrite.py`。

判据：

* **端到端**：在源码里插一条 / 删一条，写出来的 cubin nvdisasm 能整段读回，且
  指令序列与源码逐条一致（标号按「指向第几条」比 —— 地址会变，序号不会）；
* **元数据**：符号 `st_value`/`st_size`、`.nv.info` 的指令偏移、`.debug_frame`
  的 FDE `address_range`、后续 section 的 `sh_offset`、SHT/PHT 位置全都跟着改，
  且 program header 的归属沿用基底的 containment；
* **拒绝**：非 CUDA/非 sm_90 的 ELF、认不出的 program header、映射不到的旧地址、
  行号类调试信息、看着像指令偏移的未知 `.nv.info` 属性 —— 报错，不硬来。
"""
from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import _norm_sass, sass_by_addr, segtable           # noqa: E402
from nvisa.model.elf_rewrite import (RewriteError, _sections,       # noqa: E402
                                     _phdrs, rewrite)
from nvisa.model.reflow import _symbols                             # noqa: E402
from nvisa.model.sass_asm import SourceAsmError, assemble_into      # noqa: E402
from nvisa.model.sass_source import emit_source                     # noqa: E402

CUBINS = sorted((ROOT / "corpus" / "cubins").glob("*.cubin"))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins")

FMA = ROOT / "corpus" / "cubins" / "fma.sm_90.cubin"
CONTROL = ROOT / "corpus" / "cubins" / "control.sm_90.cubin"
NOP_LINE = "[B------:R-:W-:-:S01] NOP;"
_LBL = re.compile(r"\.L_[0-9a-f]+")


def _canon(src_text: str) -> list[str]:
    """指令文本序列，标号换成「指向第几条指令」——插删之后地址会变，序号不会。"""
    lines = src_text.splitlines()
    idx, n = {}, 0
    for l in lines:
        if l.startswith(".L_") and l.endswith(":"):
            idx[l[:-1]] = n
        elif l.startswith("[B"):
            n += 1
    return [_LBL.sub(lambda m: f"#{idx.get(m.group(), '?')}",
                     _norm_sass(l.split("//")[0].split("]", 1)[1]))
            for l in lines if l.startswith("[B")]


def _edit(path: Path, at: int, line: str | None):
    """在第 `at` 条指令处插入 `line`（None 表示删掉这一条）。返回 (基底, 新源码)。"""
    data = path.read_bytes()
    lines = emit_source(data).text.splitlines()
    i = [j for j, l in enumerate(lines) if l.startswith("[B")][at]
    if line is None:
        del lines[i]
    else:
        lines.insert(i, line)
    return data, "\n".join(lines) + "\n"


# --- 端到端 ----------------------------------------------------------------

@pytest.mark.parametrize("path,at,line,delta", [
    (FMA, 3, NOP_LINE, +16),
    (FMA, 5, None, -16),
    (CONTROL, 3, NOP_LINE, +16),                       # 两个函数，插在前一个里
    (CONTROL, 220, NOP_LINE, +16),                     # 插在 device function 里
    (CONTROL, 6, None, -16),
])
def test_insert_delete_end_to_end(tmp_path, path, at, line, delta):
    if not path.exists():
        pytest.skip(f"需要 {path.name}")
    data, src = _edit(path, at, line)
    out, asm = assemble_into(data, src)
    assert len(out) - len(data) == delta

    dest = tmp_path / path.name
    dest.write_bytes(out)
    got = sass_by_addr(dest)
    assert len(got) == len(asm.encodings)              # 整段都读得回来
    assert _canon(emit_source(out).text) == _canon(src)


def test_section_grows_and_later_sections_move():
    data, src = _edit(FMA, 3, NOP_LINE)
    out, asm = assemble_into(data, src)
    before = {s.name: (s.offset, s.size) for s in _sections(data)}
    after = {s.name: (s.offset, s.size) for s in _sections(out)}
    assert set(before) == set(after)                   # section 数量/名字不变
    tgt = asm.section
    assert after[tgt][1] == before[tgt][1] + 16
    later = [n for n, (off, _s) in before.items() if off > before[tgt][0]]
    assert later and all(after[n][0] == before[n][0] + 16 for n in later)


def test_headers_and_segments_follow():
    data, src = _edit(FMA, 3, NOP_LINE)
    out, _asm = assemble_into(data, src)
    # SHT/PHT 挪了，且头里的 e_shoff/e_phoff 指着新位置
    e_phoff, e_shoff = struct.unpack_from("<QQ", out, 0x20)
    shnum, = struct.unpack_from("<H", out, 0x3C)
    phnum, = struct.unpack_from("<H", out, 0x38)
    assert e_shoff + shnum * 64 <= len(out) and e_phoff + phnum * 56 <= len(out)
    # 覆盖 .text 的那个 segment 跟着长大；段的归属照抄基底
    tsec = next(s for s in _sections(out) if s.name.startswith(".text"))
    hit = [p for p in _phdrs(out) if p[2] == tsec.offset and p[5] == tsec.size]
    assert hit, "应当有一个 program header 正好覆盖新的 .text"
    for p in _phdrs(out):
        assert not p[7] or (p[2] - p[3]) % p[7] == 0    # p_align 同余


def test_symbols_and_nvinfo_follow_the_code():
    if not CONTROL.exists():
        pytest.skip("需要 control.sm_90.cubin")
    data, src = _edit(CONTROL, 3, NOP_LINE)             # 插在 device function 之前
    out, _asm = assemble_into(data, src)
    was = {s["name"]: s for s in _symbols(data)}
    now = {s["name"]: s for s in _symbols(out)}
    assert set(was) == set(now)
    kernel = "_Z14control_kernelPiii"
    dev = "$_Z14control_kernelPiii$_Z6helperi"
    assert now[kernel]["value"] == was[kernel]["value"]          # 起点没动
    assert now[kernel]["size"] == was[kernel]["size"] + 16       # 长了一条
    assert now[dev]["value"] == was[dev]["value"] + 16           # 整体后移
    assert now[dev]["size"] == was[dev]["size"]
    assert _exit_offsets(out) == [o + 16 for o in _exit_offsets(data)]


def _exit_offsets(data: bytes) -> list[int]:
    """`.nv.info.<fn>` 里的 `EIATTR_EXIT_INSTR_OFFSETS`（0x1c）payload。"""
    out = []
    for s in _sections(data):
        if not s.name.startswith(".nv.info."):
            continue
        pos, end = s.offset, s.offset + s.size
        while pos + 4 <= end:
            fmt, attr, plen = struct.unpack_from("<BBH", data, pos)
            if fmt != 4:
                pos += 4
                continue
            if attr == 0x1C:
                out += list(struct.unpack_from("<" + "I" * (plen // 4), data, pos + 4))
            pos += 4 + plen
    return out


def test_debug_frame_fde_range_updated():
    data, src = _edit(FMA, 3, NOP_LINE)
    out, _asm = assemble_into(data, src)
    assert _fde_ranges(out) == [r + 16 for r in _fde_ranges(data)]


def _fde_ranges(data: bytes) -> list[int]:
    """`.debug_frame` 里每条 FDE 的 `address_range`（DWARF64）。"""
    sec = next((s for s in _sections(data) if s.name == ".debug_frame"), None)
    if sec is None:
        return []
    out, pos, end = [], sec.offset, sec.offset + sec.size
    while pos + 4 <= end:
        l32, = struct.unpack_from("<I", data, pos)
        if l32 == 0xFFFFFFFF:
            length, = struct.unpack_from("<Q", data, pos + 4)
            body, idw = pos + 12, 8
        else:
            length, body, idw = l32, pos + 4, 4
        if not length or body + length > end:
            break
        cie_id, = struct.unpack_from("<Q" if idw == 8 else "<I", data, body)
        if cie_id != (0xFFFFFFFFFFFFFFFF if idw == 8 else 0xFFFFFFFF):
            out.append(struct.unpack_from("<Q", data, body + idw + 8)[0])
        pos = body + length
    return out


def test_tail_padding_is_only_a_warning_not_a_silent_change():
    """长度不再是 `sh_addralign` 的倍数时**说出来** —— ptxas 一向补齐到 128。"""
    data, src = _edit(FMA, 3, NOP_LINE)
    _out, asm = assemble_into(data, src)
    assert any("sh_addralign" in w for w in asm.warnings)


# --- 拒绝 ------------------------------------------------------------------

def test_refuses_non_cuda_elf():
    data = bytearray(FMA.read_bytes())
    struct.pack_into("<H", data, 18, 62)                # EM_X86_64
    with pytest.raises(RewriteError, match="EM_CUDA"):
        rewrite(bytes(data), ".text", b"", {})


def test_refuses_other_arch():
    data = bytearray(FMA.read_bytes())
    flags, = struct.unpack_from("<I", data, 48)
    struct.pack_into("<I", data, 48, (flags & ~0xFF) | 80)   # sm_80
    with pytest.raises(RewriteError, match="sm_90"):
        rewrite(bytes(data), ".text", b"", {})


def test_refuses_unmapped_old_address():
    """符号/`.nv.info` 指着的旧地址不在映射表里就拒绝 —— 不猜它去哪了。"""
    data = FMA.read_bytes()
    sec = next(s for s in _sections(data) if s.name.startswith(".text"))
    with pytest.raises(RewriteError, match="新布局里没有这条指令"):
        rewrite(data, sec.name, b"\0" * sec.size, {0: 0})   # 缺段末那个边界


def test_refuses_line_debug_unless_stripped(tmp_path):
    """行号类调试信息证明不了还对：默认拒绝，显式剥离才继续，并如实报告。"""
    data = bytearray(FMA.read_bytes())
    secs = _sections(bytes(data))
    victim = next(s for s in secs if s.name == ".debug_frame")
    # 把 .debug_frame 改名成 .debug_line（改的是 shstrtab 里的字节，长度一致）
    shstr = next(s for s in secs if s.name == ".shstrtab")
    pos = shstr.offset + victim.name_off
    data[pos:pos + len(b".debug_frame")] = b".debug_line\x00"
    tampered = bytes(data)
    sec = next(s for s in _sections(tampered) if s.name.startswith(".text"))
    amap = {a: a for a in range(0, sec.size + 1, 16)}
    # 没有显式策略就不许往下走（旧的 strip_debug 布尔是它的兼容写法）。
    with pytest.raises(RewriteError, match="没有调试策略"):
        rewrite(tampered, sec.name, b"\0" * sec.size, amap)
    out, rep = rewrite(tampered, sec.name, b"\0" * sec.size, amap, strip_debug=True)
    assert any("已剥离" in d for d in rep.debug)
    assert next(s for s in _sections(out) if s.name == ".debug_line").size == 0


def test_unknown_nvinfo_offset_like_payload_is_refused():
    """未知属性的 payload 命中挪过的指令地址 -> 默认拒绝（force 才放行）。"""
    data = bytearray(FMA.read_bytes())
    sec = next(s for s in _sections(bytes(data)) if s.name.startswith(".text"))
    info = next(s for s in _sections(bytes(data))
                if s.name.startswith(".nv.info."))
    # 造一条未知属性（EIFMT_SVAL, attr 0x50），payload 是 0x20 —— 一条挪过的指令
    struct.pack_into("<BBHI", data, info.offset, 4, 0x50, 4, 0x20)
    tampered = bytes(data)
    amap = {a: (a if a < 0x20 else a + 16) for a in range(0, sec.size + 1, 16)}
    with pytest.raises(RewriteError, match="认不出的属性"):
        rewrite(tampered, sec.name, b"\0" * (sec.size + 16), amap)
    out, rep = rewrite(tampered, sec.name, b"\0" * (sec.size + 16), amap, force=True)
    assert any("未知 .nv.info" in w for w in rep.warnings)
    assert struct.unpack_from("<I", out, _sections(out)[info.idx].offset + 4)[0] == 0x20


def test_known_non_offset_attrs_do_not_trigger_the_gate():
    """`EIATTR_FRAME_SIZE` 这类值撞上指令地址不该被当成偏移拒绝。

    `localmem.sm_90.cubin` 的 frame size 正好是 0xc0，与一条挪过的指令同值 ——
    第一版没有白名单，整个 cubin 就插不了指令。
    """
    from nvisa.model.elf_rewrite import NON_OFFSET_ATTRS
    assert 0x11 in NON_OFFSET_ATTRS
    data = bytearray(FMA.read_bytes())
    sec = next(s for s in _sections(bytes(data)) if s.name.startswith(".text"))
    info = next(s for s in _sections(bytes(data)) if s.name == ".nv.info")
    struct.pack_into("<BBHI", data, info.offset, 4, 0x11, 4, 0x20)
    amap = {a: (a if a < 0x20 else a + 16) for a in range(0, sec.size + 1, 16)}
    out, _rep = rewrite(bytes(data), sec.name, b"\0" * (sec.size + 16), amap)
    assert struct.unpack_from("<I", out, info.offset + 4)[0] == 0x20   # 原样保留


def test_length_must_be_instruction_aligned():
    data = FMA.read_bytes()
    sec = next(s for s in _sections(data) if s.name.startswith(".text"))
    with pytest.raises(RewriteError, match="16 的倍数"):
        rewrite(data, sec.name, b"\0" * 17, {})


def test_deleting_a_branch_target_is_refused():
    """删掉别人跳转的目标 -> 源码汇编 的重定位就报错，整次编译失败。"""
    if not CONTROL.exists():
        pytest.skip("需要 control.sm_90.cubin")
    data = CONTROL.read_bytes()
    src = emit_source(data)
    target = sorted(src.labels)[0]
    lines = src.text.splitlines()
    i = next(j for j, l in enumerate(lines)
             if l.startswith("[B") and f"@{target:#06x}" in l)
    del lines[i]
    with pytest.raises(SourceAsmError, match="找不到"):
        assemble_into(data, "\n".join(lines) + "\n")


@pytest.mark.skipif(os.environ.get("NVISA_SLOW") != "1",
                    reason="全语料插删要跑 nvdisasm：设 NVISA_SLOW=1 才跑")
@pytest.mark.parametrize("path", CUBINS, ids=lambda p: p.name)
def test_whole_corpus_grows_and_shrinks(tmp_path, path):
    for at, line, delta in ((3, NOP_LINE, 16), (4, None, -16)):
        data, src = _edit(path, at, line)
        out, asm = assemble_into(data, src)
        assert len(out) - len(data) == delta
        dest = tmp_path / f"{path.stem}-{delta}.cubin"
        dest.write_bytes(out)
        assert len(sass_by_addr(dest)) == len(asm.encodings)
        assert _canon(emit_source(out).text) == _canon(src)
