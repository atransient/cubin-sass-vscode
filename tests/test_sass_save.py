"""保存事务与验收 —— `nvisa/model/sass_save.py`。

保存事务有一份**最低验收集**（①~⑦），这份文件逐条把它钉成测试：

1. 导出源码不改直接保存，`.text` 逐字节一致；
2. 插入超过尾部 NOP 额度的指令，`.text` 至少长 16 字节，ELF 合法、nvdisasm 逐行
   读得回；
3. 循环前插删多条后本地 `BRA` 仍指向同一标号；控制码与 bits 105:121 完全一致、
   `.reuse` 与探明的 122:124 一致；两行对调证明控制码随源码行走；
4. `control.sm_90.cubin`（kernel + device function + `CALL.REL`）的符号值/函数
   大小/`.nv.info` 随布局更新；
5. 七类错误整次拒绝且不产生部分输出；
6. 产物过 `readelf`/`cuobjdump` 结构检查、全段 nvdisasm 回环、`cuModuleLoad`
   smoke（没工具/没 GPU 记「跳过」，**不算通过**）；
7. 隔离环境（`CUASM_PATH` 指向不存在的目录 + 禁止 `import CuAsm`）里，导出、
   汇编、变长打包照样跑；外加一道静态门禁：产品代码不许新增 CuAsm import 或
   `cuasm.py` subprocess。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import segtable                                    # noqa: E402
from nvisa.model.reflow import _symbols                            # noqa: E402
from nvisa.model.sass_asm import SourceAsmError                    # noqa: E402
from nvisa.model.sass_save import (canonical_texts, dry_run,       # noqa: E402
                                   save_source)
from nvisa.model.sass_source import emit_all_sources, emit_source  # noqa: E402
from nvisa.oracle.cubin import Cubin, get_bits                     # noqa: E402

CUBINS = sorted((ROOT / "corpus" / "cubins").glob("*.cubin"))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins")

FMA = ROOT / "corpus" / "cubins" / "fma.sm_90.cubin"
CONTROL = ROOT / "corpus" / "cubins" / "control.sm_90.cubin"
NOP = "[B------:R-:W-:-:S01] NOP;"


def _lines(path: Path) -> list[str]:
    return emit_source(path.read_bytes()).text.splitlines()


def _insn_idx(lines: list[str]) -> list[int]:
    return [i for i, l in enumerate(lines) if l.startswith("[B")]


def _text_of(data: bytes, section: str) -> bytes:
    sec = next(s for s in Cubin(data).sections if s.name == section)
    return data[sec.offset:sec.offset + sec.size]


# --- ① 原样保存逐字节一致 ---------------------------------------------------

def test_accept_1_unmodified_save_is_byte_identical(tmp_path):
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    src = emit_source(base.read_bytes()).text
    rep = save_source(base, src)
    assert rep.ok and rep.unchanged
    assert base.read_bytes() == FMA.read_bytes()
    assert rep.written == str(base)
    assert rep.hardware_verified is False          # 报告不冒充硬件验证过


@pytest.mark.parametrize("bundle", [False, True])
@pytest.mark.parametrize("mode", [0o644, 0o755])
def test_source_save_preserves_existing_permissions(tmp_path, bundle, mode):
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    base.chmod(mode)
    src = (emit_all_sources if bundle else emit_source)(base.read_bytes()).text
    assert save_source(base, src).ok
    assert base.stat().st_mode & 0o7777 == mode


@pytest.mark.parametrize("bundle", [False, True])
def test_indented_source_validates_and_rebinds_without_losing_layout(bundle):
    data = CONTROL.read_bytes()
    src = (emit_all_sources if bundle else emit_source)(data).text
    indented = "\n".join(" \t" + line for line in src.splitlines()) + "\n"
    out, rep = dry_run(data, indented)
    assert rep.ok and out == data, rep.summary()
    assert canonical_texts(indented) == canonical_texts(src)
    assert " \t.base " in rep.new_source
    again, second = dry_run(out, rep.new_source)
    assert second.ok and again == data


@pytest.mark.parametrize("bundle", [False, True])
def test_external_change_during_verification_is_not_overwritten(tmp_path, monkeypatch, bundle):
    from nvisa.model import sass_save

    base = tmp_path / FMA.name
    original = FMA.read_bytes()
    base.write_bytes(original)
    source = (emit_all_sources if bundle else emit_source)(original).text
    verify = sass_save.verify

    def changed(*args, **kwargs):
        checks = verify(*args, **kwargs)
        base.write_bytes(b"external replacement")
        return checks

    monkeypatch.setattr(sass_save, "verify", changed)
    with pytest.raises(SourceAsmError, match="外部修改"):
        save_source(base, source)
    assert base.read_bytes() == b"external replacement"


def test_regcount_directive_updates_kernel_metadata():
    data = FMA.read_bytes()
    src = emit_source(data)
    old = Cubin(data).regcount_for_section(src.section)
    assert old is not None
    if old == 255:
        pytest.skip("寄存器预算已经到上限")
    new = min(255, old + 8)
    edited = re.sub(r"(?m)^\.regcount \d+$", f".regcount {new}", src.text)
    out, rep = dry_run(data, edited)
    assert rep.ok and not rep.unchanged
    assert Cubin(out).regcount_for_section(src.section) == new
    assert next(c for c in rep.checks if c.name == "regcount").ok is True
    assert f".regcount {new}" in rep.new_source


def test_regcount_can_be_lowered_verbatim_at_user_risk():
    data = FMA.read_bytes()
    src = emit_source(data)
    edited = re.sub(r"(?m)^\.regcount \d+$", ".regcount 1", src.text)
    out, rep = dry_run(data, edited)
    assert rep.ok
    assert Cubin(out).regcount_for_section(src.section) == 1


def test_all_kernel_source_roundtrips_as_one_transaction():
    data = CUBINS[0].read_bytes()
    src = emit_all_sources(data)
    out, rep = dry_run(data, src.text)
    assert rep.ok and rep.unchanged
    assert out == data
    assert rep.sections == src.sections
    assert rep.count == sum(
        s.size // 16 for s in Cubin(data).sections if s.name in src.sections)


def test_all_kernel_source_rejects_deleted_section_header():
    data = CUBINS[0].read_bytes()
    src = emit_all_sources(data)
    broken = src.text.replace(f".section {src.sections[0]}\n", "", 1)
    with pytest.raises(SourceAsmError, match="必须保留基底的全部"):
        dry_run(data, broken)


# --- ② 超出尾部 NOP 额度的插入 ----------------------------------------------

def test_accept_2_insert_grows_the_section(tmp_path):
    """定长插入/删除 靠尾部 NOP 顶额度；这里连插 5 条，段必须真长出来。"""
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    lines = _lines(base)
    at = _insn_idx(lines)[3]
    for _ in range(5):
        lines.insert(at, NOP)
    rep = save_source(base, "\n".join(lines) + "\n")
    assert rep.ok and not rep.unchanged
    grown = base.read_bytes()
    assert len(_text_of(grown, rep.section)) >= \
        len(_text_of(FMA.read_bytes(), rep.section)) + 16
    # nvdisasm 逐行读回目标文本 + ELF 结构自洽，都在 checks 里
    assert {c.name: c.ok for c in rep.checks}["disasm"] is True
    assert {c.name: c.ok for c in rep.checks}["structure"] is True


# --- ③ 分支、控制码、reuse ---------------------------------------------------

def test_accept_3_branch_control_and_reuse_follow_the_source():
    if not CONTROL.exists():
        pytest.skip("需要 control.sm_90.cubin")
    data = CONTROL.read_bytes()
    src = emit_source(data)
    lines = src.text.splitlines()
    idx = _insn_idx(lines)
    # 找一条回跳（目标在自己前面）的 BRA —— 那就是循环
    back = None
    for n, i in enumerate(idx):
        m = re.search(r"BRA (\.L_[0-9a-f]+)", lines[i])
        if m and int(m.group(1)[3:], 16) < n * 16:
            back = (n, i, m.group(1))
            break
    assert back, "control.cubin 里应当有回跳"
    _n, _i, label = back
    head = lines.index(f"{label}:")
    lines.insert(head, NOP)                       # 在循环前插一条
    del lines[_insn_idx(lines)[2]]                # 再删一条别处的
    out, rep = dry_run(data, "\n".join(lines) + "\n")
    assert rep.ok

    # 分支仍然指向那个标号（按「第几条指令」算，地址会变序号不会）
    new_src = emit_source(out)
    want = canonical_texts("\n".join(lines) + "\n")
    assert canonical_texts(new_src.text) == want

    # 控制码逐字段一致、reuse 一致 —— check_control 就是这条判据
    assert {c.name: c.ok for c in rep.checks}["control"] is True


def test_accept_3_swapping_two_lines_moves_the_control_code():
    """控制码随**源码行**走，不是随原 cubin 地址留。"""
    data = FMA.read_bytes()
    lines = emit_source(data).text.splitlines()
    idx = _insn_idx(lines)
    a, b = idx[3], idx[4]
    lines[a], lines[b] = lines[b], lines[a]
    out, rep = dry_run(data, "\n".join(lines) + "\n")
    assert rep.ok and {c.name: c.ok for c in rep.checks}["control"] is True
    cub = Cubin(out)
    for pos in (a, b):
        n = idx.index(pos)
        enc = cub.read(n * 16, rep.section)
        want = int(lines[pos][lines[pos].index(":S") + 2:lines[pos].index("]")])
        assert get_bits(enc, 105, 108) == want


# --- ④ kernel + device function ---------------------------------------------

def test_accept_4_symbols_and_nvinfo_follow(tmp_path):
    if not CONTROL.exists():
        pytest.skip("需要 control.sm_90.cubin")
    base = tmp_path / CONTROL.name
    base.write_bytes(CONTROL.read_bytes())
    lines = _lines(base)
    lines.insert(_insn_idx(lines)[3], NOP)
    rep = save_source(base, "\n".join(lines) + "\n")
    assert rep.ok
    was = {s["name"]: s for s in _symbols(CONTROL.read_bytes())}
    now = {s["name"]: s for s in _symbols(base.read_bytes())}
    dev = "$_Z14control_kernelPiii$_Z6helperi"
    assert now[dev]["value"] == was[dev]["value"] + 16
    assert now["_Z14control_kernelPiii"]["size"] == \
        was["_Z14control_kernelPiii"]["size"] + 16


# --- ⑤ 七类错误都整次拒绝，且不产生部分输出 ---------------------------------

@pytest.mark.parametrize("name,mutate,expect", [
    ("缺控制码", lambda ls, i: ls.__setitem__(i, ls[i].split("]", 1)[1].strip()),
     "没有控制码"),
    ("非法控制码", lambda ls, i: ls.__setitem__(
        i, "[B------:R-:W-:-:S99]" + ls[i].split("]", 1)[1]), "stall"),
    ("未定义标号", lambda ls, i: ls.__setitem__(
        i, "[B------:R-:W-:-:S01] BRA .L_nope;"), "没有定义"),
    ("重复标号", lambda ls, i: ls.__setitem__(i, ".L_x:\n.L_x:\n" + ls[i]),
     "重复定义"),
    ("不支持的 form", lambda ls, i: ls.__setitem__(
        i, "[B------:R-:W-:-:S01] NOTANOPCODE R0, R1;"), "编不出来"),
    ("寄存器超预算", lambda ls, i: ls.__setitem__(
        i, "[B------:R-:W-:-:S01] IMAD.MOV.U32 R200, RZ, RZ, RZ;"), "超预算"),
])
def test_accept_5_bad_input_is_refused_atomically(tmp_path, name, mutate, expect):
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    lines = _lines(base)
    mutate(lines, _insn_idx(lines)[4])
    with pytest.raises(SourceAsmError) as e:
        save_source(base, "\n".join(lines) + "\n")
    assert expect in str(e.value)
    assert base.read_bytes() == FMA.read_bytes()          # 基底一个字节没动
    assert not list(tmp_path.glob(".nvsass-*"))           # 也没留下半个临时文件


def test_saving_twice_in_a_row_works(tmp_path):
    """第一次保存把基底换掉了，源码得跟着重绑到新基底 —— 否则第二次保存会被
    「基底对不上」的冲突闸挡下来（源码头里还写着旧 hash）。"""
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    lines = _lines(base)
    at = _insn_idx(lines)[3]
    lines.insert(at, NOP)
    rep = save_source(base, "\n".join(lines) + "\n")
    assert rep.ok and not rep.unchanged
    from nvisa.model.sass_source import base_hash
    assert rep.new_base == base_hash(base.read_bytes())
    src2 = rep.new_source
    assert f".base {rep.new_base}" in src2
    # 重绑之后的源码就是新基底的忠实导出：行尾原地址注释也跟着挪了
    assert canonical_texts(src2) == canonical_texts(
        emit_source(base.read_bytes()).text)

    # 第二次：在重绑后的源码上再插一条，照样存得下去
    lines2 = src2.splitlines()
    lines2.insert(_insn_idx(lines2)[3], NOP)
    rep2 = save_source(base, "\n".join(lines2) + "\n")
    assert rep2.ok and not rep2.unchanged
    assert rep2.count == rep.count + 1


def test_cli_assembles_source_from_stdin_without_any_file_on_disk(tmp_path):
    """虚拟文档模式：源码从标准输入进来，重绑后的文本从响应里回去 —— 全程磁盘
    上除了 cubin 本身没有第二个文件（扩展的 `.nvsass` 只活在内存里）。"""
    import json
    import subprocess
    import sys

    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    lines = _lines(base)
    lines.insert(_insn_idx(lines)[3], NOP)
    src = "\n".join(lines) + "\n"

    def run(text: str) -> dict:
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "cubin_sass.py"),
                            str(base), "--assemble-source", "-", "--out", str(base)],
                           input=text, capture_output=True, text=True, timeout=600)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    first = run(src)
    assert first["ok"] and first["source"], first.get("error")
    assert first["source"].splitlines()[2] == f".base {first['base']}"
    assert sorted(p.name for p in tmp_path.iterdir()) == [FMA.name]   # 没多出文件

    second = run(first["source"])          # 拿重绑后的源码再存一次
    assert second["ok"] and second["unchanged"]


def test_buffer_roundtrip_never_touches_the_file_on_disk(tmp_path):
    """编辑器的模型：打开的那份 cubin **字节**是唯一真相，SASS preview 与
    `.nvsass` 都是它的视图。所以汇编是缓冲区 -> 缓冲区（`dry_run`），连改三次都
    不该碰磁盘，源码每次重绑到刚编出来的那份字节 —— `.base` 永远对得上，
    「第一次能存、第二次报基底对不上」在这条路上根本不成立。"""
    from nvisa.model.sass_source import base_hash

    on_disk = FMA.read_bytes()
    buf = on_disk
    src = emit_source(buf).text
    assert src.splitlines()[2] == f".base {base_hash(buf)}"

    for _ in range(3):
        lines = src.splitlines()
        lines.insert(_insn_idx(lines)[3], NOP)
        buf, rep = dry_run(buf, "\n".join(lines) + "\n")
        assert rep.ok and rep.new_source
        src = rep.new_source
        assert src.splitlines()[2] == f".base {base_hash(buf)}"

    assert len(_text_of(buf, rep.section)) == \
        len(_text_of(on_disk, rep.section)) + 3 * 16
    assert FMA.read_bytes() == on_disk          # 磁盘上一个字节没动


def test_accept_5_external_change_of_the_base_is_a_conflict(tmp_path):
    """源码头里的 `.base` 是导出那一刻的 hash；对不上就是外部改过，拒绝覆盖。"""
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    src = emit_source(base.read_bytes()).text
    # 模拟「导出之后基底被别的工具改了」
    other = bytearray(base.read_bytes())
    other[-1] ^= 0xFF
    base.write_bytes(bytes(other))
    with pytest.raises(SourceAsmError, match="基底对不上"):
        save_source(base, src)
    assert base.read_bytes() == bytes(other)              # 没被覆盖


def test_accept_5_unknown_nvinfo_offset_attr_refuses_variable_length(tmp_path):
    import struct

    from nvisa.model.elf_rewrite import _sections
    data = bytearray(FMA.read_bytes())
    info = next(s for s in _sections(bytes(data)) if s.name == ".nv.info")
    # 把最后一条属性改名成一个没人认识的属性码，payload 换成「一条会挪走的指令
    # 地址」。只改属性码和值、不动结构，nvdisasm 仍读得出这个 cubin。
    pos, last = info.offset, None
    while pos + 4 <= info.offset + info.size:
        fmt, _attr, plen = struct.unpack_from("<BBH", data, pos)
        if fmt == 4:
            last = (pos, plen)
            pos += 4 + plen
        else:
            pos += 4
    assert last and last[1] >= 8
    struct.pack_into("<BBH", data, last[0], 4, 0x5A, last[1])
    struct.pack_into("<I", data, last[0] + 8, 0x40)
    base = tmp_path / FMA.name
    base.write_bytes(bytes(data))
    lines = _lines(base)
    lines.insert(_insn_idx(lines)[1], NOP)
    with pytest.raises(SourceAsmError, match="认不出的属性"):
        save_source(base, "\n".join(lines) + "\n")
    assert base.read_bytes() == bytes(data)


# --- ⑥ 结构检查 / 回环 / 加载 -----------------------------------------------

def test_accept_6_external_checks_run_and_report_skips(tmp_path):
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    lines = _lines(base)
    lines.insert(_insn_idx(lines)[3], NOP)
    rep = save_source(base, "\n".join(lines) + "\n", smoke=True)
    names = {c.name: c for c in rep.checks}
    assert set(names) >= {"structure", "disasm", "control", "readelf",
                          "cuobjdump", "load"}
    for c in rep.checks:
        assert c.ok is not False, c.line
    # 「跳过」与「通过」是两个状态，不许混成一个
    assert all(c.ok is not None or c.detail for c in rep.checks)
    assert "硬件语义未验证" in rep.summary()


def test_accept_6_no_gpu_smoke_is_a_skip_not_a_failure(monkeypatch):
    """没 GPU 时 `load_check` 必须回 `ok=None`（没测），不是 `ok=False`（没过）。

    回归：原来写的是 `{"ok": None, **d}`，而 `d` 里带着 loadcheck 打出来的
    `"ok": false`，`**d` 在后面会把 None 覆盖回 False —— 「跳过」变「失败」，
    一路把没有 GPU 的机器上的保存事务拦掉。
    """
    import nvisa.oracle.execute as ex

    payload = {"ok": False, "stage": "init", "err": "no CUDA-capable device"}

    class Proc:
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(ex, "build_loadcheck", lambda: Path("/nonexistent/loadcheck"))
    monkeypatch.setattr(ex.subprocess, "run", lambda *a, **k: Proc())
    r = ex.load_check(Path("whatever.cubin"))
    assert r["ok"] is None, r
    assert r["stage"] == "init"           # 阶段和原因照样带出来
    # 真正的加载失败（stage=load）仍然是失败，别把这条也放过去
    payload["stage"] = "load"
    Proc.stdout = json.dumps(payload)
    assert ex.load_check(Path("whatever.cubin"))["ok"] is False


def test_accept_6_no_gpu_still_saves(tmp_path, monkeypatch):
    """接着上一条：没 GPU + `--smoke` 时保存照常落盘，报告里 load 记「跳过」。"""
    import nvisa.oracle.execute as ex

    monkeypatch.setattr(ex, "load_check", lambda *a, **k: {
        "ok": None, "stage": "init", "err": "no CUDA-capable device"})
    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    lines = _lines(base)
    lines.insert(_insn_idx(lines)[3], NOP)
    rep = save_source(base, "\n".join(lines) + "\n", smoke=True)
    load = {c.name: c for c in rep.checks}["load"]
    assert load.ok is None and "跑不了" in load.detail
    assert rep.ok and rep.written == str(base)


def test_accept_6_a_broken_product_is_caught_before_it_lands(tmp_path, monkeypatch):
    """验证不过就不落盘 —— 把打包结果故意弄坏，保存必须失败且基底不动。"""
    import nvisa.model.sass_save as save_mod

    base = tmp_path / FMA.name
    base.write_bytes(FMA.read_bytes())
    src = emit_source(base.read_bytes()).text

    real_assemble = save_mod.assemble_into

    def broken(base_data, text, **kw):
        data, asm = real_assemble(base_data, text, **kw)
        bad = bytearray(data)
        sec = next(s for s in Cubin(data).sections if s.name == asm.section)
        bad[sec.offset:sec.offset + 16] = b"\xff" * 16      # 一条读不出来的编码
        return bytes(bad), asm

    monkeypatch.setattr(save_mod, "assemble_into", broken)
    with pytest.raises(SourceAsmError, match="验证没过"):
        save_source(base, src)
    assert base.read_bytes() == FMA.read_bytes()


# --- ⑦ 隔离环境 + 静态门禁 ---------------------------------------------------

#: 产品代码：不许 import CuAsm，也不许 subprocess 调 cuasm.py（源码模式的解耦要求）。
#: 判据看**代码**不看散文 —— Python 走 `ast` 只查真正的 import，JS 查 require/
#: 命令行拼接。注释里写「不得 import CuAsm」当然不算违规。
PY_PRODUCT = ([p for p in (ROOT / "nvisa").rglob("*.py")]
              + [ROOT / "scripts" / "cubin_sass.py"])
JS_PRODUCT = ([p for p in (ROOT).glob("*.js")]
              + [p for p in (ROOT / "media").glob("*.js")])
_JS_BANNED = re.compile(r"require\(['\"].*CuAsm|cuasm\.py|CUASM_PATH")


def _code_only(path: Path) -> str:
    """去掉注释与字符串字面量之后的源码 —— 判据看**代码**，不看散文。

    `sass_parser.py` 的模块 docstring 里明写着「不得 import CuAsm」，那是在说
    边界，不是违规；用 `tokenize` 把注释和字符串摘掉，剩下的才是真依赖。
    """
    import tokenize

    out = []
    with path.open("rb") as f:
        for tok in tokenize.tokenize(f.readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            out.append(tok.string)
    return " ".join(out)


def test_accept_7_no_cuasm_in_product_code():
    import ast

    hits = []
    for p in PY_PRODUCT:
        for node in ast.walk(ast.parse(p.read_text())):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom)
                     else [])
            if any(n.split(".")[0] in ("CuAsm", "cuasm") for n in names):
                hits.append(f"{p.relative_to(ROOT)}:{node.lineno} import {names}")
        code = _code_only(p)
        if "cuasm.py" in code or "CUASM_PATH" in code:
            hits.append(f"{p.relative_to(ROOT)}: 代码里出现了 cuasm.py/CUASM_PATH")
    for p in JS_PRODUCT:
        if _JS_BANNED.search(p.read_text()):
            hits.append(str(p.relative_to(ROOT)))
    assert not hits, "产品代码里出现了 CuAsm 依赖：" + "、".join(hits)


def test_accept_7_the_static_gate_is_not_vacuous(tmp_path):
    """门禁本身得能红 —— 造一个真违规的文件，`_code_only()` 必须看得见它。"""
    bad = tmp_path / "bad.py"
    bad.write_text('"""注释里提 CuAsm 与 cuasm.py 不算违规。"""\n'
                   "import CuAsm\nCUASM_PATH = 1\n")
    code = _code_only(bad)
    assert "CUASM_PATH" in code and "CuAsm" in code
    good = tmp_path / "good.py"
    good.write_text('"""不得 import CuAsm、不得 subprocess 调 cuasm.py。"""\n'
                    "x = 1\n")
    assert "CuAsm" not in _code_only(good)


def test_accept_7_works_without_cuasm(tmp_path):
    """在「`CUASM_PATH` 指向不存在的目录 + `import CuAsm` 直接报错」的子进程里，
    导出源码、整段汇编、变长打包全过。"""
    script = textwrap.dedent(f"""
        import sys, builtins
        sys.path[:0] = [{str(ROOT)!r}, {str(ROOT / "scripts")!r}]
        real_import = builtins.__import__
        def guard(name, *a, **kw):
            if name.split(".")[0] in ("CuAsm", "sympy"):
                raise ImportError("blocked by 保存事务 isolation test: " + name)
            return real_import(name, *a, **kw)
        builtins.__import__ = guard
        from pathlib import Path
        from nvisa.model.sass_source import emit_source
        from nvisa.model.sass_save import dry_run
        data = Path({str(FMA)!r}).read_bytes()
        src = emit_source(data).text
        out, rep = dry_run(data, src)
        assert rep.ok and rep.unchanged, rep.summary()
        lines = src.splitlines()
        i = [k for k, l in enumerate(lines) if l.startswith("[B")][3]
        lines.insert(i, {NOP!r})
        out, rep = dry_run(data, "\\n".join(lines) + "\\n")
        assert rep.ok and rep.new_size == rep.old_size + 16, rep.summary()
        print(json.dumps({{"ok": True, "summary": rep.summary()}}))
    """).replace("json.dumps", "__import__('json').dumps")
    env = {**os.environ, "CUASM_PATH": str(tmp_path / "nope"),
           "PYTHONPATH": ""}
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True,
                          text=True, env=env, cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert json.loads(proc.stdout.strip().splitlines()[-1])["ok"]
