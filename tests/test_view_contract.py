"""文本渲染契约 + Webview 行为测试。

三件事：

1. `values_to_text()` 到底是什么渲染器 —— 这里把契约钉死：**oracle 渲染器**，
   编码之后交给 nvdisasm 读回，nvdisasm 不认就抛 `TranslateError`。它不是
   「按段表把语义值拼成文字」的语义渲染器，也就没有「拼得出但 nvdisasm 读不出」
   这种中间状态。
2. 前端纯逻辑的 node 用例（`media/view.js`）在跑全仓库测试时一起带起来。
3. 验收那条：**非法格子编辑绕不过 保存安全闸 的保存闸**。下拉里能选非法档是故意的
   （造非法编码探边界本来就是这个工具的用途），但选了之后普通保存必须被拦。
"""
from __future__ import annotations

import glob
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cubin_sass import build, check_save, disasm_one, identify, segtable  # noqa: E402
from nvisa.model.asm_spec import values_to_text                           # noqa: E402
from nvisa.model.encode import decode_spec                                # noqa: E402
from nvisa.model.translate import TranslateError, to_sass                 # noqa: E402
from nvisa.oracle.cubin import enc_from_bytes, enc_to_bytes, set_bits     # noqa: E402

CUBINS = sorted(glob.glob(str(ROOT / "corpus/cubins/*.cubin")))
pytestmark = pytest.mark.skipif(not (segtable() and CUBINS),
                                reason="需要 data/segtable-sm90.json 与 corpus/cubins/")


@pytest.fixture(scope="module")
def illegal_edit():
    """语料里第一处「下拉里选得到、但选完 nvdisasm 就读不出」的格子编辑。

    `(cubin 字节, 指令, 格子, 取值, 改完的编码)`。第一个 cubin 里未必有 ——
    段表标的非法档在具体某条指令上可能照样解得出（`LDS.???7`）—— 所以整个语料
    扫过去，找到一处就够。
    """
    for src in map(Path, CUBINS):
        data = src.read_bytes()
        for sec in build(src, None, data)["sections"]:
            for i in sec.get("insns", []):
                if not i.get("sass"):
                    continue
                for c in i.get("cells") or []:
                    if not (c.get("illegal") and c.get("editable") and c.get("bit_list")):
                        continue
                    for v in c["illegal"]:
                        bad = _set_cell(i["enc"], c["bit_list"], int(v))
                        if not disasm_one(enc_to_bytes(bad)):
                            return data, i, c, int(v), bad
    pytest.skip("语料里没找到「选了非法档就解不出」的格子")


@pytest.fixture(scope="module")
def insns():
    """语料第一个 cubin 里解得出的指令（带 cells）。"""
    src = Path(CUBINS[0])
    data = src.read_bytes()
    out = []
    for sec in build(src, None, data)["sections"]:
        out += [i for i in sec.get("insns", []) if i.get("sass")]
    if not out:
        pytest.skip("语料里没有解得出的指令")
    return src, data, out


# --- 1. `values_to_text()` 的契约 -------------------------------------------

def test_values_to_text_renders_through_nvdisasm(insns):
    """契约：它的输出**就是** nvdisasm 对同一份编码的输出，一字不差。

    这不是「顺便也对得上」—— `values_to_text()` 内部走的就是
    `translate.to_sass()`，那是 nvdisasm 的包装（带 `discache` 落盘缓存，
    缓存只省进程不改判据）。所以文本层从来不用自己拼字符串去猜 nvdisasm 会怎么
    打印取反、地址形式这些边角写法。
    """
    _src, _data, rows = insns
    checked = 0
    for i in rows[:40]:
        key = identify(i["enc"])
        if key is None:
            continue
        values = decode_spec(i["enc"], key)
        assert values_to_text(key, values) == to_sass(i["enc"])
        checked += 1
    assert checked > 5


def test_values_to_text_raises_when_nvdisasm_refuses(illegal_edit):
    """nvdisasm 读不出来时**抛 `TranslateError`**，不返回一个凑出来的字符串。

    语义渲染器在这里会照样拼出一行文本（它只看段表），oracle 渲染器不会 ——
    这就是两者在契约上的区别，也是编辑器敢拿它的输出当回显的理由。
    """
    _data, insn, _cell, _v, bad = illegal_edit
    key = identify(insn["enc"])
    assert key is not None
    with pytest.raises(TranslateError):
        values_to_text(key, decode_spec(bad, key))


def test_the_final_authority_for_an_edit_is_the_e2_roundtrip(insns):
    """契约的另一半：渲染只是**回显**，落盘与否由 `assemble_at()` 的 nvdisasm 回环定。

    `IMAD.MOV.U32 R2, RZ, RZ, R5, PT` 编得出来（`IMAD_R_R_R_R_P` 收下了这些
    语义值），但 nvdisasm 读回的是**不带 `, PT`** 的那条 —— 编码里没有一个位
    能把这个谓词表达出来。判据在回环上，所以整条被拒；换成读得回来的那一条就
    通过，且返回的 `sass` 是 nvdisasm 读回的文本，不是用户敲的那串。
    """
    from cubin_sass import _assemble_spec
    _src, _data, rows = insns
    cur = rows[0]["enc"]

    ok = _assemble_spec(cur, "IMAD.MOV.U32 R2, RZ, RZ, R5")
    assert ok and ok["ok"] and ok["sass"] == "IMAD.MOV.U32 R2, RZ, RZ, R5"

    bad = _assemble_spec(cur, "IMAD.MOV.U32 R2, RZ, RZ, R5, PT")
    assert bad and bad["ok"] is False
    assert any("回环不符" in e for e in bad["spec_errors"]), bad["spec_errors"]


# --- 2. 前端纯逻辑 ----------------------------------------------------------

@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 跑前端测试")
def test_node_view_suite():
    """`media/view.js`：INVALID 警示、thin/borrowed 提示、operand 输入、取消、
    非法编码提示、撤销提示、插入/删除 失败反馈。"""
    r = subprocess.run(["node", "--test",
                        str(ROOT / "test/view.test.js")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 跑前端测试")
def test_node_nvsassfs_suite():
    """`nvsassfs.js`：`.nvsass` 只活在内存里、基底绑定在 uri 上、重载后能重导。"""
    r = subprocess.run(["node", "--test",
                        str(ROOT / "test/nvsassfs.test.js")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 跑前端测试")
def test_js_and_python_agree_on_the_base_hash():
    """`.base` 是「源码对着哪一份基底」的唯一判据：后端拿它决定拒不拒绝写回，
    前端拿它决定要不要重导源码。两边的定义一旦错开，就又是「第一次能存、第二次
    报基底对不上」。所以在真 cubin 上逐字比一次。"""
    from nvisa.model.sass_source import base_hash

    data = (ROOT / "corpus" / "cubins" / "fma.sm_90.cubin").read_bytes()
    js = subprocess.run(
        ["node", "-e",
         "const {baseHash}=require(process.argv[1]);"
         "process.stdout.write(baseHash(require('fs').readFileSync(process.argv[2])))",
         str(ROOT / "basehash.js"),
         str(ROOT / "corpus" / "cubins" / "fma.sm_90.cubin")],
        capture_output=True, text=True, timeout=60)
    assert js.returncode == 0, js.stderr
    assert js.stdout.strip() == base_hash(data)


def test_webview_loads_the_pure_logic_module():
    """`view.js` 得真的被 webview 加载，而且排在 `bits.js` 之后、`main.js` 之前
    （它依赖前者的全局函数，后者依赖它的 `V`）。"""
    html = (ROOT / "extension.js").read_text()
    order = [html.index(f"'media', '{f}'") for f in ("bits.js", "view.js", "main.js")]
    assert order == sorted(order)


# --- 3. 验收：非法格子编辑绕不过 保存安全闸 -----------------------------------------

def _set_cell(enc: str, bit_list: list[int], value: int) -> str:
    """前端 `commitCell` 那一步的等价物：把值按低位在前散进这些位。"""
    for k, b in enumerate(bit_list):
        enc = set_bits(enc, b, b, (value >> k) & 1)
    return enc


def test_illegal_cell_edit_cannot_bypass_the_save_gate(illegal_edit):
    """下拉里选一个「非法档」（nvdisasm 读不出）之后，`check_save()` 必须拦住
    普通保存，并点名是哪一条 —— 前端那句提示只是提醒，闸在后端。"""
    data, insn, _cell, _v, bad = illegal_edit
    off = insn["file_off"]
    edited = bytearray(data)
    edited[off:off + 16] = enc_to_bytes(bad)
    res = check_save(bytes(edited), data)
    assert res["ok"] is False
    assert res["changed"] == 1
    assert [r["file_off"] for r in res["bad"]] == [off]
    assert res["bad"][0]["enc"] == enc_from_bytes(enc_to_bytes(bad))
    assert "实验性保存" in res["error"]
    # 闸只认「解不出来」，不是见改就拦：把同一条原样写回去要放行
    same = bytearray(data)
    same[off:off + 16] = enc_to_bytes(insn["enc"])
    assert check_save(bytes(same), data)["ok"]
