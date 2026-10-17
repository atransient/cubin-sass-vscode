"""nvdisasm 单条解码结果的跨进程缓存。

**起一次 nvdisasm 约 0.25~0.35 秒**，而这个项目的每条路都在反复问同一批
16 字节：语料是固定的，回环校验一天要跑几十遍，测试跑一次就要几十次单条解码。
结果只取决于「这 16 个字节 + 目标架构 + nvdisasm 自己」，所以缓存不改变任何
判据 —— 它只是不再为同一个问题重开一次进程。

缓存键里带 **nvdisasm 的版本串**：换一个 CUDA 工具链就是另一套答案，不该拿
旧答案当数。存在 `$XDG_CACHE_HOME/nvisa-nvdisasm/<版本>-<arch>.json`，
和 `cubin_sass._corpus_pool()` 的模板缓存同一个地方、同一套规矩。

**只缓存 nvdisasm 真的回答过的东西**：它没装、超时、跑不起来的时候不写缓存，
不然「这条编码解不出来」和「这台机器上没有 nvdisasm」会混成一件事。
"""
from __future__ import annotations

import atexit
import json
import os
import subprocess
from pathlib import Path

_MAX = 1 << 16                      # 一份缓存最多这么多条，超了整份丢掉重来
                                    # （语料 1328 条去重指令，够用得多）
_mem: dict[tuple[str, bytes], str] = {}
_loaded: set[str] = set()
_dirty: set[str] = set()
_version: str | None = None
_text_mem: dict[bytes, dict[int, str]] = {}
_section_text_mem: dict[bytes, dict[str, dict[int, str]]] = {}


def _root() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) \
        / "nvisa-nvdisasm"


def nvdisasm_version() -> str:
    """`nvdisasm --version` 的指纹。问不出来就返回空串 —— 那时不落盘。"""
    global _version
    if _version is None:
        try:
            out = subprocess.run(["nvdisasm", "--version"], capture_output=True,
                                 text=True, timeout=20).stdout
            _version = "".join(c for c in out.split("release")[-1].strip()
                               if c.isalnum() or c in ".-_")[:32] or "unknown"
        except (OSError, subprocess.SubprocessError):
            _version = ""
    return _version


def _file(arch: str) -> Path | None:
    v = nvdisasm_version()
    return _root() / f"{v}-{arch}.json" if v else None


def _load(arch: str) -> None:
    if arch in _loaded:
        return
    _loaded.add(arch)
    f = _file(arch)
    if not f or not f.is_file():
        return
    try:
        for k, v in json.loads(f.read_text()).items():
            _mem[(arch, bytes.fromhex(k))] = v
    except Exception:                                        # noqa: BLE001
        pass                                                 # 缓存坏了就当没有


def get(arch: str, raw: bytes) -> str | None:
    """缓存里的解码文本；`None` = 没缓存过（不是「解不出来」，那是 `""`）。"""
    _load(arch)
    return _mem.get((arch, bytes(raw)))


def put(arch: str, raw: bytes, text: str) -> str:
    _load(arch)
    if len(_mem) >= _MAX:
        _mem.clear()
        _loaded.clear()
        _loaded.add(arch)
    _mem[(arch, bytes(raw))] = text
    _dirty.add(arch)
    return text


# --- 整段反汇编（`nvdisasm -c` 一次一个文件）--------------------------------
#
# 单条那套是「一堆小答案」，这套是「一个大答案」：一份 cubin 的全段文本。
# 按**文件内容**的 sha1 存，一个文件一份 —— 内容变了就是另一个键，不存在过期。

def _map_file(digest: str, kind: str = "sass") -> Path | None:
    v = nvdisasm_version()
    return _root() / v / f"{kind}-{digest}.json" if v else None


def get_blob(kind: str, digest: str):
    """一份 JSON 缓存；`None` = 没缓存过。"""
    f = _map_file(digest, kind)
    if not f or not f.is_file():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:                                        # noqa: BLE001
        return None


def put_blob(kind: str, digest: str, obj):
    f = _map_file(digest, kind)
    if f:
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            _prune_maps(f.parent)
            tmp = f.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(obj))
            tmp.replace(f)
        except OSError:
            pass
    return obj


def get_map(digest: str) -> dict[int, str] | None:
    rows = get_blob("sass", digest)
    return None if rows is None else {int(k): v for k, v in rows.items()}


#: 整段缓存一份文件一个 cubin 内容。测试和插入/删除会造出一堆一次性的缓冲区，
#: 不封顶的话这个目录会慢慢长起来 —— 超了就把最旧的一批删掉。
_MAP_FILES_MAX = 512


def _prune_maps(d: Path) -> None:
    try:
        files = sorted(d.glob("*-*.json"), key=lambda f: f.stat().st_mtime)
    except OSError:
        return
    for f in files[:max(0, len(files) - _MAP_FILES_MAX + 1)]:
        try:
            f.unlink()
        except OSError:
            pass


def put_map(digest: str, rows: dict[int, str]) -> dict[int, str]:
    put_blob("sass", digest, {str(k): v for k, v in rows.items()})
    return rows


def get_section_map(digest: str) -> dict[str, dict[int, str]] | None:
    rows = get_blob("sass-sections", digest)
    if rows is None:
        return None
    return {name: {int(k): v for k, v in section.items()}
            for name, section in rows.items()}


def put_section_map(digest: str, rows: dict[str, dict[int, str]]) \
        -> dict[str, dict[int, str]]:
    put_blob("sass-sections", digest, {
        name: {str(k): v for k, v in section.items()}
        for name, section in rows.items()
    })
    return rows


def _sections_from_output(output: str) -> dict[str, dict[int, str]]:
    """Parse ``nvdisasm -c`` without merging equal addresses across sections.

    Every executable section starts its instruction addresses at zero.  A flat
    ``{address: text}`` map therefore silently lets the last kernel overwrite
    earlier kernels in a multi-kernel cubin.
    """
    import re
    section_pat = re.compile(r"^\s*\.section\s+([^,\s]+)")
    insn_pat = re.compile(r"/\*([0-9a-f]{4,})\*/\s*(.*?);")
    rows: dict[str, dict[int, str]] = {}
    current: str | None = None
    for line in output.splitlines():
        section = section_pat.match(line)
        if section:
            current = section.group(1)
            rows.setdefault(current, {})
            continue
        insn = insn_pat.search(line)
        if current is not None and insn:
            rows[current][int(insn.group(1), 16)] = " ".join(insn.group(2).split())
    return {name: section for name, section in rows.items() if section}


def text_by_sections(path: "Path") -> dict[str, dict[int, str]]:
    """A cubin's SASS indexed by section name and then section-relative address."""
    import hashlib
    try:
        content = Path(path).read_bytes()
    except OSError:
        return {}
    if content in _section_text_mem:
        return _section_text_mem[content]
    digest = hashlib.sha1(content).hexdigest()
    hit = get_section_map(digest)
    if hit is None:
        try:
            proc = subprocess.run(["nvdisasm", "-c", str(path)],
                                  capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return {}
        if proc.returncode != 0:
            return {}
        hit = _sections_from_output(proc.stdout)
        if hit:
            put_section_map(digest, hit)
    if len(_section_text_mem) >= 512:
        _section_text_mem.clear()
    _section_text_mem[content] = hit
    return hit


def text_by_addr(path: "Path") -> dict[int, str]:
    """一份 cubin 的 `nvdisasm -c` 文本，按指令地址索引，**按内容缓存**。

    `asm.py` 的模板搜索/回环校验和 `cubin_sass` 的整份渲染问的是同一个问题，
    以前各起各的 nvdisasm（一次 ~0.3 秒，一遍测试要起几十次）。缓存按文件
    内容的 sha1 走，不按路径 —— 临时文件的路径会被反复复用，装的却是不同内容。
    """
    import hashlib
    import re
    try:
        content = Path(path).read_bytes()
    except OSError:
        return {}
    if content in _text_mem:
        return _text_mem[content]
    digest = hashlib.sha1(content).hexdigest()
    hit = get_map(digest)
    if hit is None:
        try:
            proc = subprocess.run(["nvdisasm", "-c", str(path)],
                                  capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return {}
        if proc.returncode != 0:
            return {}
        pat = re.compile(r"/\*([0-9a-f]{4,})\*/\s*(.*?);")
        hit = {int(m.group(1), 16): " ".join(m.group(2).split())
               for m in pat.finditer(proc.stdout)}
        if hit:
            put_map(digest, hit)
    if len(_text_mem) >= 512:
        _text_mem.clear()
    _text_mem[content] = hit
    return hit


def flush() -> None:
    """进程退出时落盘。中途崩了顶多损失这一轮的缓存，不影响正确性。"""
    for arch in list(_dirty):
        f = _file(arch)
        if not f:
            continue
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            rows = {raw.hex(): text for (a, raw), text in _mem.items() if a == arch}
            tmp = f.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(rows))
            tmp.replace(f)                                   # 原子替换
        except OSError:
            pass
    _dirty.clear()


atexit.register(flush)
