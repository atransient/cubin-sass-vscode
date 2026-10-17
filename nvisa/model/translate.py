"""SASS <-> binary translation, the two directions a person actually types.

    to_sass(word)   128-bit  -> nvdisasm's mnemonic text        (general)
    from_sass(text) SASS text -> 128-bit encoding                (calibrated forms)

The two directions are not symmetric, because only one has an oracle:

* **Disassembly is free and general.** `nvdisasm -b SM90` decodes a bare 16-byte
  instruction with no cubin, so any decodable word round-trips to real text.
* **Assembly has no oracle** (nvdisasm cannot assemble). We fall back to the
  template-patch assembler (`model/asm.py`): take a real instruction of the same
  mnemonic and overwrite only the fields this project has calibrated. That covers
  register-form operands + predicate + control; immediates / const banks /
  uncalibrated modifiers still need a matching template and otherwise error out.

Keeping this out of `model/codec.py` lets the codec stay pure bit-twiddling with
no toolchain dependency; only this module shells out to nvcc / nvdisasm.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

from nvisa.model import asm, codec
from nvisa.oracle.cubin import Cubin, enc_to_bytes, int_to_enc

#: seeds compiled to source assembly templates from (mnemonic -> real encoding).
_SEEDS = ("execfma", "fma", "intops", "regscan")


class TranslateError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# binary -> SASS
# --------------------------------------------------------------------------- #


def to_sass(word: str | int, arch: str = "SM90") -> str:
    """Disassemble one 128-bit word to nvdisasm's instruction text.

    `word` takes the same spellings as `codec.parse_word` (32-hex enc, 0x..., or
    a binary string). Raises TranslateError if nvdisasm refuses to decode it.

    Cached per (word, arch): starting nvdisasm costs ~0.3 s and callers ask the
    same words over and over (roundtrip checks, corpus sweeps).  The function is
    pure -- same bytes in, same text out -- so the cache changes no verdict.
    """
    w = word if isinstance(word, int) else codec.parse_word(word)
    text, err = _to_sass_cached(w, arch)
    if err:                        # refusals are cached too: the sweep over a
        raise TranslateError(err)  # corpus hits the same bad words repeatedly
    return text


@lru_cache(maxsize=1 << 16)
def _to_sass_cached(w: int, arch: str) -> tuple[str, str]:
    """(text, error).  Also backed by the on-disk cache in `oracle.discache`,
    so a second run over the same corpus does not re-launch nvdisasm at all."""
    from nvisa.oracle import discache
    raw = enc_to_bytes(int_to_enc(w))
    hit = discache.get(arch, raw)
    if hit is not None:
        return (hit, "") if hit else ("", f"nvdisasm refused 0x{w:032x}")
    try:
        text = _to_sass_uncached(w, arch)
    except TranslateError as e:
        # Only a real refusal is cacheable; "nvdisasm is not installed" is not.
        if "refused" in str(e) or "no instruction" in str(e):
            discache.put(arch, raw, "")
        return "", str(e)
    discache.put(arch, raw, text)
    return text, ""


def _to_sass_uncached(w: int, arch: str) -> str:
    raw = enc_to_bytes(int_to_enc(w))
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(raw)
        binpath = Path(fh.name)
    try:
        proc = subprocess.run(["nvdisasm", "-b", arch, str(binpath)],
                              capture_output=True, text=True)
    finally:
        binpath.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise TranslateError(f"nvdisasm refused 0x{w:032x}: "
                             f"{proc.stderr.strip() or 'no output'}")
    for line in proc.stdout.splitlines():
        if "*/" in line:                              # /*0000*/  FFMA R9, ... ;
            text = re.sub(r"\s+", " ", line.split("*/", 1)[1]).strip().rstrip(";").strip()
            if text:
                return text
    raise TranslateError(f"nvdisasm produced no instruction for 0x{w:032x}")


# --------------------------------------------------------------------------- #
# SASS -> binary
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=None)
def _templates(arch: str) -> tuple[tuple[str, str], ...]:
    """(cubin_path, disasm_text) for the compiled seeds, cached per arch."""
    from nvisa.collect.harvest import ROOT, compile_seed  # lazy: needs nvcc
    out = []
    for name in _SEEDS:
        src = ROOT / "corpus" / "seeds" / f"{name}.cu"
        bundled = ROOT / "corpus" / "cubins" / f"{name}.{arch}.cubin"
        if bundled.is_file():
            out.append(bundled)
        elif src.exists():
            try:
                out.append(compile_seed(src, arch))
            except Exception:                          # noqa: BLE001 -- seed may not build
                continue
    return tuple((str(p), p.name) for p in out)


def _find_template(mnemonic: str, arch: str) -> str:
    """A real encoding of `mnemonic` to patch, sourced from the seed cubins."""
    base = mnemonic.split(".")[0]
    for path, _ in _templates(arch):
        cub = Cubin.load(Path(path))
        try:
            _addr, enc = asm.find_template(cub, Path(path), base)
            return enc
        except asm.AsmError:
            continue
    raise TranslateError(
        f"no template for {mnemonic!r} in the seed cubins ({', '.join(_SEEDS)}).\n"
        f"  Assembly reuses a real instruction's opcode/modifier bits; add a seed "
        f"that emits {base}, or pass one via template=.")


def from_sass(text: str, arch: str = "sm_90", template: str | None = None,
              **ctrl: int) -> str:
    """Assemble SASS text to a 128-bit `enc` via template patch.

    Only calibrated fields are set (registers, predicate, control); opcode and
    modifier bits come from a template instruction of the same mnemonic -- found
    in the seed cubins, or supplied via `template` (a 32-hex enc). `ctrl` forwards
    control-section overrides to `asm.assemble` (stall=, yield_=, wait=, ...).
    """
    p = asm.parse(text)
    tmpl = template or _find_template(p.mnemonic, arch)
    return asm.assemble(tmpl, text, **ctrl)


def roundtrip(text: str, arch: str = "sm_90", **kw) -> tuple[str, str]:
    """Assemble then disassemble; returns (enc, nvdisasm's text) for comparison."""
    enc = from_sass(text, arch=arch, **kw)
    return enc, to_sass(enc)
