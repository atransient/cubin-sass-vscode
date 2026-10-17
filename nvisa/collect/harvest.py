"""Compile seed kernels and harvest real SASS encodings as samples."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from nvisa.model.keys import try_canonical_key
from nvisa.oracle.nvdisasm import Inst, Nvdisasm

ROOT = Path(__file__).resolve().parents[2]
SEEDS = ROOT / "corpus" / "seeds"
CUBINS = ROOT / "corpus" / "cubins"
SAMPLES = ROOT / "corpus" / "samples"


def compile_seed(src: Path, arch: str = "sm_90", *, force: bool = False) -> Path:
    """Compile a seed to `corpus/cubins/<stem>.<arch>.cubin`.

    Skips nvcc when the cubin is already there and newer than its source: one
    nvcc run costs ~0.22 s and callers (translate's template pool, the field
    scans) ask for the same four seeds over and over.  `force=True` recompiles
    regardless -- use it when the toolchain changed rather than the source.
    """
    CUBINS.mkdir(parents=True, exist_ok=True)
    out = CUBINS / f"{src.stem}.{arch}.cubin"
    if not force and out.is_file() and out.stat().st_mtime >= src.stat().st_mtime:
        return out
    cmd = ["nvcc", f"-arch={arch}", "-cubin", "-o", str(out), str(src)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nvcc failed for {src.name}:\n{proc.stderr}")
    return out


def operand_shape(text: str) -> list[str]:
    """Legacy operand classifier -- superseded by `nvisa.model.keys`.

    Kept only so migration reports can reproduce a pre-migration `legacy_key`;
    it mis-reads predicate prefixes as operands and cannot tell `c[0x0][0x28]`
    from `c[0x0][R2+0x28]`.  Do not use it for new records.
    """
    parts = text.split(None, 1)
    if len(parts) < 2:
        return []
    shape = []
    for op in parts[1].split(","):
        op = op.strip().strip(";").strip()
        if not op:
            continue
        if op.startswith("c[") or "desc[" in op:
            shape.append("C")
        elif op.startswith("UR"):
            shape.append("UR")
        elif op.startswith(("R", "RZ")):
            shape.append("R")
        elif op.startswith(("P", "PT", "!P")):
            shape.append("P")
        elif op.startswith(("0x", "-0x")) or op.replace(".", "").isdigit():
            shape.append("I")
        elif op.startswith("SR_"):
            shape.append("SR")
        else:
            shape.append("X")
    return shape


def legacy_key(inst: Inst) -> str:
    """The pre-canonical key (see `operand_shape`)."""
    mods = "_".join(inst.modifiers)
    shape = "_".join(operand_shape(inst.text))
    return "_".join(p for p in (inst.mnemonic, mods, shape) if p)


def make_key(inst: Inst) -> str | None:
    """canonical key (see `nvisa.model.keys`); None when unparseable."""
    key, _ = try_canonical_key(inst.text)
    return key


def to_record(inst: Inst, arch: str, origin: str) -> dict:
    key, err = try_canonical_key(inst.text)
    rec = {
        "arch": arch,
        "enc": inst.enc,
        "text": inst.text,
        "mnemonic": inst.mnemonic,
        "modifiers": inst.modifiers,
        "origin": origin,
        "ok": True,
    }
    if key is None:
        rec["key_error"] = err
    else:
        rec["key"] = key
    return rec


def harvest(arch: str = "sm_90") -> Path:
    seeds = sorted(SEEDS.glob("*.cu"))
    if not seeds:
        raise SystemExit(f"no seed kernels in {SEEDS}")

    oracle = Nvdisasm()
    SAMPLES.mkdir(parents=True, exist_ok=True)
    out_path = SAMPLES / f"seed-{arch}.jsonl"
    seen: set[str] = set()
    n = 0

    with out_path.open("w") as fh:
        for src in seeds:
            cubin = compile_seed(src, arch)
            for inst in oracle.disassemble(cubin):
                if inst.enc in seen:
                    continue
                seen.add(inst.enc)
                origin = f"harvest:{src.name}@0x{inst.addr:x}"
                fh.write(json.dumps(to_record(inst, arch, origin)) + "\n")
                n += 1
    print(f"{n} unique encodings -> {out_path.relative_to(ROOT)}")
    return out_path


if __name__ == "__main__":
    harvest()
