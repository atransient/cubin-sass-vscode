"""Execution oracle: run a patched cubin on the real GPU.

Hardware behaviour is the final specification.  Unlike
nvdisasm, which only tells you how NVIDIA's decoder *labels* an encoding, this
tells you what the silicon actually computes -- and it keeps working for
instructions nvdisasm has not learned to print yet.

cuda-gdb is deliberately not used: it exposes no way to write device code
memory, and device-side debugging is not reliably available.  Patching
the cubin and loading it with the driver API sidesteps both problems; the
driver does not validate .text contents.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from nvisa.oracle.base import Verdict

ROOT = Path(__file__).resolve().parents[2]
RUNNER_SRC = Path(__file__).with_name("runner.c")
BUILD_CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "cubin-sass-vscode" / "bin"
RUNNER_BIN = BUILD_CACHE / "runner"
#: 只加载不发射的 smoke 用例（`--smoke`）。与 runner 分开是刻意的：手改过的
#: `.text` 在保存校验里**不该被执行**。
LOADCHECK_SRC = Path(__file__).with_name("loadcheck.c")
LOADCHECK_BIN = BUILD_CACHE / "loadcheck"
_nvcc = shutil.which("nvcc")
CUDA_HOME = Path(os.environ.get("CUDA_HOME") or os.environ.get("CUDA_PATH")
                 or (str(Path(_nvcc).resolve().parents[1]) if _nvcc else "/usr/local/cuda"))
STUBS = CUDA_HOME / "lib64" / "stubs"


class ExecutorError(RuntimeError):
    pass


def build_loadcheck(force: bool = False) -> Path:
    """编译 `loadcheck.c`（只 `cuModuleLoad` + 查符号，不发射）。"""
    return _build(LOADCHECK_SRC, LOADCHECK_BIN, force)


def build_runner(force: bool = False) -> Path:                    # noqa: F811
    return _build(RUNNER_SRC, RUNNER_BIN, force)


def _build(src: Path, binary: Path, force: bool) -> Path:
    if binary.exists() and not force and binary.stat().st_mtime >= src.stat().st_mtime:
        return binary
    binary.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gcc", str(src), "-o", str(binary),
        f"-I{CUDA_HOME / 'include'}", f"-L{STUBS}", "-lcuda",
        f"-Wl,-rpath,{CUDA_HOME / 'lib64'}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ExecutorError(f"cannot build {src.name}:\n{proc.stderr}")
    return binary


def load_check(cubin: Path, entries: list[str] | None = None,
               device: int = 0, timeout: float = 30.0) -> dict:
    """把 cubin 交给驱动 `cuModuleLoad` 一次 —— **不发射任何 kernel**。

    返回 `{"ok": bool, "stage": str, "err": str}`。GPU 不可用（没卡、没驱动、
    编不出来）时返回 `{"ok": None, ...}`：这是「没测」，不是「测过通过」。
    """
    import os

    try:
        binary = build_loadcheck()
    except (ExecutorError, OSError) as e:
        return {"ok": None, "stage": "build", "err": str(e)}
    cmd = [str(binary), str(cubin), *(entries or [])]
    env = {**os.environ, "CUDA_VISIBLE_DEVICES": str(device)}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=env)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"ok": None, "stage": "run", "err": str(e)}
    out = proc.stdout.strip().splitlines()
    if not out:
        return {"ok": None, "stage": "run", "err": proc.stderr.strip() or "no output"}
    try:
        d = json.loads(out[-1])
    except json.JSONDecodeError:
        return {"ok": None, "stage": "run", "err": out[-1]}
    if not d.get("ok") and d.get("stage") in ("init", "device", "context"):
        # `**d` 必须在前：d 里带着 "ok": False，放在后面会把这里的 None 覆盖回去，
        # 「没测」就变成「测了没过」，一路把没 GPU 的机器上的保存事务拦掉。
        return {**d, "ok": None}          # 没有可用的 GPU，不算失败
    return d


@dataclass
class Run:
    ok: bool
    stage: str        # init/load/entry/launch/sync/done -- how far it got
    err: str
    out: list[float]
    repeats: list[tuple[str, float | None]] | None = None   # (stage, result) per run

    @property
    def result(self) -> float | None:
        return self.out[0] if self.out else None

    @property
    def stable(self) -> bool | None:
        """False when repeated identical launches disagreed.

        Two distinct kinds of disagreement, both of which disqualify a sample
        as semantic evidence:

        * same stage, different value -- clearing FFMA's wait mask lets it read
          operands before the loads land, returning register-file residue that
          differs every run.
        * different stage -- whether a clobbered address register faults at all
          depends on where the allocation happened to land, so the same encoding
          can be clean in one sweep and ILLEGAL_ADDRESS in the next.

        Comparing (stage, result) rather than result alone catches both; the
        earlier version only repeated successful runs and so was blind to the
        second kind entirely.
        """
        if not self.repeats:
            return None
        return len(set(self.repeats)) == 1


class Executor:
    """Runs one cubin per query in a fresh process, pinned to one GPU.

    Inputs default to a=2, b=3, c=1 so an FFMA-shaped kernel yields 7.0 --
    distinct enough that a swapped operand register is visible by eye.

    Containment:
      * `device` pins every launch to one GPU via CUDA_VISIBLE_DEVICES, so the
        other cards on the box are never exposed to a patched kernel.
      * one process per query, so a trap's sticky context error dies with it.
      * `timeout` bounds runaway kernels.  H20 is a compute-only card with no
        display watchdog, so nothing kills a spinning kernel except us; killing
        the host process tears down the context and the driver reclaims the GPU
        (measured: back to 0% util, 0 MiB, within 5s).
    """

    name = "execute"

    #: Default fuzz GPU. Kept off card 0 so an accidental full-box run does not
    #: land on whatever people usually reach for first.
    DEFAULT_DEVICE = 7

    def __init__(self, entry: str = "f", inputs: tuple[float, float, float] = (2, 3, 1),
                 repeat: int = 1, device: int | None = None, timeout: float = 10.0):
        self.entry = entry
        self.inputs = inputs
        self.repeat = repeat
        self.device = self.DEFAULT_DEVICE if device is None else device
        self.timeout = timeout
        self.binary = build_runner()

    @property
    def env(self) -> dict:
        import os

        return {**os.environ, "CUDA_VISIBLE_DEVICES": str(self.device)}

    def run_cubin(self, cubin: Path, timeout: float | None = None) -> Run:
        timeout = self.timeout if timeout is None else timeout
        run = self._launch(cubin, timeout)
        if self.repeat > 1:
            # Repeat failures too: faulting is itself sometimes nondeterministic.
            run.repeats = [(run.stage, run.result)] + [
                (r.stage, r.result)
                for r in (self._launch(cubin, timeout) for _ in range(self.repeat - 1))
            ]
        return run

    def _launch(self, cubin: Path, timeout: float) -> Run:
        cmd = [str(self.binary), str(cubin), self.entry, *(str(v) for v in self.inputs)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, env=self.env)
        except subprocess.TimeoutExpired:
            # subprocess.run has already killed it; the driver reclaims the GPU
            # as the context tears down.
            return Run(False, "timeout", f"runner exceeded {timeout}s", [])
        line = proc.stdout.strip().splitlines()
        if not line:
            return Run(False, "runner", proc.stderr.strip() or "no output", [])
        try:
            d = json.loads(line[-1])
        except json.JSONDecodeError:
            return Run(False, "runner", line[-1], [])
        return Run(d["ok"], d["stage"], d["err"], d["out"])

    def ask_cubin(self, cubin: Path) -> Verdict:
        r = self.run_cubin(cubin)
        if not r.ok:
            return Verdict(False, f"{r.stage}: {r.err}")
        return Verdict(True, f"c[0]={r.result:g}", value=r.result)
