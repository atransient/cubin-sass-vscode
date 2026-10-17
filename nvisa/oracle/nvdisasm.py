"""nvdisasm oracle: cubin -> (address, encoding, text) samples."""
from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

# "/*0090*/   IMAD.WIDE R2, R9, 0x4, R2 ;   /* 0x0000000409027825 */"
_INST = re.compile(
    r"^\s*/\*([0-9a-f]{4,})\*/\s+(.*?);\s*/\* 0x([0-9a-f]{16}) \*/"
)
# continuation line holding the upper 64 bits
_CONT = re.compile(r"/\* 0x([0-9a-f]{16}) \*/")


@dataclass(frozen=True)
class Inst:
    addr: int
    enc: str          # 32 hex chars = 128 bit, low half first
    text: str         # "IMAD.WIDE R2, R9, 0x4, R2"

    @property
    def _head(self) -> str:
        """The opcode token, skipping a leading predicate guard.

        "@!P0 BRA 0x10" heads with "@!P0", not the opcode -- reading the first
        token blindly reported the mnemonic of every predicated instruction as
        its guard register.
        """
        toks = self.text.split()
        if toks and toks[0].startswith("@"):
            toks = toks[1:]
        return toks[0] if toks else ""

    @property
    def mnemonic(self) -> str:
        return self._head.split(".")[0]

    @property
    def modifiers(self) -> list[str]:
        return self._head.split(".")[1:]


class NvdisasmError(RuntimeError):
    pass


class Nvdisasm:
    def __init__(self, binary: str = "nvdisasm") -> None:
        self.binary = binary

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.binary, *args], capture_output=True, text=True
        )

    def disassemble(self, cubin: Path) -> list[Inst]:
        """Disassemble a cubin, returning every decoded instruction."""
        proc = self._run(["-hex", "-c", str(cubin)])
        if proc.returncode != 0 and not proc.stdout.strip():
            raise NvdisasmError(proc.stderr.strip())
        return self.parse(proc.stdout)

    @staticmethod
    def parse(output: str) -> list[Inst]:
        lines = output.splitlines()
        out: list[Inst] = []
        for i, line in enumerate(lines):
            m = _INST.match(line)
            if not m:
                continue
            hi = _CONT.search(lines[i + 1]) if i + 1 < len(lines) else None
            if not hi:
                continue
            out.append(
                Inst(
                    addr=int(m.group(1), 16),
                    enc=m.group(3) + hi.group(1),
                    text=" ".join(m.group(2).split()),
                )
            )
        return out

    # ---- raw binary mode (nvdisasm --binary SMxy) -------------------------
    #
    # Feeds 16-byte encodings straight to nvdisasm, no cubin round-trip.
    # One illegal encoding aborts the whole batch (rc=1, no partial output),
    # but stderr names the address of *every* offender, not just the first.
    # Dropping them all at once costs 2 calls regardless of how many there are;
    # dropping one per call cost f+1, and the bisection in enumerate.py cost
    # O(f log N).  Measured on a 105-candidate bit-flip probe: 37-51 calls
    # before, 2 after.

    #: Mnemonics whose printed operand is an address derived from the PC.
    #: In a batch every candidate sits at a different offset in the blob, so
    #: their text moves with their position -- see `_rebase`.
    PC_RELATIVE = frozenset({
        "BRA", "BRX", "BRXU", "JMP", "JMX", "JMXU", "CALL", "RET",
        "BSSY", "SSY", "PBK", "PRET", "LEPC", "BPT", "WARPSYNC",
    })
    #: 这些指令的文本操作数是可由 PC 解析出的目标地址。BRX/BRXU 的第二
    #: 个操作数是 nvdisasm 直接打印的相对偏移，不能按批次地址做 rebasing。
    #: BPT 虽在 PC-relative 指令族中，但 `--binary` 已把它的立即数按裸编码
    #: 坐标打印；再减候选在 blob 中的地址会把实测位权重改坏。WARPSYNC 则相反，
    #: 批量输出仍带候选地址，必须归一化。
    # JMP/JMX/JMXU, like BRX/BRXU, print the encoded displacement directly.
    # They are not PC-derived absolute targets: at file offsets 0, 0x10, 0x20,
    # a zero JMP still prints ``0x0`` (whereas BRA prints 0x10/0x20/0x30).
    PC_TARGET = PC_RELATIVE - frozenset({
        "BRX", "BRXU", "JMP", "JMX", "JMXU", "BPT"
    })

    _HEX_NUM = re.compile(r"-?0x[0-9a-fA-F]+")

    @classmethod
    def _rebase(cls, inst: "Inst") -> "Inst":
        """Rewrite a PC-relative target as if the instruction sat at address 0.

        nvdisasm prints `PC + insn_len + offset` for these, so in a batch of
        unrelated encodings the printed value encodes the candidate's position
        in the blob.  A bit-flip probe then sees every flip "change the
        operand", including flips that only touched a modifier -- and misses a
        real immediate bit whose weight happens to cancel the shift.  That is
        exactly how BRA's branch target came out 81 bits wide with bit 22
        missing.
        """
        if inst.addr == 0 or inst.mnemonic not in cls.PC_TARGET:
            return inst
        if "ABS" in inst.modifiers:     # CALL.ABS / RET.ABS take a real address
            return inst
        # the target is the last hex literal; a trailing `?PM1` etc. may follow
        hits = list(cls._HEX_NUM.finditer(inst.text))
        if not hits:
            return inst
        m = hits[-1]
        rebased = int(m.group(0), 16) - inst.addr
        text = (inst.text[:m.start()]
                + ("-0x%x" % -rebased if rebased < 0 else "0x%x" % rebased)
                + inst.text[m.end():])
        return Inst(addr=inst.addr, enc=inst.enc, text=text)

    def disassemble_raw(
        self, encodings: list[int], arch: str, *, insn_len: int = 16,
        rebase: bool = True,
    ) -> list[Inst | None]:
        """Cached wrapper around `_disassemble_raw`; see it for the semantics.

        A batch is a pure function of (encodings, arch, insn_len, rebase), so
        the whole answer is cached on disk keyed by their digest.  Sweeps rerun
        the same corpus constantly and one nvdisasm launch costs ~0.3 s.
        """
        from nvisa.oracle import discache
        digest = hashlib.sha1(
            f"{arch}|{insn_len}|{int(rebase)}|"
            f"{','.join(format(e, 'x') for e in encodings)}".encode()).hexdigest()
        hit = discache.get_blob("batch", digest)
        if hit is not None:
            return [None if r is None else Inst(r[0], r[1], r[2]) for r in hit]
        out = self._disassemble_raw(encodings, arch, insn_len=insn_len,
                                    rebase=rebase)
        if any(x is not None for x in out):     # all-None = nvdisasm never ran
            discache.put_blob("batch", digest,
                              [None if x is None else [x.addr, x.enc, x.text]
                               for x in out])
        return out

    def _disassemble_raw(
        self, encodings: list[int], arch: str, *, insn_len: int = 16,
        rebase: bool = True,
    ) -> list[Inst | None]:
        """Disassemble raw 128-bit encodings; None where nvdisasm refused.

        `arch` is an nvdisasm --binary value, e.g. "SM86" / "SM90".
        Returns one entry per input, in order.

        With `rebase` (the default) PC-relative targets are normalised to what
        they would read at address 0, so a batch behaves like N independent
        single-instruction decodes.  The normalisation is checked against one
        real single decode per batch; if it disagrees the batch is redone one
        instruction at a time, rather than returning text that silently depends
        on batch position.  Pass `rebase=False` for nvdisasm's raw text.
        """
        out: list[Inst | None] = [None] * len(encodings)
        alive = list(range(len(encodings)))

        while alive:
            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
                for i in alive:
                    fh.write(encodings[i].to_bytes(insn_len, "little"))
                path = fh.name
            try:
                proc = self._run(["-hex", "--binary", arch, path])
            finally:
                Path(path).unlink(missing_ok=True)

            if proc.returncode == 0:
                # Map by the address nvdisasm prints, never by output order:
                # `parse` silently skips any line whose format it does not
                # recognise, and a zip would then shift every later result onto
                # the wrong input.  Measured: a 103-entry batch came back with
                # 101 parsed lines, corrupting everything after the gap.
                for inst in self.parse(proc.stdout):
                    idx = inst.addr // insn_len
                    if 0 <= idx < len(alive):
                        out[alive[idx]] = inst
                break

            bad = self._failing_indices(proc.stderr, insn_len)
            bad = {i for i in bad if i < len(alive)}
            if not bad:
                break               # can't localise: give up on this batch
            alive = [x for i, x in enumerate(alive) if i not in bad]

        if not rebase:
            return out
        moved = [i for i, x in enumerate(out)
                 if x is not None and x.addr != 0 and x.mnemonic in self.PC_TARGET]
        if not moved:
            return out
        out = [x if x is None else self._rebase(x) for x in out]
        probe = out[moved[0]]
        truth = self._one(encodings[moved[0]], arch, insn_len)
        if truth is None or truth.text != probe.text:
            return [self._one(e, arch, insn_len) for e in encodings]
        return out

    def _one(self, encoding: int, arch: str, insn_len: int) -> "Inst | None":
        """Decode a single encoding, so it really does sit at address 0.

        Cached on disk (`oracle.discache`): the batch rebase check asks for one
        of these per batch, and the fallback path asks for one per instruction.
        """
        from nvisa.oracle import discache
        raw = encoding.to_bytes(insn_len, "little")
        hit = discache.get_blob("one", f"{arch}-{raw.hex()}")
        if hit is not None:
            return Inst(hit[0], hit[1], hit[2]) if hit else None
        got = self._one_uncached(encoding, arch, insn_len)
        if got is not None or _nvdisasm_runs(self):
            discache.put_blob("one", f"{arch}-{raw.hex()}",
                              [got.addr, got.enc, got.text] if got else None)
        return got

    def _one_uncached(self, encoding: int, arch: str, insn_len: int) -> "Inst | None":
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(encoding.to_bytes(insn_len, "little"))
            path = fh.name
        try:
            proc = self._run(["-hex", "--binary", arch, path])
        finally:
            Path(path).unlink(missing_ok=True)
        if proc.returncode != 0:
            return None
        got = self.parse(proc.stdout)
        return got[0] if got else None

    _ADDR_ERR = re.compile(r"at address 0x([0-9a-f]+)", re.I)

    @classmethod
    def _failing_indices(cls, stderr: str, insn_len: int) -> set[int]:
        return {int(a, 16) // insn_len
                for a in cls._ADDR_ERR.findall(stderr)}

    @classmethod
    def _failing_index(cls, stderr: str, insn_len: int) -> int | None:
        """Kept for callers that only want the first offender."""
        bad = cls._failing_indices(stderr, insn_len)
        return min(bad) if bad else None

    def probe(self, cubin: Path) -> tuple[bool, str]:
        """Ask whether a (possibly mutated) cubin decodes cleanly."""
        proc = self._run(["-c", str(cubin)])
        err = proc.stderr.strip()
        return (proc.returncode == 0 and "error" not in err.lower(), err)


def _nvdisasm_runs(nv: "Nvdisasm") -> bool:
    """Did nvdisasm actually answer?  "refused this encoding" is a result worth
    caching; "not installed / timed out" is not, and both look like None."""
    try:
        return nv._run(["--version"]).returncode == 0
    except OSError:
        return False
