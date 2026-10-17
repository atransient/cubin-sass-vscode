"""Oracle interfaces.

Two independent oracles answer two different questions about one encoding:

    Nvdisasm  -- "what instruction is this?"   (syntax / field layout)
    Executor  -- "what does it compute?"       (semantics, ground truth)

Both may also answer "this encoding is invalid", and they can disagree:
nvdisasm rejecting an encoding the hardware happily runs means the oracle
lags the silicon, which is itself a finding worth recording.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Verdict:
    """One oracle's answer about one encoding."""

    ok: bool
    detail: str = ""      # decoded text, or the error message
    value: float | None = None   # observed result, execution oracle only

    def __str__(self) -> str:
        return self.detail if self.ok else f"<error: {self.detail}>"


class Oracle(Protocol):
    name: str

    def ask(self, enc: str) -> Verdict:
        """Answer for a single 128-bit encoding (32 hex chars, low half first)."""
        ...
