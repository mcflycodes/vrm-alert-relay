"""Linear-time detection of registered secrets in any per-character encoding.

Text containing ``%``, ``\\`` or ``+`` can be read as characters in more than
one way: ``%41`` is either ``A`` or the three characters ``%``, ``4``,
``1``. This module considers every reading at once. It builds a lattice
whose nodes are text positions and whose edges are a literal character or a
decoded escape (``%XX`` UTF-8 sequences, ``\\uXXXX`` including surrogate
pairs, ``\\xNN``, JSON and ``repr`` short escapes, and ``+`` as a space),
and runs bit-parallel Shift-And over it for all secrets together. The cost
is proportional to the text length, independent of secret length or how
many secrets are registered; a regex scan of a periodic secret over
near-prefix text is proportional to their product.

The edges cover every alternative of the per-secret regex in
:mod:`vrm_alert_relay.logs.redaction`, so a regex match always implies a
detection here. The regex is still used to locate and replace matches, but
only for secrets detected here.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

ESCAPE_STARTS: Final = frozenset("%\\+")
MAX_ESCAPE_LENGTH: Final = 12

_ESCAPE_RE = re.compile(r"[%\\+]")
_HEX: Final = frozenset("0123456789abcdefABCDEF")
_ESCAPE_TAIL: Final = _HEX | frozenset("%\\uUx\"/nrt'")
_SHORT_ESCAPES: Final = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "'": "'",
}


def escape_edges(text: str, start: int) -> list[tuple[int, str]]:
    """Escapes beginning at ``start``, as ``(end, decoded character)`` pairs."""
    char = text[start]
    if char == "+":
        return [(start + 1, " ")]
    if char == "%":
        return _percent_edges(text, start)
    kind = text[start + 1 : start + 2]
    if kind in _SHORT_ESCAPES:
        return [(start + 2, _SHORT_ESCAPES[kind])]
    if kind == "x":
        value = _hex(text, start + 2, 2)
        return [] if value is None else [(start + 4, chr(value))]
    if kind not in ("u", "U"):
        return []
    unit = _hex(text, start + 2, 4)
    if unit is None:
        return []
    edges = [(start + 6, chr(unit))]
    if 0xD800 <= unit < 0xDC00 and text[start + 6 : start + 7] == "\\":
        low = _hex(text, start + 8, 4) if text[start + 7 : start + 8] in "uU" else None
        if low is not None and 0xDC00 <= low < 0xE000:
            code = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            edges.append((start + 12, chr(code)))
    return edges


def _hex(text: str, start: int, count: int) -> int | None:
    digits = text[start : start + count]
    if len(digits) != count or not all(digit in _HEX for digit in digits):
        return None
    return int(digits, 16)


def _percent_edges(text: str, start: int) -> list[tuple[int, str]]:
    lead = _hex(text, start + 1, 2) if text[start : start + 1] == "%" else None
    if lead is None:
        return []
    size = 1 if lead < 0x80 else 2 if lead < 0xE0 else 3 if lead < 0xF0 else 4
    data = bytearray([lead])
    for index in range(1, size):
        position = start + 3 * index
        byte = _hex(text, position + 1, 2) if text[position : position + 1] == "%" else None
        if byte is None:
            return []
        data.append(byte)
    try:
        decoded = bytes(data).decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return []
    return [(start + 3 * size, decoded)]


class Lattice:
    """Shift-And automaton for a fixed list of secrets."""

    def __init__(self, secrets: Sequence[str]) -> None:
        self._secrets = tuple(secrets)
        masks: dict[str, int] = {}
        firsts = 0
        lasts: list[int] = []
        offset = 0
        for secret in self._secrets:
            for index, char in enumerate(secret):
                masks[char] = masks.get(char, 0) | (1 << (offset + index))
            firsts |= 1 << offset
            lasts.append(1 << (offset + len(secret) - 1))
            offset += len(secret)
        self._masks = masks
        self._firsts = firsts
        self._lasts = tuple(lasts)
        self._all_lasts = sum(lasts)
        self._all = (1 << offset) - 1
        self._carry = self._all ^ self._all_lasts

    def detect(self, text: str) -> tuple[list[int], bool]:
        """Indexes of secrets occurring in ``text``, and whether only literally.

        When ``text`` has no ``%``, ``\\`` or ``+``, every occurrence is
        literal and plain substring search decides.
        """
        if not self._secrets:
            return [], True
        if not _ESCAPE_RE.search(text):
            return [i for i, secret in enumerate(self._secrets) if secret in text], True
        found = 0
        for state in self._scan(text, firsts=self._firsts):
            if state & self._all_lasts:
                found |= state
        return [i for i, last in enumerate(self._lasts) if found & last], False

    def partial_prefix_start(self, text: str) -> int:
        """Earliest start of a secret prefix that runs into the end of ``text``.

        A prefix runs into the end if it reaches the end, or stops at a
        ``%`` or ``\\`` close enough to the end to begin an escape the cut
        split. Returns ``len(text)`` when there is none.
        """
        size = len(text)
        starts = [size] * (size + MAX_ESCAPE_LENGTH + 1)
        states = self._scan(text, firsts=self._firsts, starts=starts)
        earliest = size
        for position in range(max(0, size - MAX_ESCAPE_LENGTH + 1), size + 1):
            split = position < size and text[position] in "%\\"
            if (position == size or split) and states[position] & self._carry:
                earliest = min(earliest, starts[position])
        return earliest

    def partial_suffix_end(self, text: str) -> int:
        """End of the longest secret suffix that runs in from the start of ``text``.

        Chains begin at the start, or after a leading run that could be the
        rest of an escape the cut split. Returns 0 when there is none.
        """
        seeds = [0]
        for position in range(1, min(len(text), MAX_ESCAPE_LENGTH)):
            if text[position - 1] not in _ESCAPE_TAIL:
                break
            seeds.append(position)
        states = self._scan(text, firsts=0, seeded=self._carry, seeds=seeds)
        latest = 0
        for position, state in enumerate(states):
            if state & self._all_lasts:
                latest = position
        return latest

    def _scan(
        self,
        text: str,
        *,
        firsts: int,
        seeded: int = 0,
        seeds: Sequence[int] = (),
        starts: list[int] | None = None,
    ) -> list[int]:
        size = len(text)
        states = [0] * (size + MAX_ESCAPE_LENGTH + 1)
        for position in seeds:
            states[position] = seeded
        masks = self._masks
        carry = self._carry
        for index, char in enumerate(text):
            state = states[index]
            shifted = (state & carry) << 1 if state else 0
            edges = [(index + 1, char)]
            if char in ESCAPE_STARTS:
                edges += escape_edges(text, index)
            for end, decoded in edges:
                mask = masks.get(decoded)
                if mask is None:
                    continue
                continued = shifted & mask
                fresh = firsts & mask
                if continued or fresh:
                    states[end] |= continued | fresh
                    if starts is not None:
                        origin = starts[index] if continued else index
                        starts[end] = min(starts[end], origin)
        return states
