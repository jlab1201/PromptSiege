"""Reversible/obfuscating transforms used to expand the `encoding` corpus category."""
from __future__ import annotations

import base64
from collections.abc import Callable

_HOMOGLYPHS = {  # ASCII -> visually similar Unicode (1:1, length-preserving)
    "a": "а", "A": "А", "c": "с", "C": "С", "e": "е", "E": "Е",
    "i": "і", "I": "І", "o": "о", "O": "О", "p": "р", "P": "Р",
    "x": "х", "X": "Х", "y": "у", "Y": "У",
}
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _hex(text: str) -> str:
    return text.encode("utf-8").hex()


def _homoglyph(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _leet(text: str) -> str:
    return "".join(_LEET.get(ch.lower(), ch) for ch in text)


ENCODERS: dict[str, Callable[[str], str]] = {
    "base64": _b64,
    "hex": _hex,
    "homoglyph": _homoglyph,
    "leetspeak": _leet,
}


def encode_variants(text: str) -> list[tuple[str, str]]:
    """Return [(encoder_name, encoded_text), ...] for every encoder."""
    return [(name, fn(text)) for name, fn in ENCODERS.items()]
