"""Characters that make a manifest read differently to a human than to a model."""

from __future__ import annotations

import unicodedata
from collections import Counter
from typing import Iterator

from ..manifest import Manifest
from .base import TAG_BLOCK, Finding, Severity, decode_tags, ident, rule, texts

TAGS = rule(
    "GA-U001",
    Severity.CRITICAL,
    "Hidden text in Unicode tag characters",
    "Remove them. Tag characters (U+E0000-E007F) render as nothing in most UIs but are read by the model.",
)
BIDI = rule(
    "GA-U002",
    Severity.HIGH,
    "Bidirectional control characters",
    "Remove them. Bidi overrides reorder text on screen so reviewers see something other than what is sent.",
)
ZERO_WIDTH = rule(
    "GA-U003",
    Severity.MEDIUM,
    "Zero-width or invisible characters",
    "Remove them. They can split keywords past filters or carry hidden data.",
)
MIXED_SCRIPT = rule(
    "GA-U004",
    Severity.HIGH,
    "Look-alike characters in an identifier",
    "Use plain ASCII for tool and parameter names. A mixed-script name can impersonate another tool.",
)

_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_ZERO_WIDTH = (
    {0x200B, 0x200C, 0x00AD, 0x180E, 0xFEFF}
    | set(range(0x2060, 0x2065))
    | set(range(0xE0100, 0xE01F0))  # variation selectors supplement: one byte of payload each
)


def _name(cp: int) -> str:
    return unicodedata.name(chr(cp), "unnamed")


def _tally(text: str, wanted: set[int]) -> str:
    counts = Counter(ord(c) for c in text if ord(c) in wanted)
    return ", ".join(f"{n} x U+{cp:04X} ({_name(cp)})" for cp, n in sorted(counts.items()))


def _scripts(identifier: str) -> dict[str, str]:
    """Map each script used by the letters of an identifier to one example character."""
    found: dict[str, str] = {}
    for ch in identifier:
        if ch.isalpha():
            found.setdefault(unicodedata.name(ch, "UNKNOWN").split()[0], ch)
    return found


def _check_text(tool: str | None, location: str, text: str) -> Iterator[Finding]:
    tag_count = sum(1 for c in text if ord(c) in TAG_BLOCK)
    if tag_count:
        decoded = decode_tags(text).strip()
        shown = decoded if len(decoded) <= 140 else decoded[:140] + "..."
        yield TAGS.hit(tool, location, f'{tag_count} invisible characters decode to: "{shown}"')
    bidi = _tally(text, _BIDI)
    if bidi:
        yield BIDI.hit(tool, location, bidi)
    zero_width = _tally(text, _ZERO_WIDTH)
    if zero_width:
        yield ZERO_WIDTH.hit(tool, location, zero_width)


def _check_identifier(tool: str, location: str, name: str) -> Iterator[Finding]:
    scripts = _scripts(name)
    if len(scripts) > 1:
        odd = [f"U+{ord(ch):04X} {_name(ord(ch))}" for script, ch in scripts.items() if script != "LATIN"]
        yield MIXED_SCRIPT.hit(tool, location, f'"{ident(name)}" mixes scripts: {"; ".join(odd)}')


def check(manifest: Manifest) -> Iterator[Finding]:
    for tool, location, text in texts(manifest):
        if not location.endswith("(hidden text)"):
            yield from _check_text(tool, location, text)
    for tool in manifest.tools:
        yield from _check_text(tool.name, "name", tool.name)
        yield from _check_identifier(tool.name, "name", tool.name)
        for param in tool.parameters():
            location = f"parameter {ident(param.path)}"
            yield from _check_text(tool.name, location, param.name)
            yield from _check_identifier(tool.name, location, param.name)
