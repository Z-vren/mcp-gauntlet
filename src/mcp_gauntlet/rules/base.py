"""Shared vocabulary for rules: severities, findings, the rule registry, and text helpers."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Iterator

from ..manifest import Manifest

TAG_BLOCK = range(0xE0000, 0xE0080)


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value}") from None


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    title: str
    tool: str | None  # None for server-level findings (launch command, instructions)
    location: str
    evidence: str
    fix: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    fix: str

    def hit(self, tool: str | None, location: str, evidence: str, severity: Severity | None = None) -> Finding:
        return Finding(self.id, severity or self.severity, self.title, tool, location, evidence, self.fix)


RULES: dict[str, Rule] = {}


def rule(id: str, severity: Severity, title: str, fix: str) -> Rule:
    """Declare a rule and add it to the registry that `gauntlet rules` lists."""
    if id in RULES:
        raise ValueError(f"duplicate rule id: {id}")
    RULES[id] = Rule(id, severity, title, fix)
    return RULES[id]


def is_invisible(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\t":
        return False
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:  # variation selectors
        return True
    return unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cn", "Zl", "Zp")


def visible(text: str) -> str:
    """Render text so nothing in it can hide: invisible characters become <U+XXXX>."""
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if len(run) > 3:
            out.append(f"<{len(run)} invisible chars>")
        else:
            out.extend(f"<U+{ord(c):04X}>" for c in run)
        run.clear()

    for ch in text:
        if is_invisible(ch):
            run.append(ch)
            continue
        flush()
        out.append("\\n" if ch == "\n" else " " if ch == "\t" else ch)
    flush()
    return "".join(out)


def ident(name: str) -> str:
    """Render an identifier so look-alike characters stand out."""
    return "".join(ch if ch.isascii() and ch.isprintable() else f"<U+{ord(ch):04X}>" for ch in name)


def excerpt(text: str, start: int, end: int, pad: int = 40, limit: int = 180) -> str:
    """The matched span with a little context, safe to print."""
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    snippet = visible(text[lo:hi]).strip()
    if len(snippet) > limit:
        snippet = snippet[:limit].rstrip() + "..."
    return ("..." if lo > 0 else "") + snippet + ("..." if hi < len(text) else "")


def decode_tags(text: str) -> str:
    """Recover ASCII smuggled through the Unicode tag block."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0x20 <= ord(c) - 0xE0000 <= 0x7E)


def tokens(identifier: str) -> set[str]:
    """Split snake_case / camelCase / kebab-case into lowercase words."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", identifier)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


def texts(manifest: Manifest) -> Iterator[tuple[str | None, str, str]]:
    """Every model-visible string in the manifest as (tool, location, text).

    Text smuggled through tag characters is decoded and yielded as well, so the
    content rules get to read what the model reads.
    """

    def with_hidden(tool: str | None, location: str, text: str) -> Iterator[tuple[str | None, str, str]]:
        yield tool, location, text
        hidden = decode_tags(text)
        if hidden.strip():
            yield tool, f"{location} (hidden text)", hidden

    if manifest.instructions:
        yield from with_hidden(None, "instructions", manifest.instructions)
    for tool in manifest.tools:
        for field in tool.text_fields():
            yield from with_hidden(tool.name, field.location, field.text)
