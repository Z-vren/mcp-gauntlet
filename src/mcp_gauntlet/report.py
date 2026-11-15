"""Turn findings into a terminal report card or machine-readable JSON."""

from __future__ import annotations

import json
import os
import textwrap
from typing import IO

from . import __version__
from .manifest import Manifest
from .rules.base import Finding, Severity, ident

_COLORS = {
    Severity.CRITICAL: "1;31",
    Severity.HIGH: "31",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "2",
}
_GRADES = {
    Severity.CRITICAL: "F",
    Severity.HIGH: "D",
    Severity.MEDIUM: "C",
    Severity.LOW: "B",
    Severity.INFO: "A",
}
_WIDTH = 96
_INDENT = " " * 12


def use_color(stream: IO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def grade(findings: list[Finding]) -> str:
    """A to F, set by the single worst finding: one critical is a failing manifest."""
    return _GRADES[max((f.severity for f in findings), default=Severity.INFO)] if findings else "A"


def counts(findings: list[Finding]) -> dict[str, int]:
    return {
        sev.label: n
        for sev in sorted(Severity, reverse=True)
        if (n := sum(1 for f in findings if f.severity == sev))
    }


def _paint(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def _wrap(text: str) -> list[str]:
    return textwrap.wrap(text, width=_WIDTH, initial_indent=_INDENT, subsequent_indent=_INDENT) or [_INDENT]


def _block(finding: Finding, color: bool) -> list[str]:
    severity = _paint(finding.severity.label.upper().ljust(9), _COLORS[finding.severity], color)
    lines = [f"  {severity} {_paint(finding.rule, '2', color)}  {_paint(finding.title, '1', color)}"]
    lines += _wrap(f"{finding.location}: {finding.evidence}")
    lines += [_paint(line, "2", color) for line in _wrap(f"fix: {finding.fix}")]
    return lines


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.rule))


def render_text(
    manifest: Manifest, findings: list[Finding], *, color: bool = False, only_flagged: bool = False
) -> str:
    by_tool: dict[str | None, list[Finding]] = {}
    for finding in findings:
        by_tool.setdefault(finding.tool, []).append(finding)

    server = " ".join(part for part in (manifest.server_name, manifest.server_version) if part) or "(unnamed)"
    lines = [
        _paint(f"mcp-gauntlet {__version__}", "1", color),
        f"  server   {server}",
    ]
    if manifest.command:
        lines.append(f"  launch   {' '.join(manifest.command)}")
    lines.append(f"  tools    {len(manifest.tools)}")

    if None in by_tool:
        lines += ["", _paint("x", "31", color) + " " + _paint("server", "1", color)]
        for finding in _ordered(by_tool[None]):
            lines += _block(finding, color)

    # Tools the server advertises, then any that only exist in findings (removed since pinning).
    names = [tool.name for tool in manifest.tools]
    names += [name for name in by_tool if name is not None and name not in names]
    for name in names:
        flagged = by_tool.get(name)
        if not flagged:
            if not only_flagged:
                lines += ["", _paint("ok", "32", color) + " " + _paint(ident(name), "1", color)]
            continue
        lines += ["", _paint("x", "31", color) + " " + _paint(ident(name), "1", color)]
        for finding in _ordered(flagged):
            lines += _block(finding, color)

    tally = "   ".join(
        _paint(f"{n} {label}", _COLORS[Severity.parse(label)], color) for label, n in counts(findings).items()
    )
    letter = grade(findings)
    lines += ["", "-" * 64]
    lines.append(f"{tally or 'no findings'}   grade {_paint(letter, '1;32' if letter == 'A' else '1;31', color)}")
    if not only_flagged:
        clean = sum(1 for tool in manifest.tools if tool.name not in by_tool)
        lines.append(f"{clean} of {len(manifest.tools)} tools clean")
    return "\n".join(lines)


def render_json(manifest: Manifest, findings: list[Finding]) -> str:
    return json.dumps(
        {
            "gauntlet": __version__,
            "server": {"name": manifest.server_name, "version": manifest.server_version},
            "command": manifest.command,
            "tools": len(manifest.tools),
            "grade": grade(findings),
            "summary": counts(findings),
            "findings": [f.to_dict() for f in _ordered(findings)],
        },
        indent=2,
        ensure_ascii=True,
    )
