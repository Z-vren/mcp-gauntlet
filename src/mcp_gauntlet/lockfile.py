"""Pin a server's manifest and detect drift.

MCP clients ask for approval once, then trust the server to keep advertising
the same tools. A server that rewrites a description afterwards (a "rug pull")
is invisible unless something remembers what was approved. The lockfile is that
memory: commit it, and a changed tool shows up in code review and fails CI.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Iterator

from .manifest import Manifest, sha256
from .rules.base import Finding, Severity, excerpt, ident, rule

LOCK_VERSION = 1
DEFAULT_PATH = ".gauntlet.lock"

CHANGED = rule(
    "GA-D001",
    Severity.CRITICAL,
    "Tool definition changed since it was pinned",
    "Review the change. If it is legitimate, re-run `gauntlet pin` and commit the new lockfile.",
)
ADDED = rule(
    "GA-D002",
    Severity.HIGH,
    "Tool appeared since the manifest was pinned",
    "Review the new tool, then re-run `gauntlet pin` to accept it.",
)
REMOVED = rule(
    "GA-D003",
    Severity.LOW,
    "Pinned tool is no longer advertised",
    "Re-run `gauntlet pin` if the removal is expected.",
)
INSTRUCTIONS_CHANGED = rule(
    "GA-D004",
    Severity.HIGH,
    "Server instructions changed since they were pinned",
    "Review the new instructions, then re-run `gauntlet pin` to accept them.",
)


def build(manifest: Manifest) -> dict:
    return {
        "lockVersion": LOCK_VERSION,
        "server": {"name": manifest.server_name, "version": manifest.server_version},
        "instructions": manifest.instructions,
        "tools": {
            tool.name: {
                "sha256": tool.digest(),
                "schemaSha256": sha256(tool.input_schema),
                # Kept in clear so a changed description is readable in the lockfile's own diff.
                "description": tool.description,
            }
            for tool in sorted(manifest.tools, key=lambda t: t.name)
        },
    }


def write(path: Path, manifest: Manifest) -> None:
    path.write_text(json.dumps(build(manifest), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def load(path: Path) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(lock, dict) or lock.get("lockVersion") != LOCK_VERSION:
        raise ValueError(f"{path} is not a version {LOCK_VERSION} gauntlet lockfile")
    return lock


def _added_text(old: str, new: str) -> str:
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    parts = [new[j1:j2].strip() for op, _, _, j1, j2 in matcher.get_opcodes() if op in ("insert", "replace")]
    return " ... ".join(p for p in parts if p)


def _describe_change(pinned: dict, tool) -> str:
    changes = []
    if pinned.get("description") != tool.description:
        added = _added_text(str(pinned.get("description", "")), tool.description)
        if added:
            changes.append(f'description gained: "{excerpt(added, 0, len(added), pad=0)}"')
        else:
            changes.append("description was shortened")
    if pinned.get("schemaSha256") != sha256(tool.input_schema):
        changes.append("inputSchema changed")
    return "; ".join(changes) or "title, annotations or outputSchema changed"


def diff(lock: dict, manifest: Manifest) -> Iterator[Finding]:
    """Compare what the server advertises now against what was pinned."""
    pinned_tools = lock.get("tools") or {}
    live = {tool.name: tool for tool in manifest.tools}

    if lock.get("instructions", "") != manifest.instructions:
        added = _added_text(str(lock.get("instructions", "")), manifest.instructions)
        evidence = f'gained: "{excerpt(added, 0, len(added), pad=0)}"' if added else "text was removed"
        yield INSTRUCTIONS_CHANGED.hit(None, "instructions", evidence)

    for name, tool in live.items():
        pinned = pinned_tools.get(name)
        if pinned is None:
            yield ADDED.hit(name, "tools/list", f'"{ident(name)}" was not in the lockfile')
        elif pinned.get("sha256") != tool.digest():
            yield CHANGED.hit(name, "tools/list", _describe_change(pinned, tool))

    for name in pinned_tools:
        if name not in live:
            yield REMOVED.hit(name, "tools/list", f'"{ident(name)}" was pinned but is gone')
