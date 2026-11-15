"""Tools that can do more than their description or annotations admit."""

from __future__ import annotations

import re
from typing import Iterator

from ..manifest import Manifest, Tool
from .base import Finding, Severity, ident, rule, tokens

EXEC = rule(
    "GA-S001",
    Severity.HIGH,
    "Arbitrary command or code execution",
    "Expose specific operations instead of a shell. If a shell is the point, say so and sandbox the server.",
)
PATH = rule(
    "GA-S002",
    Severity.MEDIUM,
    "Unconstrained file path",
    "Confirm the server confines paths to a root directory and rejects traversal; "
    "declare a pattern if the layout allows it.",
)
RAW_QUERY = rule(
    "GA-S003",
    Severity.MEDIUM,
    "Raw query passthrough",
    "Offer parameterised operations, or connect with a read-only, least-privilege database role.",
)
READONLY_LIE = rule(
    "GA-S004",
    Severity.HIGH,
    "Marked read-only but looks like it changes things",
    "Fix the annotation. Clients skip confirmation prompts for tools that claim readOnlyHint.",
)
NOT_DESTRUCTIVE = rule(
    "GA-S005",
    Severity.MEDIUM,
    "Destructive tool declared non-destructive",
    "Set destructiveHint to true so clients ask before running it.",
)

_EXEC_NAMES = {"command", "cmd", "shell", "script", "code", "exec", "eval", "bash", "powershell", "cmdline"}
_EXEC_WORDS = {"command", "cmd", "shell", "exec", "eval"}
_EXEC_TOOL_WORDS = {"exec", "shell", "bash", "eval", "terminal", "powershell", "cmd"}
_PATH_WORDS = {"path", "file", "filepath", "filename", "dir", "directory", "folder"}
_QUERY_NAMES = {"sql", "query", "statement"}
_MUTATING = {
    "write", "delete", "remove", "update", "create", "send", "exec", "execute", "run", "drop", "kill",
    "post", "put", "patch", "set", "insert", "modify", "edit", "move", "rename", "deploy", "publish",
    "upload", "install",
}  # fmt: skip
_DESTRUCTIVE = {"delete", "remove", "drop", "kill", "wipe", "purge", "destroy", "truncate"}
_SQL = re.compile(r"\b(?:sql|database|db|table|select)\b", re.IGNORECASE)


def _exec_params(tool: Tool) -> list[str]:
    return [
        p.path
        for p in tool.parameters()
        if p.name.lower() in _EXEC_NAMES or tokens(p.name) & _EXEC_WORDS
    ]


def _quoted(names: list[str]) -> str:
    return ", ".join(f'"{ident(n)}"' for n in names)


def check(manifest: Manifest) -> Iterator[Finding]:
    for tool in manifest.tools:
        name_words = tokens(tool.name)
        exec_params = _exec_params(tool)

        if exec_params:
            yield EXEC.hit(tool.name, "inputSchema", f"takes {_quoted(exec_params)}")
        elif name_words & _EXEC_TOOL_WORDS:
            yield EXEC.hit(tool.name, "name", f'named "{ident(tool.name)}"')

        for param in tool.parameters():
            free = param.schema.get("type") in (None, "string") and not any(
                key in param.schema for key in ("enum", "const", "pattern")
            )
            if not free:
                continue
            location = f"parameter {ident(param.path)}"
            if tokens(param.name) & _PATH_WORDS:
                yield PATH.hit(tool.name, location, f'"{ident(param.name)}" accepts any path')
            lowered = param.name.lower()
            if lowered in _QUERY_NAMES and (lowered == "sql" or _SQL.search(f"{tool.name} {tool.description}")):
                yield RAW_QUERY.hit(tool.name, location, f'"{ident(param.name)}" is passed through as a query')

        annotations = tool.annotations
        if annotations.get("readOnlyHint") is True:
            reasons = []
            if exec_params:
                reasons.append(f"it takes {_quoted(exec_params)}")
            verbs = sorted(name_words & _MUTATING)
            if verbs:
                reasons.append(f'its name says "{verbs[0]}"')
            if reasons:
                yield READONLY_LIE.hit(
                    tool.name, "annotations.readOnlyHint", "readOnlyHint is true, but " + " and ".join(reasons)
                )
        if annotations.get("destructiveHint") is False:
            verbs = sorted(name_words & _DESTRUCTIVE)
            if verbs:
                yield NOT_DESTRUCTIVE.hit(
                    tool.name, "annotations.destructiveHint", f'destructiveHint is false, but its name says "{verbs[0]}"'
                )
