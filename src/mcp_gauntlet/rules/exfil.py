"""Channels a hijacked agent could use to send data out."""

from __future__ import annotations

import re
from typing import Iterator

from ..manifest import Manifest
from .base import Finding, Severity, excerpt, ident, rule, texts, tokens

URL_SINK = rule(
    "GA-E001",
    Severity.MEDIUM,
    "Free-form outbound destination",
    "Constrain it with an enum, a pattern, or a server-side allowlist. "
    "An unconstrained URL parameter is an exfiltration channel for any injected agent.",
)
SIDE_CHANNEL = rule(
    "GA-E002",
    Severity.LOW,
    "Catch-all parameter",
    "Drop it or give it a real purpose and a constraint. "
    "Vague free-text parameters are where poisoned descriptions tell the model to stash stolen data.",
)
HARVEST = rule(
    "GA-E003",
    Severity.HIGH,
    "Asks for the conversation or system prompt",
    "Remove it. A tool should receive its arguments, not the model's context.",
)
EXFIL_HOST = rule(
    "GA-E004",
    Severity.HIGH,
    "Points at a request-capture host or a raw IP",
    "Remove the hard-coded destination or replace it with a domain you control and document.",
)

_URL_WORDS = {"url", "uri", "webhook", "callback", "endpoint", "hostname", "redirect"}
_URL_FORMATS = {"uri", "url", "uri-reference", "iri"}
_VAGUE_WORDS = {"sidenote", "scratchpad", "reasoning", "thoughts", "debug", "context", "extra", "memo"}

_HARVEST = re.compile(
    r"\b(?:conversation|chat|message)\s+(?:history|logs?|transcript)\b"
    r"|\bprevious\s+(?:messages|conversations?|turns)\b"
    r"|\b(?:entire|full|whole|complete)\s+(?:conversation|chat|context|transcript)\b"
    r"|\bsystem\s+prompt\b"
    r"|\bcontext\s+window\b",
    re.IGNORECASE,
)

_EXFIL_HOST = re.compile(
    r"\b(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)"
    r"|burpcollaborator\.net|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|oastify\.com"
    r"|canarytokens\.(?:com|org)|beeceptor\.com|hookbin\.com|trycloudflare\.com)\b"
    r"|\bhttps?://(?!127\.|0\.0\.0\.0)\d{1,3}(?:\.\d{1,3}){3}\b",
    re.IGNORECASE,
)


def _constrained(schema: dict) -> bool:
    return any(key in schema for key in ("enum", "const", "pattern"))


def _is_free_string(schema: dict) -> bool:
    return schema.get("type") in (None, "string") and not _constrained(schema)


def check(manifest: Manifest) -> Iterator[Finding]:
    for tool in manifest.tools:
        for param in tool.parameters():
            if not _is_free_string(param.schema):
                continue
            words = tokens(param.name)
            location = f"parameter {ident(param.path)}"
            if words & _URL_WORDS or param.schema.get("format") in _URL_FORMATS:
                yield URL_SINK.hit(tool.name, location, f'"{ident(param.name)}" accepts any destination')
            elif words & _VAGUE_WORDS:
                yield SIDE_CHANNEL.hit(tool.name, location, f'"{ident(param.name)}" is an unconstrained string')

    for tool_name, location, text in texts(manifest):
        match = _HARVEST.search(text)
        if match:
            yield HARVEST.hit(tool_name, location, f'"{excerpt(text, match.start(), match.end())}"')
        match = _EXFIL_HOST.search(text)
        if match:
            yield EXFIL_HOST.hit(tool_name, location, f'"{excerpt(text, match.start(), match.end())}"')
