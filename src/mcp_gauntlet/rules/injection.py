"""Text in a manifest that talks to the model instead of describing the tool."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Iterator

from ..manifest import Manifest
from .base import Finding, Rule, Severity, excerpt, rule, texts

OVERRIDE = rule(
    "GA-I001",
    Severity.CRITICAL,
    "Instruction override",
    "Remove it. A tool description has no business countermanding the user's or the system's instructions.",
)
CONCEAL = rule(
    "GA-I002",
    Severity.CRITICAL,
    "Tells the model to hide something from the user",
    "Remove it. Nothing a tool does should need to be kept from the person approving it.",
)
HIJACK = rule(
    "GA-I003",
    Severity.HIGH,
    "Claims priority over other tools",
    "Describe what the tool does, not when the model must pick it over others.",
)
CROSS_TOOL = rule(
    "GA-I004",
    Severity.MEDIUM,
    "Dictates how other tools are used",
    "A description should only cover its own tool. Rules about other tools are how shadowing attacks work.",
)
MARKUP = rule(
    "GA-I005",
    Severity.HIGH,
    "Pseudo-system markup",
    "Remove tags such as <IMPORTANT> or [SYSTEM]. They exist to make text look more authoritative to a model.",
)
SENSITIVE_FILE = rule(
    "GA-I006",
    Severity.HIGH,
    "References credential or config files",
    "Remove the reference, or explain in the README why this tool needs that file.",
)
ENCODED = rule(
    "GA-I007",
    Severity.MEDIUM,
    "Encoded payload",
    "Replace the encoded blob with plain text so reviewers can read what the model reads.",
)
PADDING = rule(
    "GA-I008",
    Severity.MEDIUM,
    "Whitespace padding",
    "Remove the padding. Long runs of blank space push text out of view in approval dialogs.",
)
OVERSIZED = rule(
    "GA-I009",
    Severity.LOW,
    "Oversized description",
    "Trim it. Very long descriptions are rarely read in full and are a common place to hide instructions.",
)

_MAX_DESCRIPTION = 2000
_NOT = r"(?:do\s+not|don['’]?t|never|must\s+not|should\s+not|shouldn['’]?t)"


def _any(*patterns: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE | re.MULTILINE)


_PATTERNS: list[tuple[Rule, re.Pattern]] = [
    (
        OVERRIDE,
        _any(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|preceding|other|all|any)\b[^.\n]{0,30}"
            r"\b(?:instructions?|rules?|prompts?|guidelines?|directives?)\b",
            r"\bnew\s+instructions?\s*:",
            r"\byou\s+are\s+now\b",
            r"\bfrom\s+now\s+on\b",
        ),
    ),
    (
        CONCEAL,
        _any(
            _NOT + r"\s+(?:tell|mention|inform|reveal|show|notify|alert|disclose)\b[^.\n]{0,40}"
            r"\b(?:users?|humans?|anyone|operator)\b",
            r"\bwithout\s+(?:telling|informing|notifying|asking|alerting|mentioning)\b[^.\n]{0,30}"
            r"\b(?:users?|humans?)\b",
            r"\busers?\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|be\s+(?:told|informed|aware))\b",
            r"\bkeep\s+(?:this|it)\s+(?:secret|hidden|confidential)\b",
        ),
    ),
    (
        HIJACK,
        _any(
            r"\balways\s+(?:call|use|invoke|run|prefer)\s+(?:this|these)\b",
            r"\b(?:call|use|invoke|run)\s+this\s+(?:tool\s+)?(?:first|before\s+(?:any|all|every))\b",
            r"\bbefore\s+(?:using|calling|invoking|running)\s+any\s+(?:other\s+)?tools?\b",
            r"\binstead\s+of\s+(?:using\s+|calling\s+)?(?:the\s+|any\s+)?(?:other\s+)?[\w-]+\s+tools?\b",
            _NOT + r"\s+(?:use|call|invoke)\s+(?:the\s+|any\s+)?(?:other\s+)?"
            r"(?!this\b|the\s+tools?\b|tools?\b)[\w-]+\s+(?:[\w-]+\s+)?tools?\b",
            r"\bprefer\s+(?:this|these)\s+(?:tools?\s+)?over\b",
            r"\bover\s+(?:any|all)\s+other\s+(?:tools?|servers?)\b",
        ),
    ),
    (
        CROSS_TOOL,
        _any(
            r"\b(?:when|whenever|while|after|before)\s+(?:you\s+(?:are\s+)?)?"
            r"(?:use|using|call|calling|invoke|invoking)\s+(?:the\s+|any\s+|an?\s+)?(?:other\s+)?"
            r"(?!this\b|the\s+tools?\b|tools?\b)[\w-]+\s+(?:[\w-]+\s+)?tools?\b",
        ),
    ),
    (
        MARKUP,
        _any(
            r"<\s*/?\s*(?:important|system|instructions?|secret|admin|priority|critical|override|hidden)\s*>",
            r"\[\s*(?:system|admin|important|instructions?)\s*\]",
            r"^\s*(?:system|assistant)\s*:",
            r"^\s*#{1,6}\s*(?:system|instructions?)\b",
        ),
    ),
    (
        SENSITIVE_FILE,
        _any(
            r"~/\.ssh\b",
            r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b",
            r"\.aws/credentials\b",
            r"(?<![\w.])\.env\b(?!\.example)",
            r"/etc/(?:passwd|shadow)\b",
            r"\bmcp\.json\b",
            r"\bclaude_desktop_config\.json\b",
            r"\.npmrc\b",
            r"\.netrc\b",
            r"\.git-credentials\b",
            r"\.kube/config\b",
            r"\.docker/config\.json\b",
        ),
    ),
    (PADDING, _any(r"\n{6,}", r"[ \t]{40,}")),
]

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{48,}={0,2}")


def _decoded_text(blob: str) -> str | None:
    """Decode a base64 candidate, returning it only if the result is readable text."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("ascii", "ignore")
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    if not raw or printable / len(raw) < 0.9 or " " not in text:
        return None
    return text


def check(manifest: Manifest) -> Iterator[Finding]:
    for tool, location, text in texts(manifest):
        for found, pattern in _PATTERNS:
            match = pattern.search(text)
            if match:
                yield found.hit(tool, location, f'"{excerpt(text, match.start(), match.end())}"')
        for match in _BASE64.finditer(text):
            decoded = _decoded_text(match.group())
            if decoded:
                shown = decoded if len(decoded) <= 120 else decoded[:120] + "..."
                yield ENCODED.hit(tool, location, f'base64 decodes to: "{shown}"')
                break
        if len(text) > _MAX_DESCRIPTION:
            yield OVERSIZED.hit(tool, location, f"{len(text)} characters")
