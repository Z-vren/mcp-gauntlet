"""Static checks over an MCP manifest. Each module contributes one `check(manifest)` generator."""

from __future__ import annotations

from ..manifest import Manifest
from . import exfil, injection, scope, supply_chain, unicode
from .base import RULES, Finding, Rule, Severity

__all__ = ["RULES", "Finding", "Rule", "Severity", "run_all"]

_CHECKS = (supply_chain.check, unicode.check, injection.check, exfil.check, scope.check)


def run_all(manifest: Manifest) -> list[Finding]:
    return [finding for check in _CHECKS for finding in check(manifest)]
