from __future__ import annotations

import sys

from mcp_gauntlet.manifest import Manifest, Tool
from mcp_gauntlet.rules import run_all

TRAPDOOR = [sys.executable, "-m", "mcp_gauntlet.demo.trapdoor"]


def tool(name: str = "lookup", description: str = "Look something up.", properties: dict | None = None, **extra) -> dict:
    schema = {"type": "object", "properties": properties if properties is not None else {"city": {"type": "string"}}}
    return {"name": name, "description": description, "inputSchema": schema, **extra}


def manifest(*tools: dict, instructions: str = "", command: list[str] | None = None) -> Manifest:
    return Manifest(tools=[Tool(t) for t in tools], instructions=instructions, command=command or [])


def rule_ids(m: Manifest) -> set[str]:
    return {f.rule for f in run_all(m)}
