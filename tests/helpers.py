from __future__ import annotations

import sys

from mcp_gauntlet.arena import Reply, ToolCall
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


# --- a stand-in agent for the range ------------------------------------------


def call(name: str, **arguments) -> Reply:
    return Reply(calls=[ToolCall(f"call_{name}", name, arguments)])


class ScriptedConversation:
    def __init__(self, moves, system, tools, history):
        self.system = system
        self.tools = tools
        self.history = history
        self.sent: list[str] = []
        self.last_results: list = []
        self._moves = iter(moves)

    def send(self, text: str) -> None:
        self.sent.append(text)

    def step(self) -> Reply:
        move = next(self._moves, None)
        if move is None:
            return Reply(text="done")
        return move(self) if callable(move) else move

    def results(self, results) -> None:
        self.last_results = results

    @property
    def result(self) -> str:
        """The text of the first tool result from the previous step."""
        return self.last_results[0][1]


class ScriptedModel:
    """Plays back the same moves in every conversation. A move is a Reply, or a function of the conversation."""

    label = "scripted:agent"

    def __init__(self, *moves):
        self.moves = moves
        self.conversations: list[ScriptedConversation] = []

    def start(self, system, tools, history) -> ScriptedConversation:
        conversation = ScriptedConversation(self.moves, system, tools, history)
        self.conversations.append(conversation)
        return conversation
