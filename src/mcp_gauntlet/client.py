"""A minimal MCP client for the stdio transport.

Just enough of the protocol to complete the handshake and enumerate tools:
newline-delimited JSON-RPC 2.0 over the child's stdin/stdout. Written against
the standard library so the scanner itself has nothing to audit.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from collections import deque
from typing import Any

from . import __version__
from .manifest import Manifest, Tool

PROTOCOL_VERSION = "2025-06-18"
_MAX_PAGES = 50


class MCPError(Exception):
    """The server could not be started or did not speak MCP as expected."""


class StdioClient:
    def __init__(self, command: list[str], env: dict[str, str] | None = None, timeout: float = 20.0):
        if not command:
            raise MCPError("no server command given")
        self.command = list(command)
        self.env = env
        self.timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._inbox: queue.Queue = queue.Queue()
        self._stderr: deque[str] = deque(maxlen=20)
        self._next_id = 0

    def __enter__(self) -> "StdioClient":
        # shutil.which honours PATHEXT, so `npx` resolves to npx.cmd on Windows.
        exe = shutil.which(self.command[0]) or self.command[0]
        try:
            self._proc = subprocess.Popen(
                [exe, *self.command[1:]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, **(self.env or {})},
            )
        except OSError as exc:
            raise MCPError(f"could not start server: {exc}") from exc
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _pump_stdout(self) -> None:
        for line in self._proc.stdout:
            self._inbox.put(line)
        self._inbox.put(None)

    def _pump_stderr(self) -> None:
        # Drained so a chatty server cannot block on a full pipe; kept for error messages.
        for line in self._proc.stderr:
            self._stderr.append(line.decode("utf-8", "replace").rstrip())

    def _send(self, message: dict) -> None:
        data = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
        try:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()
        except OSError as exc:
            raise MCPError(self._died(f"server closed its input ({exc})")) from exc

    def _died(self, reason: str) -> str:
        tail = "\n".join(self._stderr)
        return f"{reason}\n--- server stderr ---\n{tail}" if tail else reason

    def notify(self, method: str, params: dict | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPError(self._died(f"timed out after {self.timeout:g}s waiting for {method}"))
            try:
                line = self._inbox.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                raise MCPError(self._died(f"server exited before answering {method}"))
            try:
                reply = json.loads(line)
            except ValueError:
                continue  # some servers log to stdout; skip anything that is not JSON
            if not isinstance(reply, dict):
                continue
            if "method" in reply:
                self._answer_server(reply)
                continue
            if reply.get("id") != request_id:
                continue
            if "error" in reply:
                err = reply["error"] if isinstance(reply["error"], dict) else {}
                raise MCPError(f"{method} failed: {err.get('message', reply['error'])}")
            result = reply.get("result")
            return result if isinstance(result, dict) else {}

    def _answer_server(self, message: dict) -> None:
        """Server-to-client traffic: answer pings, decline everything else, ignore notifications."""
        if "id" not in message:
            return
        if message.get("method") == "ping":
            self._send({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": "not supported by mcp-gauntlet"},
                }
            )

    def initialize(self) -> dict:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-gauntlet", "version": __version__},
            },
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        tools: list[dict] = []
        cursor = None
        for _ in range(_MAX_PAGES):
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in result.get("tools") or [] if isinstance(t, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools


def fetch_manifest(command: list[str], env: dict[str, str] | None = None, timeout: float = 20.0) -> Manifest:
    """Launch a stdio MCP server and return what it advertises."""
    with StdioClient(command, env=env, timeout=timeout) as client:
        init = client.initialize()
        tools = client.list_tools()
    info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else {}
    return Manifest(
        tools=[Tool(t) for t in tools],
        server_name=str(info.get("name", "")),
        server_version=str(info.get("version", "")),
        instructions=str(init.get("instructions") or ""),
        command=list(command),
    )
