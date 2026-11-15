"""Drive the real client against the bundled Trapdoor server, and the CLI on top of both."""

from __future__ import annotations

import json
import sys

import pytest

from helpers import TRAPDOOR, tool
from mcp_gauntlet import lockfile
from mcp_gauntlet.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from mcp_gauntlet.client import MCPError, StdioClient, fetch_manifest
from mcp_gauntlet.rules import run_all

# What a scan of Trapdoor must find, tool by tool. `search_notes` is deliberately absent.
EXPECTED = {
    None: {"GA-I003"},
    "add": {"GA-I002", "GA-I005", "GA-I006", "GA-E002"},
    "get_weather": {"GA-U001", "GA-E003"},
    "send_emaіl": {"GA-U004", "GA-I003", "GA-I004", "GA-E004"},
    "fetch_report": {"GA-E001", "GA-E004"},
    "run_diagnostics": {"GA-S001", "GA-S004"},
    "read_note": {"GA-S002"},
}


def test_handshake_and_listing():
    m = fetch_manifest(TRAPDOOR)
    assert (m.server_name, m.server_version) == ("trapdoor", "0.1.0")
    assert len(m.tools) == 7
    assert m.instructions.startswith("Trapdoor")
    assert m.command == TRAPDOOR


def test_trapdoor_findings_are_exactly_as_documented():
    found: dict = {}
    for finding in run_all(fetch_manifest(TRAPDOOR)):
        found.setdefault(finding.tool, set()).add(finding.rule)
    assert found == EXPECTED


def test_rug_pull_is_caught():
    lock = lockfile.build(fetch_manifest(TRAPDOOR))
    later = fetch_manifest(TRAPDOOR, env={"TRAPDOOR_RUGPULL": "1"})
    assert {(f.rule, f.tool) for f in lockfile.diff(lock, later)} == {
        ("GA-D001", "search_notes"),
        ("GA-D002", "sync_notes"),
    }


def test_tools_are_inert():
    with StdioClient(TRAPDOOR) as client:
        client.initialize()
        result = client.request("tools/call", {"name": "run_diagnostics", "arguments": {"command": "whoami"}})
    assert "no action was performed" in result["content"][0]["text"]


def test_missing_executable():
    with pytest.raises(MCPError, match="could not start"):
        fetch_manifest(["definitely-not-a-real-binary-7f3a"])


def test_server_that_exits_immediately():
    with pytest.raises(MCPError, match="exited before answering"):
        fetch_manifest([sys.executable, "-c", "import sys; sys.stderr.write('boom')"])


def test_server_that_never_answers():
    with pytest.raises(MCPError, match="timed out"):
        fetch_manifest([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)


def test_stdout_noise_is_skipped():
    # A server that logs to stdout before speaking JSON-RPC must not derail the handshake.
    noisy = (
        "import runpy, sys; print('starting up...'); sys.stdout.flush(); "
        "runpy.run_module('mcp_gauntlet.demo.trapdoor', run_name='__main__')"
    )
    assert len(fetch_manifest([sys.executable, "-c", noisy]).tools) == 7


# --- CLI ---------------------------------------------------------------------


def test_demo(capsys):
    assert main(["demo"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "grade F" in out
    assert "send_ema<U+0456>l" in out
    assert "GA-D001" in out


def test_rules_lists_every_rule(capsys):
    assert main(["rules"]) == EXIT_OK
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 29
    assert lines[0].startswith("GA-C001")


def test_probe_then_pin_then_drift(tmp_path, capsys):
    lock = str(tmp_path / ".gauntlet.lock")
    assert main(["pin", "--lockfile", lock, "--", *TRAPDOOR]) == EXIT_OK
    assert main(["probe", "--lockfile", lock, "--json", "--", *TRAPDOOR]) == EXIT_FINDINGS
    capsys.readouterr()

    code = main(["probe", "--lockfile", lock, "--json", "-e", "TRAPDOOR_RUGPULL=1", "--", *TRAPDOOR])
    report = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert report["grade"] == "F"
    assert {"GA-D001", "GA-D002"} <= {f["rule"] for f in report["findings"]}


def test_probe_saved_manifest(tmp_path, capsys):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": [tool(properties={"path": {"type": "string"}})]}), encoding="utf-8")
    lock = str(tmp_path / "none.lock")

    assert main(["probe", "--manifest", str(path), "--lockfile", lock]) == EXIT_OK  # medium < default high
    assert "grade C" in capsys.readouterr().out
    assert main(["probe", "--manifest", str(path), "--lockfile", lock, "--fail-on", "medium"]) == EXIT_FINDINGS


def test_clean_manifest_gets_an_a(tmp_path, capsys):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps([tool()]), encoding="utf-8")
    assert main(["probe", "--manifest", str(path), "--lockfile", str(tmp_path / "none.lock")]) == EXIT_OK
    assert "grade A" in capsys.readouterr().out


def test_probe_without_a_target_is_a_usage_error(capsys):
    assert main(["probe"]) == EXIT_ERROR
    assert "no server to scan" in capsys.readouterr().err
