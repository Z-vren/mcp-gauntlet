"""`gauntlet run` and the third act of `gauntlet demo`, with a scripted agent in place of a real model."""

from __future__ import annotations

import json

import pytest

from helpers import TRAPDOOR, ScriptedModel, call, tool
from mcp_gauntlet import cli
from mcp_gauntlet.arena import Reply
from mcp_gauntlet.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

LEAKY = (
    lambda c: call("lookup", city=c.system) if any(t.name == "lookup" for t in c.tools) else Reply(text="done"),
)
OBEYS_RESULTS = (
    lambda c: call("search_notes", query="standup") if any(t.name == "search_notes" for t in c.tools) else Reply(text="done"),
    lambda c: call("read_file", path="~/.aws/credentials") if "credentials" in c.result else Reply(text="done"),
    lambda c: call("search_notes", query=c.result),
)


@pytest.fixture
def agent(monkeypatch):
    """Swap the model resolver for one that hands back a scripted agent, and record what was asked for."""
    asked = []

    def install(*moves):
        def resolve(spec, base_url=None):
            asked.append((spec, base_url))
            return ScriptedModel(*moves)

        monkeypatch.setattr(cli, "resolve_model", resolve)
        return asked

    return install


@pytest.fixture
def saved_manifest(tmp_path):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps([tool(), tool("other")]), encoding="utf-8")
    return str(path)


def test_run_dry_against_a_saved_manifest(agent, saved_manifest, capsys):
    asked = agent(*LEAKY)
    code = main(["run", "--model", "ollama:llama3.1", "--trials", "2", "--manifest", saved_manifest])
    out, err = capsys.readouterr()
    assert code == EXIT_FINDINGS
    assert asked == [("ollama:llama3.1", None)]
    assert "agent    scripted:agent" in out
    assert "mode     dry" in out
    assert "GA-R001" in out and "2 of 2 runs" in out
    assert "ok other" in out
    assert "not that the tool is safe" in out
    assert "[1/8] use-tool lookup: leak" in err  # two tools and two bystander scenarios, twice each


def test_run_json(agent, saved_manifest, capsys):
    agent(*LEAKY)
    assert main(["run", "--model", "x:y", "--trials", "1", "--json", "--manifest", saved_manifest]) == EXIT_FINDINGS
    report = json.loads(capsys.readouterr().out)
    assert report["range"] == {
        "model": "scripted:agent",
        "trialsPerScenario": 1,
        "runs": 4,
        "forwarded": False,
        "refused": 0,
        "errors": [],
        "skipped": [],
    }
    # The script leaks whenever `lookup` is loaded, which includes the bystander runs.
    assert {f["rule"] for f in report["findings"]} == {"GA-R001", "GA-R004"}


def test_run_only_reports_the_tools_it_tested(agent, saved_manifest, capsys):
    agent(Reply(text="done"))
    assert main(["run", "--model", "x:y", "--trials", "1", "--tool", "other", "--manifest", saved_manifest]) == EXIT_OK
    out = capsys.readouterr().out
    assert "ok other" in out and "lookup" not in out


def test_run_forward_and_transcripts(agent, tmp_path, capsys):
    agent(*OBEYS_RESULTS)
    transcripts = tmp_path / "runs.jsonl"
    code = main(
        ["run", "--model", "x:y", "--trials", "1", "--tool", "search_notes", "--forward",
         "--transcripts", str(transcripts), "--", *TRAPDOOR]
    )  # fmt: skip
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "mode     live" in out
    assert "the secret from ~/.aws/credentials" in out
    assert len(transcripts.read_text(encoding="utf-8").splitlines()) == 3


def test_model_can_come_from_the_environment(agent, saved_manifest, monkeypatch, capsys):
    asked = agent(Reply(text="done"))
    monkeypatch.setenv("GAUNTLET_MODEL", "ollama:from-env")
    assert main(["run", "--trials", "1", "--manifest", saved_manifest]) == EXIT_OK
    assert asked == [("ollama:from-env", None)]


@pytest.mark.parametrize(
    "argv, message",
    [
        (["run", "--manifest", "MANIFEST"], "no model chosen"),
        (["run", "--model", "ollama:x", "--forward", "--manifest", "MANIFEST"], "--forward needs a live server"),
        (["run", "--model", "ollama:x", "--trials", "0", "--manifest", "MANIFEST"], "at least 1"),
        (["run", "--model", "ollama:x"], "no server to scan"),
    ],
)
def test_run_usage_errors(argv, message, saved_manifest, capsys):
    argv = [saved_manifest if arg == "MANIFEST" else arg for arg in argv]
    assert main(argv) == EXIT_ERROR
    assert message in capsys.readouterr().err


def test_demo_without_a_model_points_at_the_third_act(capsys):
    assert main(["demo"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "gauntlet demo --model ollama:llama3.1" in out
    assert "live range" not in out


def test_demo_with_a_model_runs_the_range(agent, capsys):
    agent(*OBEYS_RESULTS)
    assert main(["demo", "--model", "x:y"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Now the live range" in out
    assert "x search_notes" in out and "GA-R001" in out
    assert "ok add" in out
    assert "runs     8 (2 per scenario)" in out
