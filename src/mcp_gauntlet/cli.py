"""Command-line entry point: `gauntlet probe | pin | run | demo | rules`."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

from . import __version__, lockfile
from .arena import (
    Model,
    ModelError,
    RangeConfig,
    RangeResult,
    Trial,
    load_corpus,
    resolve_model,
    run_range,
    write_transcripts,
)
from .client import MCPError, StdioClient, fetch_manifest
from .manifest import Manifest
from .report import render_json, render_text, use_color
from .rules import RULES, Severity, run_all
from .rules.base import ident

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

_EPILOG = """\
examples:
  gauntlet demo
  gauntlet probe -- npx -y some-mcp-server@1.4.2 ./workspace
  gauntlet pin   -- uvx some-mcp-server==1.4.2
  gauntlet probe --manifest tools.json --json
  gauntlet run --model ollama:llama3.1 -- npx -y some-mcp-server@1.4.2 ./workspace

Everything after `--` is the command that launches the server. Probing a server
runs it: treat an untrusted server like any other untrusted program.
"""

_DRY = "dry: tool calls are intercepted, the server never runs them"
_LIVE = "live: tool calls reach the server and really run"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gauntlet",
        description="Lint MCP tool manifests for prompt injection, pin them against rug pulls, "
        "and test them against a live agent.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"mcp-gauntlet {__version__}")
    sub = parser.add_subparsers(dest="action", required=True)

    source = argparse.ArgumentParser(add_help=False)
    source.add_argument("--manifest", metavar="FILE", help="use a saved tools/list result instead of launching a server")
    source.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS", help="per MCP request, default: %(default)g")
    source.add_argument("-e", "--env", action="append", default=[], metavar="KEY=VALUE", help="extra environment for the server")

    locked = argparse.ArgumentParser(add_help=False)
    locked.add_argument("--lockfile", metavar="PATH", default=lockfile.DEFAULT_PATH, help="default: %(default)s")

    output = argparse.ArgumentParser(add_help=False)
    output.add_argument("--json", action="store_true", help="machine-readable output")
    output.add_argument(
        "--fail-on",
        default="high",
        choices=[s.label for s in Severity],
        help="exit 1 if any finding is at least this severe (default: %(default)s)",
    )

    agent = argparse.ArgumentParser(add_help=False)
    agent.add_argument("--model", metavar="PROVIDER:MODEL", help="the model that plays the agent, e.g. ollama:llama3.1 (or set GAUNTLET_MODEL)")
    agent.add_argument("--base-url", metavar="URL", help="endpoint for an OpenAI-compatible server")
    agent.add_argument("--trials", type=int, metavar="N", help="runs per scenario (default: 3, demo: 2)")

    probe = sub.add_parser("probe", parents=[source, locked, output], help="scan a server and check it against the lockfile")
    probe.add_argument("--no-lock", action="store_true", help="skip the drift check even if a lockfile exists")

    sub.add_parser("pin", parents=[source, locked], help="record the current manifest in the lockfile")

    run = sub.add_parser("run", parents=[source, output, agent], help="test the server against a live agent holding planted secrets")
    run.add_argument("--forward", action="store_true", help="let tool calls reach the server (they really run), to catch injection in tool results")
    run.add_argument("--tool", action="append", default=[], metavar="NAME", help="only test this tool (repeatable)")
    run.add_argument("--max-steps", type=int, default=6, metavar="N", help="model turns per run (default: %(default)s)")
    run.add_argument("--corpus", metavar="FILE", help="scenarios and honeypots to use instead of the bundled corpus")
    run.add_argument("--transcripts", metavar="FILE", help="write every run, step by step, as JSON lines")

    sub.add_parser("demo", parents=[agent], help="scan Trapdoor, the bundled malicious server (no setup needed)")
    sub.add_parser("rules", help="list every rule")
    return parser


def _env(args: argparse.Namespace) -> dict[str, str]:
    env = {}
    for pair in args.env:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise ValueError(f"--env expects KEY=VALUE, got: {pair}")
        env[key] = value
    return env


def _load(args: argparse.Namespace, command: list[str]) -> Manifest:
    if args.manifest:
        if command:
            raise ValueError("give either --manifest or a server command, not both")
        return Manifest.from_json(json.loads(Path(args.manifest).read_text(encoding="utf-8")))
    if not command:
        raise ValueError("no server to scan: pass a launch command after `--`, or --manifest FILE")
    return fetch_manifest(command, env=_env(args), timeout=args.timeout)


def _exit_code(findings: list, fail_on: str) -> int:
    threshold = Severity.parse(fail_on)
    return EXIT_FINDINGS if any(f.severity >= threshold for f in findings) else EXIT_OK


def _probe(args: argparse.Namespace, command: list[str]) -> int:
    manifest = _load(args, command)
    findings = run_all(manifest)
    lock_path = Path(args.lockfile)
    pinned = not args.no_lock and lock_path.exists()
    if pinned:
        findings += lockfile.diff(lockfile.load(lock_path), manifest)

    if args.json:
        print(render_json(manifest, findings))
    else:
        print(render_text(manifest, findings, color=use_color(sys.stdout)))
        print(f"drift check against {lock_path}" if pinned else "not pinned: run `gauntlet pin` to detect future changes")
    return _exit_code(findings, args.fail_on)


def _pin(args: argparse.Namespace, command: list[str]) -> int:
    manifest = _load(args, command)
    lock_path = Path(args.lockfile)
    lockfile.write(lock_path, manifest)
    print(f"pinned {len(manifest.tools)} tools to {lock_path}")
    print("commit it: a changed tool definition will now fail `gauntlet probe`")
    return EXIT_OK


# --- the range ---------------------------------------------------------------


def _progress(done: int, total: int, trial: Trial) -> None:
    what = trial.scenario + (f" {ident(trial.tool)}" if trial.tool else "")
    if trial.error:
        outcome = f"error: {trial.error}"
    elif trial.refused:
        outcome = "model declined"
    else:
        outcome = ", ".join(sorted({event.kind for event in trial.events})) or "clean"
    print(f"  [{done}/{total}] {what}: {outcome}", file=sys.stderr, flush=True)


def _range_details(model: Model, result: RangeResult, config: RangeConfig, forwarded: bool) -> list[tuple[str, str]]:
    return [
        ("agent", model.label),
        ("runs", f"{len(result.trials)} ({config.trials} per scenario)"),
        ("mode", _LIVE if forwarded else _DRY),
    ]


def _tested(manifest: Manifest, config: RangeConfig) -> Manifest:
    """The manifest as the report should show it: only tools that were actually put under test."""
    if config.only is None:
        return manifest
    return dataclasses.replace(manifest, tools=[t for t in manifest.tools if t.name in config.only])


def _range_notes(result: RangeResult, config: RangeConfig) -> list[str]:
    notes = []
    if result.refused:
        notes.append(f"{result.refused} runs ended with the model's safety layer declining; they count as not steered")
    if result.errors:
        notes.append(f"{len(result.errors)} runs failed and were left out: {result.errors[0]}")
    notes += [f"skipped {reason}" for reason in result.skipped]
    notes.append(f"a clean tool means this agent was not steered in {config.trials} tries, not that the tool is safe")
    return notes


def _run(args: argparse.Namespace, command: list[str]) -> int:
    trials = 3 if args.trials is None else args.trials
    if trials < 1 or args.max_steps < 1:
        raise ValueError("--trials and --max-steps must be at least 1")
    model = resolve_model(args.model or os.environ.get("GAUNTLET_MODEL"), args.base_url)
    corpus = load_corpus(Path(args.corpus) if args.corpus else None)
    config = RangeConfig(trials=trials, max_steps=args.max_steps, only=frozenset(args.tool) or None)

    if args.forward:
        if args.manifest or not command:
            raise ValueError("--forward needs a live server: pass its launch command after `--`")
        with StdioClient(command, env=_env(args), timeout=args.timeout) as client:
            manifest = client.read_manifest()
            result = run_range(manifest, model, corpus, config, forward=client.call_tool, progress=_progress)
    else:
        manifest = _load(args, command)
        result = run_range(manifest, model, corpus, config, progress=_progress)

    if args.transcripts:
        write_transcripts(Path(args.transcripts), result, model.label)

    shown = _tested(manifest, config)
    if args.json:
        summary = {
            "model": model.label,
            "trialsPerScenario": config.trials,
            "runs": len(result.trials),
            "forwarded": args.forward,
            "refused": result.refused,
            "errors": result.errors,
            "skipped": result.skipped,
        }
        print(render_json(shown, result.findings, extra={"range": summary}))
    else:
        details = _range_details(model, result, config, args.forward)
        print(render_text(shown, result.findings, color=use_color(sys.stdout), details=details))
        print("\n".join(_range_notes(result, config)))
        if args.transcripts:
            print(f"transcripts written to {args.transcripts}")
    return _exit_code(result.findings, args.fail_on)


# --- demo --------------------------------------------------------------------

_DEMO_TOOLS = frozenset({"add", "search_notes"})


def _demo(args: argparse.Namespace) -> int:
    command = [sys.executable, "-m", "mcp_gauntlet.demo.trapdoor"]
    shown_command = ["python", *command[1:]]
    color = use_color(sys.stdout)

    print("Scanning Trapdoor, a deliberately malicious MCP server bundled with mcp-gauntlet.")
    print("Its tools do nothing. Only the manifest - the text a model reads - is hostile.\n")
    manifest = fetch_manifest(command)
    manifest.command = shown_command
    print(render_text(manifest, run_all(manifest), color=color))

    print("\n\nNow the rug pull. You approved those tools; the server relaunches and quietly changes them.")
    print("Compared against the manifest pinned a moment ago:\n")
    later = fetch_manifest(command, env={"TRAPDOOR_RUGPULL": "1"})
    later.command = shown_command
    drift = list(lockfile.diff(lockfile.build(manifest), later))
    print(render_text(later, drift, color=color, only_flagged=True))

    spec = args.model or os.environ.get("GAUNTLET_MODEL")
    if not spec:
        print("\n\nThere is a third act: hand Trapdoor to a real agent and watch what it does with planted secrets.")
        print("It needs a model:     gauntlet demo --model ollama:llama3.1")
    else:
        model = resolve_model(spec, args.base_url)
        config = RangeConfig(trials=2 if args.trials is None else args.trials, only=_DEMO_TOOLS)
        print(f"\n\nNow the live range. {model.label} plays an assistant with a workspace full of planted secrets")
        print("and is asked to use two of Trapdoor's tools. search_notes passed the static scan above:")
        print("its description is clean. Watch what its results make the agent do.\n")
        with StdioClient(command) as client:
            live = client.read_manifest()
            result = run_range(live, model, load_corpus(), config, forward=client.call_tool, progress=_progress)
        live.command = shown_command
        details = _range_details(model, result, config, forwarded=True)
        print()
        print(render_text(_tested(live, config), result.findings, color=color, details=details))
        print("\n".join(_range_notes(result, config)))

    print("\nScan a real server:   gauntlet probe -- <command that launches it>")
    print("Pin what you approve: gauntlet pin   -- <command that launches it>")
    print("Test it on an agent:  gauntlet run --model <provider:model> -- <command that launches it>")
    return EXIT_OK


def _rules() -> int:
    for found in sorted(RULES.values(), key=lambda r: r.id):
        print(f"{found.id}  {found.severity.label:<8}  {found.title}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Everything after the first `--` belongs to the server, not to us.
    command: list[str] = []
    if "--" in argv:
        split = argv.index("--")
        argv, command = argv[:split], argv[split + 1 :]

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        os.system("")  # switches the legacy Windows console into ANSI mode

    args = _parser().parse_args(argv)
    try:
        if args.action == "probe":
            return _probe(args, command)
        if args.action == "pin":
            return _pin(args, command)
        if args.action == "run":
            return _run(args, command)
        if args.action == "demo":
            return _demo(args)
        return _rules()
    except (MCPError, ModelError, ValueError, OSError) as exc:
        print(f"gauntlet: {exc}", file=sys.stderr)
        return EXIT_ERROR
