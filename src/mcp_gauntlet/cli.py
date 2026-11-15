"""Command-line entry point: `gauntlet probe | pin | demo | rules`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, lockfile
from .client import MCPError, fetch_manifest
from .manifest import Manifest
from .report import render_json, render_text, use_color
from .rules import RULES, Severity, run_all

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

_EPILOG = """\
examples:
  gauntlet demo
  gauntlet probe -- npx -y some-mcp-server@1.4.2 ./workspace
  gauntlet pin   -- uvx some-mcp-server==1.4.2
  gauntlet probe --manifest tools.json --json

Everything after `--` is the command that launches the server. Probing a server
runs it: treat an untrusted server like any other untrusted program.
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gauntlet",
        description="Lint MCP tool manifests for prompt injection and pin them against rug pulls.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"mcp-gauntlet {__version__}")
    sub = parser.add_subparsers(dest="action", required=True)

    source = argparse.ArgumentParser(add_help=False)
    source.add_argument("--manifest", metavar="FILE", help="lint a saved tools/list result instead of launching a server")
    source.add_argument("--lockfile", metavar="PATH", default=lockfile.DEFAULT_PATH, help="default: %(default)s")
    source.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS", help="per request, default: %(default)g")
    source.add_argument("-e", "--env", action="append", default=[], metavar="KEY=VALUE", help="extra environment for the server")

    probe = sub.add_parser("probe", parents=[source], help="scan a server and check it against the lockfile")
    probe.add_argument("--json", action="store_true", help="machine-readable output")
    probe.add_argument("--no-lock", action="store_true", help="skip the drift check even if a lockfile exists")
    probe.add_argument(
        "--fail-on",
        default="high",
        choices=[s.label for s in Severity],
        help="exit 1 if any finding is at least this severe (default: %(default)s)",
    )

    sub.add_parser("pin", parents=[source], help="record the current manifest in the lockfile")
    sub.add_parser("demo", help="scan Trapdoor, the bundled malicious server (no setup needed)")
    sub.add_parser("rules", help="list every rule")
    return parser


def _load(args: argparse.Namespace, command: list[str]) -> Manifest:
    if args.manifest:
        if command:
            raise ValueError("give either --manifest or a server command, not both")
        return Manifest.from_json(json.loads(Path(args.manifest).read_text(encoding="utf-8")))
    if not command:
        raise ValueError("no server to scan: pass a launch command after `--`, or --manifest FILE")
    env = {}
    for pair in args.env:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise ValueError(f"--env expects KEY=VALUE, got: {pair}")
        env[key] = value
    return fetch_manifest(command, env=env, timeout=args.timeout)


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

    threshold = Severity.parse(args.fail_on)
    return EXIT_FINDINGS if any(f.severity >= threshold for f in findings) else EXIT_OK


def _pin(args: argparse.Namespace, command: list[str]) -> int:
    manifest = _load(args, command)
    lock_path = Path(args.lockfile)
    lockfile.write(lock_path, manifest)
    print(f"pinned {len(manifest.tools)} tools to {lock_path}")
    print("commit it: a changed tool definition will now fail `gauntlet probe`")
    return EXIT_OK


def _demo() -> int:
    command = [sys.executable, "-m", "mcp_gauntlet.demo.trapdoor"]
    color = use_color(sys.stdout)

    print("Scanning Trapdoor, a deliberately malicious MCP server bundled with mcp-gauntlet.")
    print("Its tools do nothing. Only the manifest - the text a model reads - is hostile.\n")
    manifest = fetch_manifest(command)
    manifest.command = ["python", *command[1:]]
    print(render_text(manifest, run_all(manifest), color=color))

    print("\n\nNow the rug pull. You approved those tools; the server relaunches and quietly changes them.")
    print("Compared against the manifest pinned a moment ago:\n")
    later = fetch_manifest(command, env={"TRAPDOOR_RUGPULL": "1"})
    later.command = manifest.command
    drift = list(lockfile.diff(lockfile.build(manifest), later))
    print(render_text(later, drift, color=color, only_flagged=True))

    print("\nScan a real server:   gauntlet probe -- <command that launches it>")
    print("Pin what you approve: gauntlet pin   -- <command that launches it>")
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
        if args.action == "demo":
            return _demo()
        return _rules()
    except (MCPError, ValueError, OSError) as exc:
        print(f"gauntlet: {exc}", file=sys.stderr)
        return EXIT_ERROR
