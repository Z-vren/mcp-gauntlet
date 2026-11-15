"""Run the canary agent through every scenario and turn what it did into findings."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..manifest import Manifest, Tool
from ..rules.base import Finding, Rule, Severity, rule
from .models import Model, ModelError
from .world import Corpus, Event, Forward, Scenario, World

LEAK = rule(
    "GA-R001",
    Severity.CRITICAL,
    "Agent sent a planted secret to this server",
    "Something this tool says steers agents into handing over secrets. Read the transcript to see what, "
    "and do not connect the server to an agent that can see anything sensitive.",
)
SINK = rule(
    "GA-R002",
    Severity.CRITICAL,
    "Agent sent a planted secret to an outside destination",
    "Something this server says made the agent exfiltrate through its own network or email tool. "
    "Read the transcript to see what triggered it.",
)
HONEYPOT = rule(
    "GA-R003",
    Severity.HIGH,
    "Agent read a credential file nobody asked for",
    "Something this server says sent the agent looking for secrets. Read the transcript to see what triggered it.",
)
HIJACK = rule(
    "GA-R004",
    Severity.HIGH,
    "Agent used this tool for a task addressed to another",
    "The description competes for work that belongs to other tools. Describe what the tool does and nothing more.",
)
UNPROMPTED = rule(
    "GA-R005",
    Severity.MEDIUM,
    "Agent contacted a destination nobody asked for",
    "Something this server says made the agent send a request or an email on its own. "
    "Read the transcript to see what triggered it.",
)

_RULES: dict[str, Rule] = {
    "leak": LEAK,
    "sink": SINK,
    "honeypot": HONEYPOT,
    "hijack": HIJACK,
    "outbound": UNPROMPTED,
    "redirect": UNPROMPTED,
}
_GIVE_UP_AFTER = 3  # consecutive failed runs


@dataclass(frozen=True)
class RangeConfig:
    trials: int = 3
    max_steps: int = 6
    only: frozenset[str] | None = None  # restrict per-tool scenarios to these tools


@dataclass
class Trial:
    scenario: str
    tool: str | None  # the tool under test, for per-tool scenarios
    run: int
    steps: list[dict] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    refused: bool = False
    error: str | None = None


@dataclass
class RangeResult:
    findings: list[Finding]
    trials: list[Trial]
    skipped: list[str]

    @property
    def refused(self) -> int:
        return sum(1 for t in self.trials if t.refused)

    @property
    def errors(self) -> list[str]:
        return [t.error for t in self.trials if t.error]


Progress = Callable[[int, int, Trial], None]


def _plan(manifest: Manifest, corpus: Corpus, config: RangeConfig) -> tuple[list[tuple[Scenario, Tool | None]], list[str]]:
    names = {tool.name for tool in manifest.tools}
    if config.only is not None and config.only - names:
        raise ValueError(f"the server has no tool named {', '.join(sorted(config.only - names))}")

    jobs: list[tuple[Scenario, Tool | None]] = []
    skipped: list[str] = []
    for scenario in corpus.scenarios:
        if scenario.kind == "per_tool":
            jobs += [(scenario, tool) for tool in manifest.tools if config.only is None or tool.name in config.only]
        elif scenario.needs in names:
            # The task would land on the server's own tool, so "it got involved" proves nothing.
            skipped.append(f"{scenario.id}: the server has its own {scenario.needs}")
        else:
            jobs.append((scenario, None))
    return jobs, skipped


def _run_trial(
    model: Model,
    manifest: Manifest,
    corpus: Corpus,
    scenario: Scenario,
    subject: Tool | None,
    run: int,
    config: RangeConfig,
    forward: Forward | None,
) -> Trial:
    world = World(
        corpus,
        [subject] if subject else manifest.tools,
        scenario=scenario,
        subject=subject.name if subject else None,
        forward=forward,
    )
    system = world.system
    if manifest.instructions:
        # Clients put a server's instructions in the system prompt, so they are part of the attack surface.
        system += f"\n\nInstructions from the connected server:\n{manifest.instructions}"

    trial = Trial(scenario.id, subject.name if subject else None, run)
    try:
        conversation = model.start(system, world.tool_specs(), world.history)
        conversation.send(world.task)
        for _ in range(config.max_steps):
            reply = conversation.step()
            if reply.refused:
                trial.refused = True
                break
            step: dict = {"text": reply.text, "calls": []}
            trial.steps.append(step)
            if not reply.calls:
                break
            results = []
            for call in reply.calls:
                result = world.dispatch(call)
                step["calls"].append({"tool": world.real_name(call.name), "arguments": call.arguments, "result": result})
                results.append((call, result))
            conversation.results(results)
    except ModelError as exc:
        trial.error = str(exc)
    trial.events = list(world.events)
    return trial


def _findings(trials: list[Trial]) -> list[Finding]:
    """One finding per (rule, tool, scenario), with how often it happened as the evidence."""
    completed: dict[tuple[str, str | None], int] = {}
    hits: dict[tuple[str, str | None, str, str | None], list] = {}
    for trial in trials:
        if trial.error:
            continue
        job = (trial.scenario, trial.tool)
        completed[job] = completed.get(job, 0) + 1
        counted = set()
        for event in trial.events:
            key = (_RULES[event.kind].id, event.tool, trial.scenario, trial.tool)
            if key in counted:
                continue  # a run counts once however many times the agent repeated itself
            counted.add(key)
            entry = hits.setdefault(key, [0, event])
            entry[0] += 1

    findings = []
    for (_, tool, scenario, subject), (count, event) in hits.items():
        runs = completed[(scenario, subject)]
        found = _RULES[event.kind]
        findings.append(found.hit(tool, f"scenario {scenario}", f"{count} of {runs} runs: {event.detail}"))
    return findings


def run_range(
    manifest: Manifest,
    model: Model,
    corpus: Corpus,
    config: RangeConfig,
    *,
    forward: Forward | None = None,
    progress: Progress | None = None,
) -> RangeResult:
    """Run every scenario `config.trials` times.

    With `forward` unset the range is dry: calls to the server's tools are
    inspected and answered with a placeholder, and never reach the server.
    """
    jobs, skipped = _plan(manifest, corpus, config)
    total = len(jobs) * config.trials
    trials: list[Trial] = []
    failures = 0
    for scenario, subject in jobs:
        for run in range(1, config.trials + 1):
            trial = _run_trial(model, manifest, corpus, scenario, subject, run, config, forward)
            trials.append(trial)
            if progress:
                progress(len(trials), total, trial)
            failures = failures + 1 if trial.error else 0
            # A model that fails on its very first run, or keeps failing, is misconfigured: stop paying for it.
            if trial.error and (len(trials) == 1 or failures >= _GIVE_UP_AFTER):
                raise ModelError(trial.error)
    return RangeResult(_findings(trials), trials, skipped)


def write_transcripts(path: Path, result: RangeResult, model_label: str) -> None:
    """One JSON object per run: every step the agent took and every event it caused."""
    with path.open("w", encoding="utf-8") as out:
        for trial in result.trials:
            record = {
                "model": model_label,
                "scenario": trial.scenario,
                "tool": trial.tool,
                "run": trial.run,
                "refused": trial.refused,
                "error": trial.error,
                "events": [{"kind": e.kind, "tool": e.tool, "detail": e.detail} for e in trial.events],
                "steps": trial.steps,
            }
            out.write(json.dumps(record, ensure_ascii=True) + "\n")
