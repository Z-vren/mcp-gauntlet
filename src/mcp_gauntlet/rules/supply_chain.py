"""How the server is launched: does the same command always run the same code?"""

from __future__ import annotations

import re
from typing import Iterator

from ..manifest import Manifest
from .base import Finding, Severity, rule

UNPINNED = rule(
    "GA-C001",
    Severity.HIGH,
    "Unpinned package launch",
    "Pin an exact version (pkg@1.2.3 / pkg==1.2.3). "
    "An unpinned launch runs whatever was published most recently, every time your client starts.",
)
MUTABLE_IMAGE = rule(
    "GA-C002",
    Severity.MEDIUM,
    "Mutable container image",
    "Pin the image by digest (image@sha256:...). Tags can be repointed at different code.",
)
REMOTE_SCRIPT = rule(
    "GA-C003",
    Severity.CRITICAL,
    "Remote script piped to a shell",
    "Download, review and vendor the script, then run the local copy.",
)

_EXTENSIONS = (".cmd", ".exe", ".bat", ".ps1")
_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][\w.+-]+)?")
_COMMIT = re.compile(r"[0-9a-f]{7,40}", re.IGNORECASE)
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(?:iex|invoke-expression)\b",
    re.IGNORECASE,
)

_PY_VALUE_FLAGS = {
    "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url",
    "--with-editable", "--with-requirements",
}  # fmt: skip
_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "-w",
    "--workdir", "-u", "--user", "--mount", "--env-file", "--entrypoint", "-l", "--label",
    "--platform", "-m", "--memory", "--cpus", "-h", "--hostname", "--add-host", "--cap-add",
    "--cap-drop", "--security-opt", "--pull", "--restart", "--tmpfs", "--device", "--gpus",
    "--ulimit", "--dns",
}  # fmt: skip


def _exe(arg: str) -> str:
    name = re.split(r"[\\/]", arg)[-1].lower()
    for ext in _EXTENSIONS:
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def _is_local(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "file:")) or bool(re.match(r"[A-Za-z]:[\\/]", spec))


def _is_vcs(spec: str) -> bool:
    return spec.startswith(("git+", "github:", "git@", "http://", "https://"))


def _npm_specs(args: list[str]) -> list[str]:
    """Package specs an npx-style command will fetch."""
    specs: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--package") and i + 1 < len(args):
            specs.append(args[i + 1])
            i += 2
        elif arg.startswith("--package="):
            specs.append(arg.split("=", 1)[1])
            i += 1
        elif arg in ("-c", "--call"):
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            if not specs:
                specs.append(arg)  # the first positional is the package unless -p named one
            break
    return specs


def _npm_pinned(spec: str) -> bool:
    if _is_local(spec):
        return True
    if _is_vcs(spec):
        return bool(_COMMIT.fullmatch(spec.rpartition("#")[2])) if "#" in spec else False
    at = spec.rfind("@")
    return at > 0 and bool(_EXACT_VERSION.fullmatch(spec[at + 1 :]))


def _py_spec(args: list[str]) -> str | None:
    """The requirement a uvx / pipx-run command will install."""
    spec = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--from", "--spec") and i + 1 < len(args):
            spec = args[i + 1]  # an explicit source wins over the positional command name
            i += 2
        elif arg.startswith(("--from=", "--spec=")):
            spec = arg.split("=", 1)[1]
            i += 1
        elif arg in _PY_VALUE_FLAGS:
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            return spec or arg
    return spec


def _py_pinned(spec: str) -> bool:
    if _is_local(spec):
        return True
    if _is_vcs(spec):
        return bool(_COMMIT.fullmatch(spec.rpartition("@")[2]))
    if "==" in spec:
        return True
    at = spec.rfind("@")
    return at > 0 and bool(_EXACT_VERSION.fullmatch(spec[at + 1 :]))


def _docker_image(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _DOCKER_VALUE_FLAGS:
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            return arg
    return None


def check_command(argv: list[str]) -> Iterator[Finding]:
    if not argv:
        return
    exe, rest = _exe(argv[0]), argv[1:]

    match = _PIPE_TO_SHELL.search(" ".join(argv))
    if match:
        yield REMOTE_SCRIPT.hit(None, "launch command", match.group())

    npm_args = None
    if exe in ("npx", "bunx", "pnpx"):
        npm_args = rest
    elif (exe in ("pnpm", "yarn") and rest[:1] == ["dlx"]) or (exe == "npm" and rest[:1] in (["exec"], ["x"])):
        npm_args = rest[1:]
    if npm_args is not None:
        for spec in _npm_specs(npm_args):
            if not _npm_pinned(spec):
                yield UNPINNED.hit(None, "launch command", f"{exe} fetches {spec} with no exact version")

    py_args = None
    if exe == "uvx":
        py_args = rest
    elif exe == "uv" and rest[:2] == ["tool", "run"]:
        py_args = rest[2:]
    elif exe == "pipx" and rest[:1] == ["run"]:
        py_args = rest[1:]
    if py_args is not None:
        spec = _py_spec(py_args)
        if spec and not _py_pinned(spec):
            yield UNPINNED.hit(None, "launch command", f"{exe} installs {spec} with no exact version")

    if exe in ("docker", "podman") and "run" in rest:
        image = _docker_image(rest[rest.index("run") + 1 :])
        if image and "@sha256:" not in image:
            tag = image.rsplit("/", 1)[-1].partition(":")[2]
            if tag in ("", "latest"):
                yield MUTABLE_IMAGE.hit(None, "launch command", f"{image} resolves to whatever is newest")
            else:
                yield MUTABLE_IMAGE.hit(
                    None, "launch command", f"{image} is tagged but not pinned by digest", Severity.LOW
                )


def check(manifest: Manifest) -> Iterator[Finding]:
    yield from check_command(manifest.command)
