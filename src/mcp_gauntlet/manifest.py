"""The tool manifest a server advertises, normalised for linting and pinning."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterator

# Fields a model (or a client's approval UI) actually sees. Anything else in a
# tool definition is ignored when hashing, so cosmetic churn does not read as drift.
HASHED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

# JSON Schema keys whose string values end up in the model's context.
_TEXT_KEYS = ("description", "title", "default", "const")
_TEXT_LIST_KEYS = ("enum", "examples")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


@dataclass(frozen=True)
class TextField:
    """One piece of model-visible text and where it lives in the tool definition."""

    location: str
    text: str


@dataclass(frozen=True)
class Parameter:
    path: str  # dotted path from the schema root, e.g. "options.callback_url"
    name: str  # the last segment
    schema: dict


def _walk_text(node: Any, path: str) -> Iterator[TextField]:
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}"
            if key in _TEXT_KEYS and isinstance(value, str):
                yield TextField(here, value)
            elif key in _TEXT_LIST_KEYS and isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        yield TextField(f"{here}[{i}]", item)
            else:
                yield from _walk_text(value, here)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_text(item, f"{path}[{i}]")


def _walk_params(schema: Any, prefix: str = "") -> Iterator[Parameter]:
    if not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            if isinstance(sub, dict):
                yield Parameter(prefix + name, name, sub)
                yield from _walk_params(sub, f"{prefix}{name}.")
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _walk_params(items, (prefix[:-1] if prefix else "") + "[].")
    for key in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(key) or []:
            yield from _walk_params(sub, prefix)


@dataclass
class Tool:
    raw: dict

    @property
    def name(self) -> str:
        return str(self.raw.get("name", ""))

    @property
    def description(self) -> str:
        return str(self.raw.get("description") or "")

    @property
    def input_schema(self) -> dict:
        schema = self.raw.get("inputSchema")
        return schema if isinstance(schema, dict) else {}

    @property
    def annotations(self) -> dict:
        ann = self.raw.get("annotations")
        return ann if isinstance(ann, dict) else {}

    def text_fields(self) -> Iterator[TextField]:
        """Every string in this tool that is shown to the model."""
        if self.description:
            yield TextField("description", self.description)
        title = self.raw.get("title")
        if isinstance(title, str) and title:
            yield TextField("title", title)
        ann_title = self.annotations.get("title")
        if isinstance(ann_title, str) and ann_title:
            yield TextField("annotations.title", ann_title)
        yield from _walk_text(self.input_schema, "inputSchema")

    def parameters(self) -> Iterator[Parameter]:
        yield from _walk_params(self.input_schema)

    def pinned_view(self) -> dict:
        return {k: self.raw[k] for k in HASHED_FIELDS if k in self.raw}

    def digest(self) -> str:
        return sha256(self.pinned_view())


@dataclass
class Manifest:
    tools: list[Tool]
    server_name: str = ""
    server_version: str = ""
    instructions: str = ""
    command: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Any) -> "Manifest":
        """Load a saved manifest: either a bare list of tools or a `tools/list` result."""
        if isinstance(data, list):
            data = {"tools": data}
        if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
            raise ValueError('expected a JSON list of tools or an object with a "tools" list')
        info = data.get("serverInfo") if isinstance(data.get("serverInfo"), dict) else {}
        return cls(
            tools=[Tool(t) for t in data["tools"] if isinstance(t, dict)],
            server_name=str(info.get("name", "")),
            server_version=str(info.get("version", "")),
            instructions=str(data.get("instructions") or ""),
        )
