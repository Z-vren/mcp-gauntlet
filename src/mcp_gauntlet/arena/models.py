"""The model that plays the canary agent.

A backend owns its conversation in the provider's native format. That is not
just tidiness: Claude's thinking blocks have to be sent back exactly as they
arrived, which a lowest-common-denominator message list cannot promise.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

_MAX_TOKENS = 16000


class ModelError(Exception):
    """The model could not be reached or would not answer."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema: dict


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class Reply:
    text: str = ""
    calls: list[ToolCall] = field(default_factory=list)
    refused: bool = False  # the provider's safety layer declined; there is nothing to act on


class Conversation(Protocol):
    def send(self, text: str) -> None:
        """Add a user turn."""

    def step(self) -> Reply:
        """Ask the model for its next turn."""

    def results(self, results: list[tuple[ToolCall, str]]) -> None:
        """Answer every tool call from the last step, in one go."""


class Model(Protocol):
    label: str

    def start(self, system: str, tools: list[ToolSpec], history: list[tuple[str, str]]) -> Conversation:
        """Open a conversation. `history` is earlier (role, text) turns to seed it with."""


# --- Claude ------------------------------------------------------------------


class AnthropicModel:
    """Claude, through the official SDK (an optional extra, imported only when used)."""

    def __init__(self, model: str):
        try:
            import anthropic
        except ImportError as exc:
            raise ModelError('the Claude backend needs the Anthropic SDK: pip install "mcp-gauntlet[anthropic]"') from exc
        self.sdk = anthropic
        # Resolves credentials itself: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile.
        self.client = anthropic.Anthropic()
        self.model = model
        self.label = f"anthropic:{model}"

    def start(self, system: str, tools: list[ToolSpec], history: list[tuple[str, str]]) -> Conversation:
        return _AnthropicConversation(self, system, tools, history)


class _AnthropicConversation:
    def __init__(self, owner: AnthropicModel, system: str, tools: list[ToolSpec], history: list[tuple[str, str]]):
        self._owner = owner
        self._system = system
        self._tools = [{"name": t.name, "description": t.description, "input_schema": t.schema} for t in tools]
        self._messages: list[dict] = [{"role": role, "content": text} for role, text in history]

    def send(self, text: str) -> None:
        self._messages.append({"role": "user", "content": text})

    def step(self) -> Reply:
        sdk, model = self._owner.sdk, self._owner.model
        try:
            # No thinking, effort, sampling or tool_choice settings: the agent runs on the
            # model's defaults, which is what an off-the-shelf client would give it.
            response = self._owner.client.messages.create(
                model=model,
                max_tokens=_MAX_TOKENS,
                system=self._system,
                tools=self._tools,
                messages=self._messages,
            )
        except sdk.AuthenticationError as exc:
            raise ModelError("the Claude API rejected the credentials: set ANTHROPIC_API_KEY or run `ant auth login`") from exc
        except sdk.NotFoundError as exc:
            raise ModelError(f"the Claude API does not know the model {model!r}") from exc
        except sdk.BadRequestError as exc:
            raise ModelError(f"the Claude API rejected the request: {exc.message}") from exc
        except sdk.RateLimitError as exc:
            raise ModelError("rate limited by the Claude API, even after retries") from exc
        except sdk.APIStatusError as exc:
            raise ModelError(f"Claude API error {exc.status_code}: {exc.message}") from exc
        except sdk.APIConnectionError as exc:
            raise ModelError("could not reach the Claude API") from exc

        # A refusal has no content worth reading, so it is checked first and never replayed.
        if response.stop_reason == "refusal":
            return Reply(refused=True)

        # Appended untouched: thinking blocks are only valid if they go back exactly as they came.
        self._messages.append({"role": "assistant", "content": response.content})
        return Reply(
            text="".join(block.text for block in response.content if block.type == "text"),
            calls=[
                ToolCall(block.id, block.name, dict(block.input))
                for block in response.content
                if block.type == "tool_use"
            ],
        )

    def results(self, results: list[tuple[ToolCall, str]]) -> None:
        # All results in a single user message, or the model learns to stop calling tools in parallel.
        self._messages.append(
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": call.id, "content": text} for call, text in results],
            }
        )


# --- anything that speaks the OpenAI chat-completions dialect ----------------


class OpenAICompatModel:
    """Ollama, LM Studio, vLLM, OpenAI: one small HTTP client covers all of them."""

    def __init__(self, model: str, base_url: str, *, api_key: str | None = None, label: str | None = None, timeout: float = 600.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.label = label or f"openai:{model}"

    def start(self, system: str, tools: list[ToolSpec], history: list[tuple[str, str]]) -> Conversation:
        return _OpenAICompatConversation(self, system, tools, history)

    def post(self, body: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=json.dumps(body).encode("utf-8"), headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300].strip()
            raise ModelError(f"{self.label} answered HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ModelError(f"could not reach {self.base_url}: {getattr(exc, 'reason', exc)}") from exc
        except ValueError as exc:
            raise ModelError(f"{self.label} did not answer with JSON") from exc


class _OpenAICompatConversation:
    def __init__(self, owner: OpenAICompatModel, system: str, tools: list[ToolSpec], history: list[tuple[str, str]]):
        self._owner = owner
        self._tools = [
            {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.schema}}
            for t in tools
        ]
        self._messages: list[dict] = [{"role": "system", "content": system}]
        self._messages += [{"role": role, "content": text} for role, text in history]
        self._calls = 0

    def send(self, text: str) -> None:
        self._messages.append({"role": "user", "content": text})

    def step(self) -> Reply:
        data = self._owner.post({"model": self._owner.model, "messages": self._messages, "tools": self._tools})
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelError(f"{self._owner.label} sent a response with no message in it") from exc

        raw_calls = message.get("tool_calls") or []
        text = message.get("content") or ""
        if message.get("refusal") and not text and not raw_calls:
            return Reply(refused=True)

        calls = []
        for raw in raw_calls:
            function = raw.get("function") or {}
            self._calls += 1
            # Some servers omit ids; the id only has to match between the call and its result.
            raw.setdefault("id", f"call_{self._calls}")
            calls.append(ToolCall(raw["id"], str(function.get("name", "")), _arguments(function.get("arguments"))))

        replay: dict = {"role": "assistant", "content": text}
        if raw_calls:
            replay["tool_calls"] = raw_calls
        self._messages.append(replay)
        return Reply(text=text, calls=calls)

    def results(self, results: list[tuple[ToolCall, str]]) -> None:
        for call, text in results:
            self._messages.append({"role": "tool", "tool_call_id": call.id, "content": text})


def _arguments(raw: object) -> dict:
    """Tool arguments arrive as a JSON string from OpenAI and as an object from some local servers."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"_unparsed": raw}
        return parsed if isinstance(parsed, dict) else {"_unparsed": raw}
    return {}


# --- choosing one ------------------------------------------------------------

_HELP = (
    "pick the model that plays the agent with --model (or GAUNTLET_MODEL), for example:\n"
    "  --model ollama:llama3.1              a local model, free\n"
    "  --model anthropic:claude-opus-5-5    needs the extra: pip install \"mcp-gauntlet[anthropic]\"\n"
    "  --model openai:<model> --base-url http://localhost:1234/v1    any OpenAI-compatible server"
)


def resolve_model(spec: str | None, base_url: str | None = None) -> Model:
    """Turn `provider:model` into a backend."""
    if not spec:
        raise ModelError(f"no model chosen. {_HELP}")
    provider, sep, name = spec.partition(":")
    if not sep or not name:
        raise ModelError(f"--model expects provider:model, got {spec!r}. {_HELP}")

    if provider == "anthropic":
        return AnthropicModel(name)
    if provider == "ollama":
        host = os.environ.get("OLLAMA_HOST") or "localhost:11434"
        if "://" not in host:
            host = f"http://{host}"
        return OpenAICompatModel(name, base_url or f"{host.rstrip('/')}/v1", label=spec)
    if provider == "openai":
        return OpenAICompatModel(
            name, base_url or "https://api.openai.com/v1", api_key=os.environ.get("OPENAI_API_KEY"), label=spec
        )
    raise ModelError(f"unknown provider {provider!r}. {_HELP}")
