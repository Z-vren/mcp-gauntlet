"""Model backends, against a local HTTP stub and a stand-in for the Anthropic SDK. No network, no keys."""

from __future__ import annotations

import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from mcp_gauntlet.arena import ModelError, ToolCall, ToolSpec, resolve_model
from mcp_gauntlet.arena.models import AnthropicModel, OpenAICompatModel

TOOLS = [ToolSpec("add", "Add two numbers.", {"type": "object", "properties": {"a": {"type": "number"}}})]
HISTORY = [("user", "Remember 42."), ("assistant", "Noted.")]


# --- OpenAI-compatible -------------------------------------------------------


@pytest.fixture
def chat_server():
    """A chat-completions endpoint that records requests and plays back queued replies."""
    state = SimpleNamespace(requests=[], headers=[], replies=[])

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.requests.append(body)
            state.headers.append(dict(self.headers))
            status, payload = state.replies.pop(0)
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{server.server_address[1]}/v1"
    yield state
    server.shutdown()
    server.server_close()


def assistant(content=None, tool_calls=None, **extra):
    return 200, {"choices": [{"message": {"role": "assistant", "content": content, "tool_calls": tool_calls, **extra}}]}


def test_openai_round_trip(chat_server):
    chat_server.replies += [
        assistant(tool_calls=[{"id": "c1", "type": "function", "function": {"name": "add", "arguments": '{"a": 2}'}}]),
        assistant(content="It returned 4."),
    ]
    conversation = OpenAICompatModel("m1", chat_server.url).start("Be helpful.", TOOLS, HISTORY)
    conversation.send("Add 2 and 2.")

    first = conversation.step()
    assert first.calls == [ToolCall("c1", "add", {"a": 2})]
    conversation.results([(first.calls[0], "4")])
    second = conversation.step()
    assert (second.text, second.calls) == ("It returned 4.", [])

    opening, followup = chat_server.requests
    assert opening["model"] == "m1"
    assert opening["tools"] == [
        {"type": "function", "function": {"name": "add", "description": "Add two numbers.", "parameters": TOOLS[0].schema}}
    ]
    assert [m["role"] for m in opening["messages"]] == ["system", "user", "assistant", "user"]
    assert set(opening) == {"model", "messages", "tools"}  # no sampling overrides
    # The assistant's tool call is replayed, followed by one tool message per call.
    assert followup["messages"][-2]["tool_calls"][0]["id"] == "c1"
    assert followup["messages"][-1] == {"role": "tool", "tool_call_id": "c1", "content": "4"}


def test_openai_arguments_as_object_and_missing_ids(chat_server):
    chat_server.replies += [assistant(tool_calls=[{"function": {"name": "add", "arguments": {"a": 1}}}, {"function": {"name": "add", "arguments": "not json"}}])]
    conversation = OpenAICompatModel("m1", chat_server.url).start("s", TOOLS, [])
    conversation.send("go")
    first, second = conversation.step().calls
    assert first.arguments == {"a": 1} and second.arguments == {"_unparsed": "not json"}
    assert first.id != second.id


def test_openai_sends_the_key_only_when_there_is_one(chat_server):
    chat_server.replies += [assistant(content="hi"), assistant(content="hi")]
    for key in (None, "test-key"):
        conversation = OpenAICompatModel("m1", chat_server.url, api_key=key).start("s", TOOLS, [])
        conversation.send("go")
        conversation.step()
    assert "Authorization" not in chat_server.headers[0]
    assert chat_server.headers[1]["Authorization"] == "Bearer test-key"


def test_openai_refusal(chat_server):
    chat_server.replies += [assistant(refusal="I can't help with that.")]
    conversation = OpenAICompatModel("m1", chat_server.url).start("s", TOOLS, [])
    conversation.send("go")
    assert conversation.step().refused


@pytest.mark.parametrize(
    "reply, message",
    [
        ((500, {"error": "model crashed"}), "HTTP 500: .*model crashed"),
        ((200, b"<html>gateway</html>"), "did not answer with JSON"),
        ((200, {"choices": []}), "no message in it"),
    ],
)
def test_openai_failures_become_model_errors(chat_server, reply, message):
    chat_server.replies.append(reply)
    conversation = OpenAICompatModel("m1", chat_server.url, label="ollama:m1").start("s", TOOLS, [])
    conversation.send("go")
    with pytest.raises(ModelError, match=message):
        conversation.step()


def test_openai_unreachable():
    conversation = OpenAICompatModel("m1", "http://127.0.0.1:9/v1", timeout=2).start("s", TOOLS, [])
    conversation.send("go")
    with pytest.raises(ModelError, match="could not reach"):
        conversation.step()


# --- choosing a backend ------------------------------------------------------


def test_resolve_ollama(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    model = resolve_model("ollama:llama3.1:8b")
    assert (model.model, model.base_url, model.label) == ("llama3.1:8b", "http://localhost:11434/v1", "ollama:llama3.1:8b")

    monkeypatch.setenv("OLLAMA_HOST", "gpu-box:11434")
    assert resolve_model("ollama:llama3.1").base_url == "http://gpu-box:11434/v1"


def test_resolve_openai_compatible(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    model = resolve_model("openai:local-model", "http://localhost:1234/v1/")
    assert (model.base_url, model.api_key) == ("http://localhost:1234/v1", "test-key")


@pytest.mark.parametrize("spec, message", [(None, "no model chosen"), ("llama3.1", "expects provider:model"), ("acme:x", "unknown provider")])
def test_resolve_rejects_bad_specs(spec, message):
    with pytest.raises(ModelError, match=message):
        resolve_model(spec)


def test_claude_backend_explains_the_missing_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)  # makes `import anthropic` fail
    with pytest.raises(ModelError, match=r"pip install \"mcp-gauntlet\[anthropic\]\""):
        resolve_model("anthropic:claude-opus-5-5")


# --- Claude ------------------------------------------------------------------


@pytest.fixture
def fake_sdk(monkeypatch):
    """Just enough of the `anthropic` package's surface for the backend to run against."""
    sdk = types.ModuleType("anthropic")

    class APIStatusError(Exception):
        def __init__(self, message="boom", status_code=500):
            super().__init__(message)
            self.message, self.status_code = message, status_code

    sdk.APIStatusError = APIStatusError
    for name in ("AuthenticationError", "NotFoundError", "BadRequestError", "RateLimitError"):
        setattr(sdk, name, type(name, (APIStatusError,), {}))
    sdk.APIConnectionError = type("APIConnectionError", (Exception,), {})

    state = SimpleNamespace(calls=[], replies=[])

    def create(**kwargs):
        # Snapshot the list: the backend keeps appending to the same one.
        state.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        reply = state.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    sdk.Anthropic = lambda: SimpleNamespace(messages=SimpleNamespace(create=create))
    monkeypatch.setitem(sys.modules, "anthropic", sdk)
    state.sdk = sdk
    return state


def message(*blocks, stop_reason="end_turn"):
    return SimpleNamespace(stop_reason=stop_reason, content=list(blocks))


def test_claude_round_trip(fake_sdk):
    thinking = SimpleNamespace(type="thinking", thinking="", signature="sig")
    tool_use = SimpleNamespace(type="tool_use", id="toolu_1", name="add", input={"a": 2})
    turn = message(thinking, SimpleNamespace(type="text", text="Adding."), tool_use, stop_reason="tool_use")
    fake_sdk.replies += [turn, message(SimpleNamespace(type="text", text="It returned 4."))]

    model = AnthropicModel("claude-opus-5-5")
    assert model.label == "anthropic:claude-opus-5-5"
    conversation = model.start("Be helpful.", TOOLS, HISTORY)
    conversation.send("Add 2 and 2.")

    first = conversation.step()
    assert (first.text, first.calls) == ("Adding.", [ToolCall("toolu_1", "add", {"a": 2})])
    conversation.results([(first.calls[0], "4")])
    assert conversation.step().text == "It returned 4."

    opening, followup = fake_sdk.calls
    # Model defaults only: nothing that newer models reject (thinking config, sampling, forced tool choice).
    assert set(opening) == {"model", "max_tokens", "system", "tools", "messages"}
    assert (opening["model"], opening["system"]) == ("claude-opus-5-5", "Be helpful.")
    assert opening["tools"] == [{"name": "add", "description": "Add two numbers.", "input_schema": TOOLS[0].schema}]
    assert [m["role"] for m in opening["messages"]] == ["user", "assistant", "user"]
    # The assistant turn goes back as the very same content list, thinking block included.
    assert followup["messages"][-2] == {"role": "assistant", "content": turn.content}
    assert followup["messages"][-2]["content"] is turn.content
    assert followup["messages"][-1] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "4"}],
    }


def test_claude_parallel_tool_results_share_one_message(fake_sdk):
    calls = [SimpleNamespace(type="tool_use", id=f"toolu_{i}", name="add", input={"a": i}) for i in (1, 2)]
    fake_sdk.replies += [message(*calls, stop_reason="tool_use"), message(SimpleNamespace(type="text", text="ok"))]
    conversation = AnthropicModel("claude-opus-5-5").start("s", TOOLS, [])
    conversation.send("go")
    conversation.results([(call, "r") for call in conversation.step().calls])
    conversation.step()
    assert [block["tool_use_id"] for block in fake_sdk.calls[1]["messages"][-1]["content"]] == ["toolu_1", "toolu_2"]


def test_claude_refusal_is_reported_and_not_replayed(fake_sdk):
    fake_sdk.replies += [message(stop_reason="refusal")]
    conversation = AnthropicModel("claude-opus-5-5").start("s", TOOLS, [])
    conversation.send("go")
    assert conversation.step().refused
    assert conversation._messages == [{"role": "user", "content": "go"}]


@pytest.mark.parametrize(
    "error, message_text",
    [
        ("AuthenticationError", "rejected the credentials"),
        ("NotFoundError", "does not know the model 'claude-opus-5-5'"),
        ("BadRequestError", "rejected the request: boom"),
        ("RateLimitError", "rate limited"),
        ("APIStatusError", "Claude API error 500: boom"),
        ("APIConnectionError", "could not reach the Claude API"),
    ],
)
def test_claude_errors_are_told_apart(fake_sdk, error, message_text):
    fake_sdk.replies.append(getattr(fake_sdk.sdk, error)())
    conversation = AnthropicModel("claude-opus-5-5").start("s", TOOLS, [])
    conversation.send("go")
    with pytest.raises(ModelError, match=message_text):
        conversation.step()
