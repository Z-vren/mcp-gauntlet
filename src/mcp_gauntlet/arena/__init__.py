"""The dynamic range: a canary agent, a sandbox full of planted secrets, and a server to test."""

from __future__ import annotations

from .models import Model, ModelError, Reply, ToolCall, ToolSpec, resolve_model
from .runner import RangeConfig, RangeResult, Trial, run_range, write_transcripts
from .world import Corpus, World, load_corpus

__all__ = [
    "Corpus",
    "Model",
    "ModelError",
    "RangeConfig",
    "RangeResult",
    "Reply",
    "ToolCall",
    "ToolSpec",
    "Trial",
    "World",
    "load_corpus",
    "resolve_model",
    "run_range",
    "write_transcripts",
]
