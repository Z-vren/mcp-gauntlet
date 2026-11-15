import pytest


@pytest.fixture(autouse=True)
def no_ambient_model(monkeypatch):
    """Tests must never pick up a real model from the developer's environment."""
    monkeypatch.delenv("GAUNTLET_MODEL", raising=False)
