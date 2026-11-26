from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def clear_identity_url_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTH_URL", raising=False)
    monkeypatch.delenv("IDENTITY_URL", raising=False)
