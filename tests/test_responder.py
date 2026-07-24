import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "services" / "responder" / "handler.py"
SPEC = importlib.util.spec_from_file_location("responder", MODULE_PATH)
responder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(responder)


def test_response_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("RESPONSE_MODE", raising=False)
    with pytest.raises(PermissionError):
        responder._authorize(
            {
                "action": "disable_access_key",
                "account_id": "123456789012",
                "approval": {"status": "approved"},
            }
        )


def test_approval_and_account_are_required(monkeypatch):
    monkeypatch.setenv("RESPONSE_MODE", "enabled")
    monkeypatch.setenv("ALLOWED_ACCOUNTS", "123456789012")
    with pytest.raises(PermissionError):
        responder._authorize(
            {
                "action": "disable_access_key",
                "account_id": "123456789012",
                "approval": {"status": "pending"},
            }
        )
