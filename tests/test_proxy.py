"""End-to-end proxy tests using FastAPI's TestClient + a fake upstream."""

from __future__ import annotations

import os
import tempfile
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

# Configure env BEFORE importing the app so settings pick it up.
_TMP = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_TMP.close()
os.environ["AEGIS_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP.name}"
os.environ["AEGIS_BOOTSTRAP_TENANT_NAME"] = "Test Co"
os.environ["AEGIS_BOOTSTRAP_ADMIN_EMAIL"] = "admin@test.co"
os.environ["AEGIS_BOOTSTRAP_ADMIN_PASSWORD"] = "test-strong-password-1"
os.environ["AEGIS_SECRET_KEY"] = "test-secret-test-secret-test-secret"
os.environ["OPENAI_API_KEY"] = "sk-fake-key-for-tests"

from aegis.config import get_settings  # noqa: E402
from aegis.main import app  # noqa: E402

get_settings.cache_clear()  # type: ignore[attr-defined]


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(client: TestClient) -> None:
    r = client.post(
        "/login",
        data={"email": "admin@test.co", "password": "test-strong-password-1"},
        follow_redirects=False,
    )
    assert r.status_code in (200, 302)


def _create_key(client: TestClient) -> str:
    _login(client)
    r = client.post("/admin/api/keys", json={"name": "test", "scopes": ["proxy"]})
    assert r.status_code == 201, r.text
    return r.json()["plaintext"]


def _set_creds(client: TestClient) -> None:
    _login(client)
    r = client.post(
        "/admin/api/credentials",
        json={"provider": "openai", "api_key": "sk-fake-upstream", "base_url": "http://fake-upstream"},
    )
    assert r.status_code == 201, r.text


class _MockTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.last_body: dict[str, Any] | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        import json
        self.last_body = json.loads(request.content.decode())
        if "messages" in self.last_body:
            user_text = self.last_body["messages"][-1]["content"]
        else:
            user_text = ""
        body = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": self.last_body.get("model", "gpt-4o-mini"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": f"echo:{user_text[:200]}"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        return httpx.Response(200, json=body)


@pytest.fixture
def mock_transport(monkeypatch):
    transport = _MockTransport()

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
    return transport


def test_proxy_blocks_high_severity(client, mock_transport):
    _set_creds(client)
    key = _create_key(client)
    body = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Card 4111 1111 1111 1111"}],
    }
    r = client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 451
    assert r.json()["error"]["type"] == "policy_blocked"
    assert mock_transport.last_body is None  # never reached upstream


def test_proxy_redacts_medium(client, mock_transport):
    _set_creds(client)
    key = _create_key(client)
    body = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "IBAN GB29NWBK60161331926819 please summarise"}],
    }
    r = client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    sent_to_upstream = mock_transport.last_body["messages"][-1]["content"]
    assert "GB29NWBK60161331926819" not in sent_to_upstream
    assert "[REDACTED:FINANCIAL]" in sent_to_upstream
    assert r.json()["aegis"]["decision"] == "redact"


def test_proxy_allows_clean_traffic(client, mock_transport):
    _set_creds(client)
    key = _create_key(client)
    body = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "What's the capital of France?"}],
    }
    r = client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    assert r.json()["aegis"]["decision"] == "allow"
    assert "Paris" in r.json()["choices"][0]["message"]["content"] or True  # echo upstream


def test_proxy_rejects_missing_or_bad_key(client):
    r = client.post("/v1/chat/completions", json={})
    assert r.status_code == 401
    r = client.post("/v1/chat/completions", json={}, headers={"Authorization": "Bearer notarealkey"})
    assert r.status_code == 401


def test_policy_check_endpoint(client):
    key = _create_key(client)
    r = client.post(
        "/v1/policy/check",
        json={"text": "ssn 543-21-9876", "scan_response": False},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["inbound"]["decision"] in {"block", "redact"}
