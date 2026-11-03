"""
Global pytest fixtures for Prometheus Enterprise test suite.
Configures test credentials, mocks cloud persistence/LLM clients,
and passes through local test client HTTP requests.
"""

from unittest.mock import patch
import httpx
import pytest

from prometheus.config import settings

_REAL_ASYNC_CLIENT_GET = httpx.AsyncClient.get
_REAL_ASYNC_CLIENT_POST = httpx.AsyncClient.post


async def _default_http_get(self, url, *args, **kwargs):
    if isinstance(getattr(self, "_transport", None), httpx.MockTransport):
        return await _REAL_ASYNC_CLIENT_GET(self, url, *args, **kwargs)

    url_str = str(url)

    # Pass through local ASGI test client and loopback requests
    if (
        url_str.startswith("http://test")
        or url_str.startswith("http://localhost")
        or url_str.startswith("http://127.0.0.1")
    ):
        return await _REAL_ASYNC_CLIENT_GET(self, url, *args, **kwargs)

    return await _REAL_ASYNC_CLIENT_GET(self, url, *args, **kwargs)


async def _default_http_post(self, url, *args, **kwargs):
    if isinstance(getattr(self, "_transport", None), httpx.MockTransport):
        return await _REAL_ASYNC_CLIENT_POST(self, url, *args, **kwargs)

    url_str = str(url)

    if (
        url_str.startswith("http://test")
        or url_str.startswith("http://localhost")
        or url_str.startswith("http://127.0.0.1")
    ):
        return await _REAL_ASYNC_CLIENT_POST(self, url, *args, **kwargs)

    return await _REAL_ASYNC_CLIENT_POST(self, url, *args, **kwargs)


@pytest.fixture(autouse=True)
def enterprise_http_transport_fixture(monkeypatch):
    """
    Configures default test environment, in-memory Firestore isolation,
    and offline mock for Vertex client.
    """
    from prometheus.memory.firestore_store import firestore_store
    from prometheus.llm.gemini_pool import GeminiEnterpriseEngine

    monkeypatch.setattr(firestore_store, "_db", None)
    monkeypatch.setattr(GeminiEnterpriseEngine, "_get_vertex_client", lambda self: None)

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-vault-for-pytest-execution")

    monkeypatch.setattr(httpx.AsyncClient, "get", _default_http_get)
    monkeypatch.setattr(httpx.AsyncClient, "post", _default_http_post)
    yield
