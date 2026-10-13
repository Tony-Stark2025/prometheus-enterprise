"""
Unit tests for Prometheus Multi-Provider LLM Orchestrator (In-Service Subscriptions & BYOK).
"""

import asyncio
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from prometheus.config import Settings
from prometheus.llm.provider_manager import (
    ProviderManager,
    ProviderType,
    TelemetryCache,
)


def test_telemetry_cache_operations():
    cache = TelemetryCache(ttl_seconds=60)
    key = "test_prompt_payload"

    # Initially empty
    assert cache.get(key) is None

    # Set and retrieve
    payload = {"status": "ok", "data": [1, 2, 3]}
    cache.set(key, payload)
    assert cache.get(key) == payload

    # Test TTL expiration
    expired_cache = TelemetryCache(ttl_seconds=-1)
    expired_cache.set(key, payload)
    assert expired_cache.get(key) is None


def test_extract_json():
    pm = ProviderManager()

    # Raw JSON
    raw = '{"key": "value", "count": 42}'
    assert pm._extract_json(raw) == {"key": "value", "count": 42}

    # Markdown fenced JSON
    fenced = '```json\n{"action": "patch", "lines": [10, 11]}\n```'
    assert pm._extract_json(fenced) == {"action": "patch", "lines": [10, 11]}

    # Conversational wrapper
    conversational = 'Here is the analysis:\n```json\n{"finding": "BOLA"}\n```\nHope that helps!'
    assert pm._extract_json(conversational) == {"finding": "BOLA"}

    # Invalid JSON
    assert pm._extract_json("not a valid json") is None


def test_provider_resolution_precedence(monkeypatch):
    pm = ProviderManager()

    # 1. Copilot Subscription takes precedence in auto mode
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = "gho_testcopilottoken123"
        mock_settings.copilot_base_url = "https://api.githubcopilot.com"
        mock_settings.ai_gateway_url = None
        mock_settings.use_vertex_ai = False
        mock_settings.gemini_api_key = None
        mock_settings.anthropic_api_key = None
        mock_settings.openai_api_key = None
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.COPILOT
        assert cfg["token"] == "gho_testcopilottoken123"
        assert cfg["model"] == "gpt-4o"

    # 2. AI Gateway Subscription
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = None
        mock_settings.ai_gateway_url = "https://gateway.ai.cloudflare.com/v1/test"
        mock_settings.ai_gateway_token = "cf_gw_token"
        mock_settings.use_vertex_ai = False
        mock_settings.gemini_api_key = None
        mock_settings.anthropic_api_key = None
        mock_settings.openai_api_key = None
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.GATEWAY
        assert cfg["url"] == "https://gateway.ai.cloudflare.com/v1/test"
        assert cfg["token"] == "cf_gw_token"

    # 3. Vertex AI Subscription via ADC / GCP Project
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = None
        mock_settings.ai_gateway_url = None
        mock_settings.use_vertex_ai = True
        mock_settings.gcp_project_id = "enterprise-gcp-project-123"
        mock_settings.gcp_location = "us-central1"
        mock_settings.gemini_model = "gemini-3.7-flash"
        mock_settings.gemini_api_key = None
        mock_settings.anthropic_api_key = None
        mock_settings.openai_api_key = None
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.VERTEX
        assert cfg["project"] == "enterprise-gcp-project-123"
        assert cfg["model"] == "gemini-3.7-flash"

    # 4. BYOK: Gemini Developer Key
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = None
        mock_settings.ai_gateway_url = None
        mock_settings.use_vertex_ai = False
        mock_settings.gcp_project_id = None
        mock_settings.gemini_api_key = "AIzaSyTestGeminiKey"
        mock_settings.gemini_model = "gemini-3.7-flash"
        mock_settings.anthropic_api_key = None
        mock_settings.openai_api_key = None
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.GEMINI
        assert cfg["api_key"] == "AIzaSyTestGeminiKey"

    # 5. BYOK: Anthropic
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = None
        mock_settings.ai_gateway_url = None
        mock_settings.use_vertex_ai = False
        mock_settings.gcp_project_id = None
        mock_settings.gemini_api_key = None
        mock_settings.anthropic_api_key = "sk-ant-testkey"
        mock_settings.openai_api_key = None
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.ANTHROPIC
        assert cfg["api_key"] == "sk-ant-testkey"

    # 6. BYOK: OpenAI
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = None
        mock_settings.ai_gateway_url = None
        mock_settings.use_vertex_ai = False
        mock_settings.gcp_project_id = None
        mock_settings.gemini_api_key = None
        mock_settings.anthropic_api_key = None
        mock_settings.openai_api_key = "sk-proj-testkey"
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.OPENAI
        assert cfg["api_key"] == "sk-proj-testkey"

    # 7. Offline / Air-Gapped Fallback: Pure Deterministic
    with patch("prometheus.llm.provider_manager.settings") as mock_settings:
        mock_settings.llm_provider = "auto"
        mock_settings.copilot_token = None
        mock_settings.ai_gateway_url = None
        mock_settings.use_vertex_ai = False
        mock_settings.gcp_project_id = None
        mock_settings.gemini_api_key = None
        mock_settings.anthropic_api_key = None
        mock_settings.openai_api_key = None
        mock_settings.llm_model = None

        provider, cfg = pm.resolve_provider()
        assert provider == ProviderType.DETERMINISTIC
        assert cfg == {}


@pytest.mark.asyncio
async def test_deterministic_fallback_returns_none():
    pm = ProviderManager()
    with patch.object(pm, "resolve_provider", return_value=(ProviderType.DETERMINISTIC, {})):
        result = await pm.generate_structured_json("Test prompt")
        assert result is None


@pytest.mark.asyncio
async def test_cache_hit_bypasses_provider():
    pm = ProviderManager()
    cache_key = "my_custom_cache_key"
    cached_payload = {"cached": True, "value": 123}
    pm.cache.set(cache_key, cached_payload)

    # Calling with cache key should return cached item immediately without calling provider
    with patch.object(pm, "resolve_provider") as mock_resolve:
        result = await pm.generate_structured_json("Some prompt", cache_key=cache_key)
        assert result == cached_payload
        mock_resolve.assert_not_called()


@pytest.mark.asyncio
async def test_openai_provider_invocation():
    pm = ProviderManager()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({"status": "verified", "severity": "HIGH"})
                }
            }
        ]
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response

    with patch.object(pm, "_get_client", return_value=mock_client):
        with patch.object(
            pm,
            "resolve_provider",
            return_value=(ProviderType.OPENAI, {"api_key": "sk-test", "model": "gpt-4o"}),
        ):
            result = await pm.generate_structured_json("Analyze BOLA route")
            assert result == {"status": "verified", "severity": "HIGH"}
            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args[1]
            assert "Bearer sk-test" in call_kwargs["headers"]["Authorization"]
