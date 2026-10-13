"""
Vertex AI & Gemini Enterprise Agent Platform LLM Engine.
Unified exclusively on Gemini 3.7 Flash for all agents with non-blocking async execution (client.aio),
timeout protection, and SHA-256 telemetry delta caching. Zero model cascading.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from prometheus.config import settings

logger = logging.getLogger(__name__)


class TelemetryCache:
    """In-memory SHA-256 telemetry delta cache with configurable TTL."""

    def __init__(self, ttl_seconds: int = 900, maxsize: int = 512):
        self._ttl = ttl_seconds
        self._maxsize = maxsize
        self._cache: Dict[str, Tuple[float, Any]] = {}

    @classmethod
    def _hash_key(cls, prompt: str, payload: Any) -> str:
        content = prompt + str(payload)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_key(key_payload: str) -> str:
        if len(key_payload) == 64 and all(c in "0123456789abcdef" for c in key_payload.lower()):
            return key_payload.lower()
        return hashlib.sha256(key_payload.encode("utf-8")).hexdigest()

    def get(self, key_payload: str) -> Optional[Any]:
        hashed = self._normalize_key(key_payload)
        if hashed in self._cache:
            timestamp, data = self._cache[hashed]
            if time.time() - timestamp < self._ttl:
                logger.info(f"⚡ [TelemetryCache] Cache HIT for key {hashed[:8]} (saved 1 LLM call)")
                return data
            else:
                del self._cache[hashed]
        return None

    def set(self, key_payload: str, data: Any) -> None:
        hashed = self._normalize_key(key_payload)
        if len(self._cache) >= self._maxsize and hashed not in self._cache:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]
        self._cache[hashed] = (time.time(), data)


class GeminiEnterpriseEngine:
    """
    Enterprise Vertex AI LLM Engine for Prometheus.
    Standardized exclusively on Gemini 3.7 Flash without multi-model cascades.
    """

    def __init__(self):
        from prometheus.llm.provider_manager import provider_manager
        self.cache = provider_manager.cache

    def _get_vertex_client(self) -> Optional[Any]:
        """Initializes the unified Google GenAI client targeting Vertex AI / Agent Platform."""
        try:
            from google import genai
            client_kwargs: Dict[str, Any] = {
                "vertexai": True,
                "location": settings.gcp_location,
            }
            if settings.gcp_project_id:
                client_kwargs["project"] = settings.gcp_project_id
            return genai.Client(**client_kwargs)
        except Exception as e:
            logger.info(f"ℹ️ [VertexAI] Google Cloud credentials not active locally ({e}). Using deterministic reasoning engine.")
            return None

    async def generate_structured_synthesis(
        self,
        prompt: str,
        cache_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes structured JSON reasoning across configured providers (Vertex AI, Copilot, Anthropic, OpenAI, Gemini BYOK).
        Uses non-blocking asyncio with timeout guards.
        """
        from prometheus.llm.provider_manager import provider_manager
        return await provider_manager.generate_structured_json(prompt, cache_key=cache_key)


# Global singleton instances and backward compatibility aliases
GeminiPoolClient = GeminiEnterpriseEngine
gemini_engine = GeminiEnterpriseEngine()
gemini_pool = gemini_engine
