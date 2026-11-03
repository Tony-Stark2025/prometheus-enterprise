"""
Multi-Provider LLM Integration & Orchestration Engine for Prometheus Enterprise.

Inspired by opencode architecture, this module provides dual-mode execution:
1. In-Service Subscriptions:
   - Google Cloud / Vertex AI (ADC - Application Default Credentials)
   - GitHub Copilot API Token (OpenAI-compatible subscription proxy)
   - Enterprise AI Gateway (Cloudflare AI Gateway, Portkey, LiteLLM, internal proxy)
2. Bring Your Own Key (BYOK):
   - Google Gemini API Key (GEMINI_API_KEY, GOOGLE_GENERATIVE_AI_API_KEY)
   - Anthropic API Key (ANTHROPIC_API_KEY)
   - OpenAI API Key (OPENAI_API_KEY)
3. Deterministic Heuristic Engine:
   - Pure offline/air-gapped fallback with 0 token spend when no credentials are active.

All calls enforce strict timeouts (<= 8.0s), SHA-256 delta caching, and non-blocking async execution.
"""

import asyncio
import enum
import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from pydantic import BaseModel, Field

from prometheus.config import settings

logger = logging.getLogger(__name__)


class ProviderType(str, enum.Enum):
    VERTEX = "vertex"
    GEMINI = "gemini"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    COPILOT = "copilot"
    GATEWAY = "gateway"
    DETERMINISTIC = "deterministic"


class TelemetryCache:
    """In-memory SHA-256 telemetry delta cache with configurable TTL."""

    def __init__(self, ttl_seconds: int = 900, maxsize: int = 512):
        import collections
        self._ttl = ttl_seconds
        self._maxsize = maxsize
        self._cache: collections.OrderedDict[str, Tuple[float, Any]] = collections.OrderedDict()

    @classmethod
    def _hash_key(cls, prompt: str, payload: Any = None) -> str:
        content = prompt + (str(payload) if payload is not None else "")
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
                self._cache.move_to_end(hashed)
                logger.info(f"⚡ [TelemetryCache] Cache HIT for key {hashed[:8]} (saved 1 LLM call)")
                return data
            else:
                del self._cache[hashed]
        return None

    def set(self, key_payload: str, data: Any) -> None:
        hashed = self._normalize_key(key_payload)
        if hashed in self._cache:
            del self._cache[hashed]
        elif len(self._cache) >= self._maxsize:
            # O(1) eviction of the least recently used / oldest cache entry
            self._cache.popitem(last=False)
        self._cache[hashed] = (time.time(), data)

    def clear(self) -> None:
        self._cache.clear()


class ProviderManager:
    """
    Unified Multi-Provider LLM Orchestrator for Prometheus Enterprise.
    Supports in-service subscription tokens, BYOK API keys, and deterministic offline fallbacks.
    """

    _cached_gcloud_project: Optional[str] = None
    _gcloud_project_checked: bool = False
    _cached_gcloud_token: Optional[str] = None
    _gcloud_token_expiry: float = 0.0
    _working_vertex_model: Optional[str] = None

    TIER_TIMEOUT_SECONDS: Dict[str, float] = {
        "recon": 8.0,
        "explore": 15.0,
        "swe_repair": 30.0,
    }

    TIER_MODEL_PREFERENCES: Dict[str, Dict[str, str]] = {
        "recon": {
            "vertex": "gemini-3.7-flash",
            "gemini": "gemini-3.7-flash",
            "anthropic": "claude-3-5-haiku-20241022",
            "openai": "gpt-4o-mini",
        },
        "explore": {
            "vertex": "gemini-3.8-flash",
            "gemini": "gemini-3.8-flash",
            "anthropic": "claude-3-7-sonnet-20250219",
            "openai": "gpt-4o",
        },
        "swe_repair": {
            "vertex": "gemini-3.8-flash",
            "gemini": "gemini-3.8-flash",
            "anthropic": "claude-3-7-sonnet-20250219",
            "openai": "gpt-4o",
        },
    }

    def __init__(self, cache_ttl_seconds: Optional[int] = None):
        ttl = cache_ttl_seconds or settings.cache_ttl_seconds
        self.cache = TelemetryCache(ttl_seconds=ttl)
        self._http_client: Optional[httpx.AsyncClient] = None
        self.last_provider_used: Optional[str] = None
        self.last_model_used: Optional[str] = None
        self.last_tier_used: Optional[str] = None
        self.total_llm_calls: int = 0
        self.tier_usage_counts: Dict[str, int] = {"recon": 0, "explore": 0, "swe_repair": 0}

    @classmethod
    def _get_gcloud_config_dir(cls) -> Optional[str]:
        """Returns the local gcloud configuration directory path if present."""
        candidates = [
            os.environ.get("CLOUDSDK_CONFIG"),
            os.path.join(os.environ.get("APPDATA", ""), "gcloud") if os.environ.get("APPDATA") else None,
            os.path.expanduser("~/.config/gcloud"),
        ]
        for c in candidates:
            if c and os.path.isdir(c):
                return c
        return None

    @classmethod
    def _detect_gcloud_project(cls) -> Optional[str]:
        """Detects active GCP project from gcloud CLI configuration (<1ms INI read + CLI fallback)."""
        if "PYTEST_CURRENT_TEST" in os.environ and os.environ.get("PROMETHEUS_LIVE_LLM") != "1":
            return None
        if cls._gcloud_project_checked:
            return cls._cached_gcloud_project
        cls._gcloud_project_checked = True

        # 1. Fast <1ms direct INI read from gcloud configurations/config_default
        try:
            gdir = cls._get_gcloud_config_dir()
            if gdir:
                active_cfg_name = "default"
                active_cfg_file = os.path.join(gdir, "active_config")
                if os.path.isfile(active_cfg_file):
                    with open(active_cfg_file, "r", encoding="utf-8") as af:
                        active_cfg_name = af.read().strip() or "default"
                ini_path = os.path.join(gdir, "configurations", f"config_{active_cfg_name}")
                if os.path.isfile(ini_path):
                    import configparser
                    cp = configparser.ConfigParser()
                    cp.read(ini_path, encoding="utf-8")
                    proj = cp.get("core", "project", fallback="").strip()
                    if proj and proj != "(unset)":
                        cls._cached_gcloud_project = proj
                        logger.info(f"☁️ [ProviderManager] Auto-detected gcloud project: {proj}")
                        return proj
        except Exception:
            pass

        # 2. Subprocess fallback
        try:
            import shutil
            import subprocess
            gcloud_bin = shutil.which("gcloud") or shutil.which("gcloud.cmd")
            if not gcloud_bin:
                return None
            proc = subprocess.run(
                [gcloud_bin, "config", "get-value", "project"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            proj = (proc.stdout or "").strip()
            if proj and proj != "(unset)" and not proj.startswith("ERROR"):
                cls._cached_gcloud_project = proj
                logger.info(f"☁️ [ProviderManager] Auto-detected gcloud project: {proj}")
                return proj
        except Exception as exc:
            logger.debug(f"gcloud project detection skipped: {exc}")
        return None

    @classmethod
    def _get_gcloud_access_token(cls) -> Optional[str]:
        """Obtains and caches an OAuth2 access token from gcloud SQLite cache (<1ms) or CLI refresh."""
        now = time.time()
        if cls._cached_gcloud_token and now < cls._gcloud_token_expiry:
            return cls._cached_gcloud_token

        # 1. Fast <1ms check against gcloud's local SQLite access_tokens.db
        try:
            gdir = cls._get_gcloud_config_dir()
            if gdir:
                db_path = os.path.join(gdir, "access_tokens.db")
                if os.path.isfile(db_path):
                    import sqlite3
                    from datetime import datetime, timezone
                    conn = sqlite3.connect(db_path, timeout=1.0)
                    try:
                        rows = conn.execute(
                            "SELECT access_token, token_expiry FROM access_tokens WHERE access_token IS NOT NULL"
                        ).fetchall()
                        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                        for tok, exp_str in reversed(rows):
                            if not tok or not exp_str:
                                continue
                            try:
                                exp_dt = datetime.fromisoformat(str(exp_str))
                                remaining_s = (exp_dt - now_utc).total_seconds()
                                if remaining_s > 90.0:
                                    cls._cached_gcloud_token = str(tok).strip()
                                    cls._gcloud_token_expiry = now + min(remaining_s - 60.0, 2700.0)
                                    return cls._cached_gcloud_token
                            except Exception:
                                continue
                    finally:
                        conn.close()
        except Exception:
            pass

        # 2. Refresh via gcloud CLI
        try:
            import shutil
            import subprocess
            gcloud_bin = shutil.which("gcloud") or shutil.which("gcloud.cmd")
            if not gcloud_bin:
                return None
            for cmd in (
                [gcloud_bin, "auth", "print-access-token"],
                [gcloud_bin, "auth", "application-default", "print-access-token"],
            ):
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                    check=False,
                )
                token = (proc.stdout or "").strip()
                if proc.returncode == 0 and token and not token.startswith("ERROR"):
                    cls._cached_gcloud_token = token
                    cls._gcloud_token_expiry = now + 2700.0
                    return token
        except Exception as exc:
            logger.debug(f"gcloud token fetch skipped: {exc}")
        return None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.llm_request_timeout_seconds, connect=4.0),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            )
        return self._http_client

    async def aclose(self) -> None:
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    def resolve_provider(self) -> Tuple[ProviderType, Dict[str, Any]]:
        """
        Resolves the active LLM provider and authentication context.
        Follows opencode fallback precedence:
        1. Explicit setting if not 'auto'
        2. In-Service Subscriptions (GitHub Copilot, AI Gateway, Vertex ADC / gcloud)
        3. BYOK Keys (Gemini, Anthropic, OpenAI)
        4. Deterministic Heuristic Engine
        """
        configured_mode = settings.llm_provider.lower().strip()

        # 1. Explicitly requested provider
        if configured_mode != "auto":
            return self._resolve_explicit(configured_mode)

        # 2. Check In-Service Subscriptions
        # A) GitHub Copilot subscription
        copilot_token = (
            settings.copilot_token
            or os.environ.get("COPILOT_TOKEN")
            or os.environ.get("GITHUB_COPILOT_TOKEN")
        )
        if copilot_token:
            return ProviderType.COPILOT, {
                "token": copilot_token,
                "base_url": settings.copilot_base_url,
                "model": settings.llm_model or "gpt-4o",
            }

        # B) Enterprise AI Gateway
        ai_gateway_url = settings.ai_gateway_url or os.environ.get("AI_GATEWAY_URL")
        if ai_gateway_url:
            gateway_token = (
                settings.ai_gateway_token
                or os.environ.get("AI_GATEWAY_TOKEN")
                or os.environ.get("AI_GATEWAY_API_KEY")
            )
            return ProviderType.GATEWAY, {
                "url": ai_gateway_url,
                "token": gateway_token,
                "model": settings.llm_model or "default",
            }

        # C) Google Cloud Vertex AI (In-service subscription via ADC / gcloud CLI / Cloud IAM)
        gcp_project = (
            settings.gcp_project_id
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT")
            or os.environ.get("GOOGLE_VERTEX_PROJECT")
        )
        if settings.use_vertex_ai and not gcp_project:
            gcp_project = self._detect_gcloud_project()
        if settings.use_vertex_ai and gcp_project:
            return ProviderType.VERTEX, {
                "project": gcp_project,
                "location": settings.gcp_location,
                "model": settings.llm_model or settings.gemini_model,
            }

        # 3. Check BYOK (Bring Your Own Key)
        # A) Google Gemini Developer API
        gemini_key = (
            settings.gemini_api_key
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_GENERATIVE_AI_API_KEY")
        )
        if gemini_key:
            return ProviderType.GEMINI, {
                "api_key": gemini_key,
                "model": settings.llm_model or settings.gemini_model,
            }

        # B) Anthropic
        anthropic_key = settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
        if anthropic_key:
            return ProviderType.ANTHROPIC, {
                "api_key": anthropic_key,
                "model": settings.llm_model or "claude-3-7-sonnet-20250219",
            }

        # C) OpenAI
        openai_key = settings.openai_api_key or os.environ.get("OPENAI_API_KEY")
        if openai_key:
            return ProviderType.OPENAI, {
                "api_key": openai_key,
                "model": settings.llm_model or "gpt-4o",
            }

        # 4. Fallback: Pure Deterministic Offline Engine
        return ProviderType.DETERMINISTIC, {}

    def _resolve_explicit(self, mode: str) -> Tuple[ProviderType, Dict[str, Any]]:
        if mode in ("vertex", "vertex_ai", "gcloud"):
            gcp_project = (
                settings.gcp_project_id
                or os.environ.get("GOOGLE_CLOUD_PROJECT")
                or os.environ.get("GCP_PROJECT")
                or self._detect_gcloud_project()
            )
            return ProviderType.VERTEX, {
                "project": gcp_project,
                "location": settings.gcp_location,
                "model": settings.llm_model or settings.gemini_model,
            }
        elif mode == "gemini":
            key = (
                settings.gemini_api_key
                or os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_GENERATIVE_AI_API_KEY")
            )
            return ProviderType.GEMINI, {
                "api_key": key,
                "model": settings.llm_model or settings.gemini_model,
            }
        elif mode == "anthropic":
            key = settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
            return ProviderType.ANTHROPIC, {
                "api_key": key,
                "model": settings.llm_model or "claude-3-7-sonnet-20250219",
            }
        elif mode == "openai":
            key = settings.openai_api_key or os.environ.get("OPENAI_API_KEY")
            return ProviderType.OPENAI, {
                "api_key": key,
                "model": settings.llm_model or "gpt-4o",
            }
        elif mode == "copilot":
            token = (
                settings.copilot_token
                or os.environ.get("COPILOT_TOKEN")
                or os.environ.get("GITHUB_COPILOT_TOKEN")
            )
            return ProviderType.COPILOT, {
                "token": token,
                "base_url": settings.copilot_base_url,
                "model": settings.llm_model or "gpt-4o",
            }
        elif mode == "gateway":
            url = settings.ai_gateway_url or os.environ.get("AI_GATEWAY_URL")
            token = settings.ai_gateway_token or os.environ.get("AI_GATEWAY_TOKEN")
            return ProviderType.GATEWAY, {
                "url": url,
                "token": token,
                "model": settings.llm_model or "default",
            }
        return ProviderType.DETERMINISTIC, {}

    async def generate_structured_json(
        self,
        prompt: str,
        cache_key: Optional[str] = None,
        system_instruction: Optional[str] = None,
        tier: str = "explore",
    ) -> Optional[Dict[str, Any]]:
        """
        Executes structured JSON reasoning across the resolved provider with tiered model routing:
        - tier="recon": Fast/low-cost classification & reconnaissance (<= 8s)
        - tier="explore": Multi-turn ReAct hypothesis & payload reflection (<= 15s)
        - tier="swe_repair": High-reasoning contextual SWE program repair (<= 30s)
        """
        norm_tier = tier if tier in self.TIER_TIMEOUT_SECONDS else "explore"
        if cache_key:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        provider, config = self.resolve_provider()
        if provider == ProviderType.DETERMINISTIC:
            logger.info("⚡ [ProviderManager] No active LLM credentials. Using deterministic engine.")
            return None

        # Apply tiered model routing if user hasn't explicitly forced a custom llm_model override
        config = dict(config)
        tier_prefs = self.TIER_MODEL_PREFERENCES.get(norm_tier, {})
        if not settings.llm_model and provider.value in tier_prefs:
            config["model"] = tier_prefs[provider.value]
        config["timeout"] = self.TIER_TIMEOUT_SECONDS.get(norm_tier, settings.llm_request_timeout_seconds)

        try:
            raw_text: Optional[str] = None
            if provider == ProviderType.VERTEX:
                raw_text = await self._call_vertex(prompt, config, system_instruction)
            elif provider == ProviderType.GEMINI:
                raw_text = await self._call_gemini_byok(prompt, config, system_instruction)
            elif provider == ProviderType.ANTHROPIC:
                raw_text = await self._call_anthropic(prompt, config, system_instruction)
            elif provider == ProviderType.OPENAI:
                raw_text = await self._call_openai(prompt, config, system_instruction)
            elif provider == ProviderType.COPILOT:
                raw_text = await self._call_copilot(prompt, config, system_instruction)
            elif provider == ProviderType.GATEWAY:
                raw_text = await self._call_gateway(prompt, config, system_instruction)

            if raw_text:
                parsed = self._extract_json(raw_text)
                if parsed is not None:
                    self.last_provider_used = provider.value
                    self.last_model_used = self._working_vertex_model or config.get("model")
                    self.last_tier_used = norm_tier
                    self.total_llm_calls += 1
                    self.tier_usage_counts[norm_tier] = self.tier_usage_counts.get(norm_tier, 0) + 1
                    if cache_key:
                        self.cache.set(cache_key, parsed)
                    return parsed

        except asyncio.TimeoutError:
            logger.warning(
                f"⚠️ [ProviderManager] Request timed out ({config.get('timeout')}s, tier={norm_tier}) on provider '{provider.value}'."
            )
        except Exception as e:
            logger.warning(f"⚠️ [ProviderManager] Provider error on '{provider.value}': {e}.")

        return None

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Safely extracts JSON from structured response or markdown fences."""
        cleaned = text.strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if match:
            cleaned = match.group(1).strip()
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
            elif isinstance(parsed, list):
                return {"items": parsed}
        except Exception:
            # Fallback regex search for outer braces
            brace_match = re.search(r"\{[\s\S]*\}", cleaned)
            if brace_match:
                try:
                    return json.loads(brace_match.group(0))
                except Exception:
                    pass
        return None

    async def _call_vertex(
        self, prompt: str, config: Dict[str, Any], system_instruction: Optional[str]
    ) -> Optional[str]:
        """
        Calls Google Cloud Vertex AI using active gcloud CLI OAuth2 bearer token
        against the Vertex AI Global Endpoint (locations/global on aiplatform.googleapis.com)
        required for Gemini 3 series models (gemini-3.7-flash, gemini-3.8-flash),
        or falls back to the google.genai unified SDK (location='global').
        """
        project = config.get("project") or self._detect_gcloud_project()
        location = config.get("location", "global")
        primary_model = config.get("model", settings.gemini_model)

        # Active October 2026 Gemini 3 model candidates (Gemini 2.5 series retired Oct 20, 2026)
        candidates: List[str] = []
        for m in (self._working_vertex_model, primary_model, "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.5-flash"):
            if m and m not in candidates:
                candidates.append(m)

        # 1. Direct Vertex AI REST endpoint using gcloud CLI OAuth2 token
        # Gemini 3 models on Vertex AI are served on the global endpoint (aiplatform.googleapis.com/.../locations/global)
        gcloud_token = self._get_gcloud_access_token()
        if gcloud_token and project:
            client = await self._get_client()
            headers = {
                "Authorization": f"Bearer {gcloud_token}",
                "Content-Type": "application/json",
                "User-Agent": "google-cloud-sdk",
            }
            payload: Dict[str, Any] = {
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "responseMimeType": "application/json",
                },
            }
            if system_instruction:
                payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

            for candidate_model in candidates:
                # Gemini 3 series requires locations/global on aiplatform.googleapis.com
                effective_loc = "global" if candidate_model.startswith("gemini-3") else location
                host = (
                    "https://aiplatform.googleapis.com"
                    if effective_loc == "global"
                    else f"https://{effective_loc}-aiplatform.googleapis.com"
                )
                url = (
                    f"{host}/v1beta1/projects/{project}/locations/{effective_loc}/"
                    f"publishers/google/models/{candidate_model}:generateContent"
                )
                try:
                    resp = await client.post(
                        url,
                        headers=headers,
                        json=payload,
                        timeout=config.get("timeout", settings.llm_request_timeout_seconds),
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        cand_list = data.get("candidates", [])
                        if cand_list:
                            parts = cand_list[0].get("content", {}).get("parts", [])
                            if parts and "text" in parts[0]:
                                self.__class__._working_vertex_model = candidate_model
                                self.last_model_used = candidate_model
                                return parts[0]["text"]
                except Exception as exc:
                    logger.debug(f"Vertex REST attempt on {candidate_model} ({effective_loc}) failed: {exc}")
            return None

        # 2. Fallback to google.genai unified SDK (for Cloud Run metadata server ADC)
        from google import genai
        from google.genai import types

        effective_sdk_loc = "global" if str(primary_model).startswith("gemini-3") else location
        client_kwargs: Dict[str, Any] = {
            "vertexai": True,
            "location": effective_sdk_loc,
        }
        if project:
            client_kwargs["project"] = project

        genai_client = genai.Client(**client_kwargs)

        async def _call():
            cfg_kwargs: Dict[str, Any] = {
                "response_mime_type": "application/json",
                "temperature": 0.2,
            }
            if system_instruction:
                cfg_kwargs["system_instruction"] = system_instruction

            for candidate_model in candidates:
                try:
                    resp = await genai_client.aio.models.generate_content(
                        model=candidate_model,
                        contents=prompt,
                        config=types.GenerateContentConfig(**cfg_kwargs),
                    )
                    if resp and resp.text:
                        self.__class__._working_vertex_model = candidate_model
                        self.last_model_used = candidate_model
                        return resp.text
                except Exception:
                    continue
            return None

        return await asyncio.wait_for(_call(), timeout=config.get("timeout", settings.llm_request_timeout_seconds))

    async def _call_gemini_byok(
        self, prompt: str, config: Dict[str, Any], system_instruction: Optional[str]
    ) -> Optional[str]:
        """Calls Google Gemini Developer API using BYOK API Key."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=config.get("api_key"))
        model_name = config.get("model", settings.gemini_model)

        async def _call():
            cfg_kwargs: Dict[str, Any] = {
                "response_mime_type": "application/json",
                "temperature": 0.2,
            }
            if system_instruction:
                cfg_kwargs["system_instruction"] = system_instruction

            resp = await client.aio.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(**cfg_kwargs),
            )
            return resp.text if resp else None

        return await asyncio.wait_for(_call(), timeout=config.get("timeout", settings.llm_request_timeout_seconds))

    async def _call_anthropic(
        self, prompt: str, config: Dict[str, Any], system_instruction: Optional[str]
    ) -> Optional[str]:
        """Calls Anthropic Messages API with BYOK API key."""
        client = await self._get_client()
        headers = {
            "x-api-key": config["api_key"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": config.get("model", "claude-3-7-sonnet-20250219"),
            "max_tokens": 4096,
            "temperature": 0.2,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_instruction:
            payload["system"] = system_instruction

        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
            timeout=config.get("timeout", settings.llm_request_timeout_seconds),
        )
        resp.raise_for_status()
        data = resp.json()
        content = data.get("content", [])
        if content and isinstance(content, list):
            text_blocks = [c["text"] for c in content if c.get("type") == "text"]
            return "\n".join(text_blocks)
        return None

    async def _call_openai(
        self, prompt: str, config: Dict[str, Any], system_instruction: Optional[str]
    ) -> Optional[str]:
        """Calls OpenAI Chat Completions API with BYOK API key."""
        client = await self._get_client()
        headers = {
            "Authorization": f"Bearer {config['api_key']}",
            "content-type": "application/json",
        }
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": config.get("model", "gpt-4o"),
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": messages,
        }

        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=config.get("timeout", settings.llm_request_timeout_seconds),
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content")
        return None

    async def _call_copilot(
        self, prompt: str, config: Dict[str, Any], system_instruction: Optional[str]
    ) -> Optional[str]:
        """
        Calls GitHub Copilot Subscription Endpoint (OpenAI-compatible).
        Follows opencode Copilot proxy pattern with subscription authorization token.
        """
        client = await self._get_client()
        base_url = config.get("base_url", "https://api.githubcopilot.com").rstrip("/")
        endpoint = f"{base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {config['token']}",
            "Editor-Version": "vscode/1.90.0",
            "User-Agent": "GitHubCopilotChat/0.17.0",
            "content-type": "application/json",
        }

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": config.get("model", "gpt-4o"),
            "temperature": 0.2,
            "messages": messages,
        }

        resp = await client.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=config.get("timeout", settings.llm_request_timeout_seconds),
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content")
        return None

    async def _call_gateway(
        self, prompt: str, config: Dict[str, Any], system_instruction: Optional[str]
    ) -> Optional[str]:
        """Calls custom Enterprise AI Gateway (e.g. Cloudflare AI Gateway, Portkey, LiteLLM)."""
        client = await self._get_client()
        url = config["url"]
        headers = {"content-type": "application/json"}
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": config.get("model", "default"),
            "temperature": 0.2,
            "messages": messages,
        }

        resp = await client.post(
            url,
            headers=headers,
            json=payload,
            timeout=config.get("timeout", settings.llm_request_timeout_seconds),
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content")
        return None


# Global singleton instance
provider_manager = ProviderManager()
