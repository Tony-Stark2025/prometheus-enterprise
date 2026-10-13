"""
Configuration module for Prometheus Enterprise Observability Platform.
Standardized on Gemini 3.7 Flash via Vertex AI & Gemini Enterprise Agent Platform (Agent Engine).
"""

from typing import List, Optional, Union, Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application Settings
    app_name: str = "Prometheus Chief of Staff"
    environment: str = "development"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8000
    allow_insecure_admin: bool = False

    # Google Cloud & Vertex AI / Gemini Enterprise Agent Platform (Agent Engine)
    use_vertex_ai: bool = True
    gcp_project_id: Optional[str] = None
    gcp_location: str = "us-central1"
    agent_engine_app_id: Optional[str] = None
    agent_engine_location: str = "us-central1"
    gemini_request_timeout_seconds: float = 8.0

    # Multi-Provider LLM Integration (In-Service Subscriptions & BYOK)
    llm_provider: str = "auto"  # 'auto', 'vertex', 'gemini', 'anthropic', 'openai', 'copilot', 'gateway'
    llm_model: Optional[str] = None  # Explicit override; defaults to provider-optimal model
    llm_request_timeout_seconds: float = 8.0

    # BYOK (Bring Your Own Key) Direct Credentials
    gemini_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None

    # In-Service Subscriptions & Enterprise Gateways
    copilot_token: Optional[str] = None
    copilot_base_url: str = "https://api.githubcopilot.com"
    ai_gateway_url: Optional[str] = None
    ai_gateway_token: Optional[str] = None

    # Unified Foundation Model (Standardized exclusively on Gemini 3.7 Flash)
    gemini_model: str = "gemini-3.7-flash"
    gemini_model_primary: str = "gemini-3.7-flash"

    # Telemetry Caching (TTL in seconds)
    cache_ttl_seconds: int = 900  # 15 minutes

    # Model Context Protocol (MCP) Configuration
    mcp_enabled: bool = True
    mcp_transport: str = "stdio,sse"

    # Persistence / Database (SQLite for local / free-tier; Cloud SQL / PostgreSQL for production)
    database_url: str = "sqlite+aiosqlite:///./prometheus_state.db"

    # Observability & Thresholds
    stale_pr_hours_threshold: int = 1
    ci_failure_threshold_count: int = 2
    default_org_scope: Union[List[str], str] = Field(
        default_factory=lambda: ["engineering", "platform"]
    )

    # Human-in-the-Loop (HITL) Enforcement
    enforce_human_in_the_loop: bool = True

    # External Integrations
    github_token: Optional[str] = None
    github_repos: Union[List[str], str] = Field(default_factory=list)
    jira_api_token: Optional[str] = None
    jira_instance_url: Optional[str] = None
    jira_user_email: Optional[str] = None
    jira_project_key: Optional[str] = None
    slack_bot_token: Optional[str] = None
    slack_channels: Union[List[str], str] = Field(default_factory=list)

    @field_validator("default_org_scope", "github_repos", "slack_channels", mode="after")
    @classmethod
    def normalize_list(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            if not v.strip():
                return []
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [item.strip() for item in v.split(",") if item.strip()]
        elif isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return []

    @classmethod
    def resolve_secret_manager_uri(cls, value: Optional[str], project_id: Optional[str] = None) -> Optional[str]:
        """Resolves secrets prefixed with sm:// or secretmanager:// using Google Secret Manager."""
        if not value or not isinstance(value, str):
            return value

        prefixes = ("sm://", "secretmanager://")
        matched_prefix = next((p for p in prefixes if value.startswith(p)), None)
        if not matched_prefix:
            return value

        secret_path = value[len(matched_prefix):].strip()
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            if "/" not in secret_path:
                proj = project_id or "gen-lang-client-0942141479"
                name = f"projects/{proj}/secrets/{secret_path}/versions/latest"
            elif not secret_path.startswith("projects/"):
                proj = project_id or "gen-lang-client-0942141479"
                name = f"projects/{proj}/{secret_path}"
            else:
                name = secret_path
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("utf-8")
        except Exception:
            return value

    @field_validator(
        "github_token",
        "jira_api_token",
        "jira_instance_url",
        "jira_user_email",
        "slack_bot_token",
        "gemini_api_key",
        "anthropic_api_key",
        "openai_api_key",
        "copilot_token",
        "ai_gateway_token",
        mode="before",
    )
    @classmethod
    def empty_str_to_none(cls, v: Any) -> Optional[str]:
        if isinstance(v, str) and not v.strip():
            return None
        if isinstance(v, str) and (v.startswith("sm://") or v.startswith("secretmanager://")):
            return cls.resolve_secret_manager_uri(v)
        return v

    def get_sqlite_db_path(self) -> str:
        """Extracts the filesystem path from the database URL for SQLite."""
        url = self.database_url
        for prefix in ["sqlite+aiosqlite:///", "sqlite:///", "sqlite+asyncpg:///"]:
            if url.startswith(prefix):
                return url[len(prefix):]
        return url


settings = Settings()
