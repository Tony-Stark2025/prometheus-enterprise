"""
Pydantic schemas and tier definitions for Prometheus Commercial SaaS & Enterprise Licensing.
Aligned with October 2026 Hybrid PLG + Enterprise API & Agentic Security pricing benchmarks.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SubscriptionTier(str, Enum):
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class TierQuota(BaseModel):
    tier: SubscriptionTier
    display_name: str
    monthly_price_usd: int
    annual_contract_usd: int
    max_pentest_scans_per_month: int
    max_mcp_inspections_per_month: int
    max_api_keys: int
    rate_limit_per_minute: int
    cegis_auto_patch_enabled: bool
    owasp_agentic_shield_enabled: bool
    compliance_export_enabled: bool
    sso_and_custom_abac_enabled: bool
    sla_uptime_pct: float
    features: List[str]


TIER_CATALOG: Dict[SubscriptionTier, TierQuota] = {
    SubscriptionTier.STARTER: TierQuota(
        tier=SubscriptionTier.STARTER,
        display_name="Developer Starter (PLG Free)",
        monthly_price_usd=0,
        annual_contract_usd=0,
        max_pentest_scans_per_month=5,
        max_mcp_inspections_per_month=1_000,
        max_api_keys=2,
        rate_limit_per_minute=60,
        cegis_auto_patch_enabled=False,
        owasp_agentic_shield_enabled=True,
        compliance_export_enabled=False,
        sso_and_custom_abac_enabled=False,
        sla_uptime_pct=99.0,
        features=[
            "5 Autonomous BOLA/BFLA Pentest Scans / mo",
            "1,000 MCP Gateway Tool Inspections / mo",
            "Zero False-Positive Cryptographic Canary Verification",
            "OWASP Agentic Top 10 (ASI01-ASI10) Baseline Shield",
            "2 Scoped API Keys (60 req/min)",
        ],
    ),
    SubscriptionTier.PRO: TierQuota(
        tier=SubscriptionTier.PRO,
        display_name="Professional Growth (Self-Serve)",
        monthly_price_usd=499,
        annual_contract_usd=4_990,
        max_pentest_scans_per_month=50,
        max_mcp_inspections_per_month=50_000,
        max_api_keys=10,
        rate_limit_per_minute=300,
        cegis_auto_patch_enabled=True,
        owasp_agentic_shield_enabled=True,
        compliance_export_enabled=True,
        sso_and_custom_abac_enabled=False,
        sla_uptime_pct=99.9,
        features=[
            "50 Autonomous Pentest Scans / mo (<85s CI/CD SLA)",
            "50,000 Live MCP Gateway Tool Inspections / mo",
            "CEGIS Dual-Pass AST Automated Program Repair",
            "Full OWASP Agentic Top 10 (ASI01-ASI10) Enforcement",
            "10 Scoped API Keys (300 req/min) + SARIF Export",
        ],
    ),
    SubscriptionTier.ENTERPRISE: TierQuota(
        tier=SubscriptionTier.ENTERPRISE,
        display_name="Enterprise Guard (CISO & AI Platform)",
        monthly_price_usd=7_500,
        annual_contract_usd=75_000,
        max_pentest_scans_per_month=100_000,
        max_mcp_inspections_per_month=5_000_000,
        max_api_keys=250,
        rate_limit_per_minute=2_000,
        cegis_auto_patch_enabled=True,
        owasp_agentic_shield_enabled=True,
        compliance_export_enabled=True,
        sso_and_custom_abac_enabled=True,
        sla_uptime_pct=99.99,
        features=[
            "Unlimited CI/CD Pentest Scans & Custom OpenAPI DAGs",
            "5M+ Live MCP Reverse-Proxy Gateway Inspections / mo",
            "Non-Human Identity (NHI) Macaroon Attenuation & H(S) Witnesses",
            "Cryptographically Signed EU AI Act Art. 12, SOC2 & CoSAI Ledgers",
            "Google Enterprise OAuth SSO, Custom ABAC & Dedicated VPC Support",
        ],
    ),
}


class TenantOrganization(BaseModel):
    tenant_id: str
    name: str
    domain: str
    tier: SubscriptionTier = SubscriptionTier.ENTERPRISE
    status: str = "active"  # active, past_due, suspended
    billing_email: str = "security-billing@enterprise.io"
    created_at: str
    updated_at: str


class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=80, description="Human-readable label for the API key")
    scopes: List[str] = Field(
        default_factory=lambda: ["pentest:scan", "mcp:gateway", "hypervisor:mint", "compliance:read"],
        description="Scoped permissions granted to this key",
    )
    roles: List[str] = Field(default_factory=lambda: ["operator", "developer"])
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365)


class APIKeyRecord(BaseModel):
    key_id: str
    tenant_id: str
    name: str
    key_prefix: str
    scopes: List[str]
    roles: List[str]
    created_by: str
    created_at: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    is_active: bool = True


class APIKeyCreateResponse(BaseModel):
    key_id: str
    tenant_id: str
    name: str
    raw_api_key: str = Field(..., description="Raw secret key shown ONLY ONCE at creation")
    key_prefix: str
    scopes: List[str]
    roles: List[str]
    created_at: str
    expires_at: Optional[str] = None


class UsageMeterSnapshot(BaseModel):
    tenant_id: str
    billing_period: str  # YYYY-MM
    tier: SubscriptionTier
    pentest_scans_used: int
    pentest_scans_limit: int
    mcp_inspections_used: int
    mcp_inspections_limit: int
    asi_threats_blocked: int
    cegis_patches_synthesized: int
    tokens_minted: int
    estimated_monthly_bill_usd: float
    quota_utilization_pct: float


class ComplianceExportBundle(BaseModel):
    bundle_id: str
    generated_at: str
    tenant_id: str
    organization_name: str
    tier: SubscriptionTier
    frameworks: List[str] = Field(
        default_factory=lambda: [
            "OWASP Agentic Top 10 (2026 ASI01-ASI10)",
            "EU AI Act Article 12 & 15 (Record-Keeping & Cybersecurity)",
            "SOC 2 Type II (CC6.1 Logical Access & CC7.2 System Monitoring)",
            "CoSAI (Coalition for Secure AI) MCP Governance Standard",
        ]
    )
    posture_score: float
    usage_summary: UsageMeterSnapshot
    asi_control_matrix: List[Dict[str, Any]]
    recent_abac_decisions: List[Dict[str, Any]]
    recent_asi_interceptions: List[Dict[str, Any]]
    active_witness_count: int
    ledger_merkle_root_sha256: str
    hmac_signature: str
    verification_instructions: str
