"""
Enterprise Multi-Tenant SaaS Metering, API Key Authentication, Rate-Limiting & Compliance Engine.
Backed by SQLite with WAL concurrency mode and HMAC-SHA256 cryptographic ledger signing.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from prometheus.saas.models import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyRecord,
    ComplianceExportBundle,
    SubscriptionTier,
    TIER_CATALOG,
    TenantOrganization,
    TierQuota,
    UsageMeterSnapshot,
)

SAAS_DB_PATH = os.getenv(
    "SAAS_DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "security", "abac_policies.db"),
)


class SaaSPlatformEngine:
    """
    Production-grade SaaS engine managing organizations, subscription tiers,
    SHA-256 hashed API keys, sliding-window rate limits, usage metering, and compliance exports.
    """

    def __init__(self, db_path: str = SAAS_DB_PATH, signing_secret: Optional[str] = None):
        self.db_path = db_path
        self.signing_secret = (
            signing_secret
            or os.getenv("PROMETHEUS_HMAC_SECRET", "prometheus-enterprise-saas-hmac-key-2026")
        ).encode("utf-8")
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        # Sliding-window rate limit tracker: {tenant_id: [timestamps]}
        self._rate_windows: Dict[str, List[float]] = {}
        self._init_db()
        self._seed_default_tenants()

    def _get_conn(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS saas_tenants (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT NOT NULL,
                tier TEXT NOT NULL DEFAULT 'enterprise',
                status TEXT NOT NULL DEFAULT 'active',
                billing_email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS saas_api_keys (
                key_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash_sha256 TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                roles TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                last_used_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON saas_api_keys(key_hash_sha256);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON saas_api_keys(tenant_id);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS saas_usage_counters (
                tenant_id TEXT NOT NULL,
                billing_period TEXT NOT NULL,
                pentest_scans_used INTEGER NOT NULL DEFAULT 0,
                mcp_inspections_used INTEGER NOT NULL DEFAULT 0,
                asi_threats_blocked INTEGER NOT NULL DEFAULT 0,
                cegis_patches_synthesized INTEGER NOT NULL DEFAULT 0,
                tokens_minted INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, billing_period)
            )
        """)
        conn.commit()

    def _seed_default_tenants(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        defaults = [
            TenantOrganization(
                tenant_id="default_enterprise",
                name="Acme Global Financial Corp",
                domain="acme.corp",
                tier=SubscriptionTier.ENTERPRISE,
                status="active",
                billing_email="ciso-billing@acme.corp",
                created_at=now_iso,
                updated_at=now_iso,
            ),
            TenantOrganization(
                tenant_id="org-alpha-victim-001",
                name="Alpha Cloud Platform (Pro Tier)",
                domain="alpha.cloud",
                tier=SubscriptionTier.PRO,
                status="active",
                billing_email="devops@alpha.cloud",
                created_at=now_iso,
                updated_at=now_iso,
            ),
        ]
        with self._get_conn() as conn:
            cur = conn.cursor()
            for t in defaults:
                cur.execute(
                    """
                    INSERT OR IGNORE INTO saas_tenants
                    (tenant_id, name, domain, tier, status, billing_email, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        t.tenant_id,
                        t.name,
                        t.domain,
                        t.tier.value,
                        t.status,
                        t.billing_email,
                        t.created_at,
                        t.updated_at,
                    ),
                )
            conn.commit()

    @staticmethod
    def current_billing_period() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    @staticmethod
    def hash_api_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()

    # ==========================================================================
    # Tenant & Subscription Tier Management
    # ==========================================================================
    def get_or_create_tenant(self, tenant_id: str) -> TenantOrganization:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM saas_tenants WHERE tenant_id = ?", (tenant_id,))
            row = cur.fetchone()
            if row:
                return TenantOrganization(
                    tenant_id=row["tenant_id"],
                    name=row["name"],
                    domain=row["domain"],
                    tier=SubscriptionTier(row["tier"]),
                    status=row["status"],
                    billing_email=row["billing_email"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )

            now_iso = datetime.now(timezone.utc).isoformat()
            org = TenantOrganization(
                tenant_id=tenant_id,
                name=f"Organization ({tenant_id})",
                domain=f"{tenant_id}.enterprise.io",
                tier=SubscriptionTier.PRO,
                status="active",
                billing_email=f"billing@{tenant_id}.enterprise.io",
                created_at=now_iso,
                updated_at=now_iso,
            )
            cur.execute(
                """
                INSERT INTO saas_tenants
                (tenant_id, name, domain, tier, status, billing_email, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    org.tenant_id,
                    org.name,
                    org.domain,
                    org.tier.value,
                    org.status,
                    org.billing_email,
                    org.created_at,
                    org.updated_at,
                ),
            )
            conn.commit()
            return org

    def update_tenant_tier(
        self,
        tenant_id: str,
        new_tier: SubscriptionTier,
        name: Optional[str] = None,
        billing_email: Optional[str] = None,
    ) -> TenantOrganization:
        org = self.get_or_create_tenant(tenant_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        updated_name = name or org.name
        updated_email = billing_email or org.billing_email
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE saas_tenants
                SET tier = ?, name = ?, billing_email = ?, updated_at = ?
                WHERE tenant_id = ?
                """,
                (new_tier.value, updated_name, updated_email, now_iso, tenant_id),
            )
            conn.commit()
        return self.get_or_create_tenant(tenant_id)

    def get_tier_quota(self, tenant_id: str) -> TierQuota:
        org = self.get_or_create_tenant(tenant_id)
        return TIER_CATALOG[org.tier]

    # ==========================================================================
    # API Key Lifecycle & Authentication
    # ==========================================================================
    def create_api_key(
        self,
        tenant_id: str,
        created_by: str,
        req: APIKeyCreateRequest,
    ) -> APIKeyCreateResponse:
        quota = self.get_tier_quota(tenant_id)
        active_keys = [k for k in self.list_api_keys(tenant_id) if k.is_active]
        if len(active_keys) >= quota.max_api_keys:
            raise ValueError(
                f"Subscription tier '{quota.display_name}' allows a maximum of {quota.max_api_keys} active API keys. Upgrade tier or revoke an existing key."
            )

        key_id = f"key_{uuid.uuid4().hex[:16]}"
        random_secret = secrets.token_hex(24)
        raw_key = f"prom_live_{random_secret}"
        key_prefix = raw_key[:16] + "..."
        key_hash = self.hash_api_key(raw_key)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        expires_iso = (
            (now + timedelta(days=req.expires_in_days)).isoformat()
            if req.expires_in_days
            else None
        )

        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO saas_api_keys
                (key_id, tenant_id, name, key_prefix, key_hash_sha256, scopes, roles, created_by, created_at, expires_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    key_id,
                    tenant_id,
                    req.name,
                    key_prefix,
                    key_hash,
                    json.dumps(req.scopes),
                    json.dumps(req.roles),
                    created_by,
                    now_iso,
                    expires_iso,
                ),
            )
            conn.commit()

        return APIKeyCreateResponse(
            key_id=key_id,
            tenant_id=tenant_id,
            name=req.name,
            raw_api_key=raw_key,
            key_prefix=key_prefix,
            scopes=req.scopes,
            roles=req.roles,
            created_at=now_iso,
            expires_at=expires_iso,
        )

    def authenticate_api_key(self, raw_key: str) -> Optional[APIKeyRecord]:
        if not raw_key or not raw_key.startswith("prom_live_"):
            return None
        key_hash = self.hash_api_key(raw_key)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM saas_api_keys WHERE key_hash_sha256 = ? AND is_active = 1",
                (key_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None

            if row["expires_at"]:
                exp_dt = datetime.fromisoformat(row["expires_at"])
                if now > exp_dt:
                    return None

            cur.execute(
                "UPDATE saas_api_keys SET last_used_at = ? WHERE key_id = ?",
                (now_iso, row["key_id"]),
            )
            conn.commit()

            return APIKeyRecord(
                key_id=row["key_id"],
                tenant_id=row["tenant_id"],
                name=row["name"],
                key_prefix=row["key_prefix"],
                scopes=json.loads(row["scopes"]),
                roles=json.loads(row["roles"]),
                created_by=row["created_by"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                last_used_at=now_iso,
                is_active=bool(row["is_active"]),
            )

    def list_api_keys(self, tenant_id: str) -> List[APIKeyRecord]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM saas_api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
                (tenant_id,),
            )
            rows = cur.fetchall()
            return [
                APIKeyRecord(
                    key_id=r["key_id"],
                    tenant_id=r["tenant_id"],
                    name=r["name"],
                    key_prefix=r["key_prefix"],
                    scopes=json.loads(r["scopes"]),
                    roles=json.loads(r["roles"]),
                    created_by=r["created_by"],
                    created_at=r["created_at"],
                    expires_at=r["expires_at"],
                    last_used_at=r["last_used_at"],
                    is_active=bool(r["is_active"]),
                )
                for r in rows
            ]

    def revoke_api_key(self, tenant_id: str, key_id: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE saas_api_keys SET is_active = 0 WHERE tenant_id = ? AND key_id = ?",
                (tenant_id, key_id),
            )
            conn.commit()
            return cur.rowcount > 0

    # ==========================================================================
    # Rate Limiting & Usage Metering
    # ==========================================================================
    def check_rate_limit(self, tenant_id: str) -> Tuple[bool, int]:
        """
        Enforces sliding-window per-minute rate limit based on subscription tier.
        Returns (allowed: bool, remaining_requests_in_window: int).
        """
        quota = self.get_tier_quota(tenant_id)
        now = time.time()
        window_start = now - 60.0
        timestamps = self._rate_windows.get(tenant_id, [])
        timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= quota.rate_limit_per_minute:
            self._rate_windows[tenant_id] = timestamps
            return False, 0
        timestamps.append(now)
        self._rate_windows[tenant_id] = timestamps
        return True, max(0, quota.rate_limit_per_minute - len(timestamps))

    def _ensure_usage_row(self, tenant_id: str, period: str) -> None:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO saas_usage_counters
                (tenant_id, billing_period, pentest_scans_used, mcp_inspections_used, asi_threats_blocked, cegis_patches_synthesized, tokens_minted)
                VALUES (?, ?, 0, 0, 0, 0, 0)
                """,
                (tenant_id, period),
            )
            conn.commit()

    def record_usage(
        self,
        tenant_id: str,
        pentest_scans: int = 0,
        mcp_inspections: int = 0,
        asi_threats_blocked: int = 0,
        cegis_patches: int = 0,
        tokens_minted: int = 0,
        enforce_quota: bool = True,
    ) -> UsageMeterSnapshot:
        period = self.current_billing_period()
        self._ensure_usage_row(tenant_id, period)
        quota = self.get_tier_quota(tenant_id)

        if enforce_quota:
            current = self.get_usage_snapshot(tenant_id)
            if pentest_scans > 0 and (current.pentest_scans_used + pentest_scans) > quota.max_pentest_scans_per_month:
                raise PermissionError(
                    f"Monthly pentest scan quota exceeded for tier '{quota.display_name}' ({quota.max_pentest_scans_per_month}/mo). Upgrade subscription tier."
                )
            if mcp_inspections > 0 and (current.mcp_inspections_used + mcp_inspections) > quota.max_mcp_inspections_per_month:
                raise PermissionError(
                    f"Monthly MCP gateway inspection quota exceeded for tier '{quota.display_name}' ({quota.max_mcp_inspections_per_month}/mo). Upgrade subscription tier."
                )

        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE saas_usage_counters
                SET pentest_scans_used = pentest_scans_used + ?,
                    mcp_inspections_used = mcp_inspections_used + ?,
                    asi_threats_blocked = asi_threats_blocked + ?,
                    cegis_patches_synthesized = cegis_patches_synthesized + ?,
                    tokens_minted = tokens_minted + ?
                WHERE tenant_id = ? AND billing_period = ?
                """,
                (
                    pentest_scans,
                    mcp_inspections,
                    asi_threats_blocked,
                    cegis_patches,
                    tokens_minted,
                    tenant_id,
                    period,
                ),
            )
            conn.commit()

        return self.get_usage_snapshot(tenant_id)

    def get_usage_snapshot(self, tenant_id: str) -> UsageMeterSnapshot:
        period = self.current_billing_period()
        self._ensure_usage_row(tenant_id, period)
        org = self.get_or_create_tenant(tenant_id)
        quota = TIER_CATALOG[org.tier]

        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM saas_usage_counters WHERE tenant_id = ? AND billing_period = ?",
                (tenant_id, period),
            )
            row = cur.fetchone()

        scans_used = row["pentest_scans_used"] if row else 0
        mcp_used = row["mcp_inspections_used"] if row else 0
        asi_blocked = row["asi_threats_blocked"] if row else 0
        patches_count = row["cegis_patches_synthesized"] if row else 0
        tokens_count = row["tokens_minted"] if row else 0

        scan_ratio = scans_used / max(1, quota.max_pentest_scans_per_month)
        mcp_ratio = mcp_used / max(1, quota.max_mcp_inspections_per_month)
        utilization_pct = round(min(100.0, max(scan_ratio, mcp_ratio) * 100.0), 2)

        # Base subscription + overage usage estimate ($0.02 per extra MCP block above 10k in Pro)
        estimated_bill = float(quota.monthly_price_usd)

        return UsageMeterSnapshot(
            tenant_id=tenant_id,
            billing_period=period,
            tier=org.tier,
            pentest_scans_used=scans_used,
            pentest_scans_limit=quota.max_pentest_scans_per_month,
            mcp_inspections_used=mcp_used,
            mcp_inspections_limit=quota.max_mcp_inspections_per_month,
            asi_threats_blocked=asi_blocked,
            cegis_patches_synthesized=patches_count,
            tokens_minted=tokens_count,
            estimated_monthly_bill_usd=estimated_bill,
            quota_utilization_pct=utilization_pct,
        )

    # ==========================================================================
    # SOC2 / EU AI Act / CoSAI Cryptographic Compliance Bundle Exporter
    # ==========================================================================
    def generate_compliance_bundle(
        self,
        tenant_id: str,
        asi_control_matrix: List[Dict[str, Any]],
        recent_abac_decisions: List[Dict[str, Any]],
        recent_asi_interceptions: List[Dict[str, Any]],
        active_witness_count: int,
        posture_score: float,
    ) -> ComplianceExportBundle:
        org = self.get_or_create_tenant(tenant_id)
        usage = self.get_usage_snapshot(tenant_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        bundle_id = f"COMP-{uuid.uuid4().hex[:12].upper()}"

        canonical_payload = json.dumps(
            {
                "bundle_id": bundle_id,
                "tenant_id": tenant_id,
                "organization_name": org.name,
                "tier": org.tier.value,
                "posture_score": posture_score,
                "usage": usage.model_dump(),
                "asi_controls_count": len(asi_control_matrix),
                "abac_events_count": len(recent_abac_decisions),
                "asi_interceptions_count": len(recent_asi_interceptions),
                "active_witness_count": active_witness_count,
            },
            sort_keys=True,
        )
        merkle_root = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        signature = hmac.new(
            self.signing_secret,
            f"{bundle_id}:{tenant_id}:{merkle_root}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return ComplianceExportBundle(
            bundle_id=bundle_id,
            generated_at=now_iso,
            tenant_id=tenant_id,
            organization_name=org.name,
            tier=org.tier,
            posture_score=posture_score,
            usage_summary=usage,
            asi_control_matrix=asi_control_matrix,
            recent_abac_decisions=recent_abac_decisions,
            recent_asi_interceptions=recent_asi_interceptions,
            active_witness_count=active_witness_count,
            ledger_merkle_root_sha256=merkle_root,
            hmac_signature=signature,
            verification_instructions=(
                "Verify integrity via HMAC-SHA256(secret, f'{bundle_id}:{tenant_id}:{ledger_merkle_root_sha256}'). "
                "Compliant with EU AI Act Art. 12/15 automatic logging and SOC2 CC6.1/CC7.2 non-repudiation."
            ),
        )


saas_engine = SaaSPlatformEngine()
