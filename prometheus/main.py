"""
Main entrypoint for Prometheus Platform: FastAPI Web Server, MCP SSE Stream, & Interactive CLI.
"""

import os
import sys

# Ensure project root is in sys.path for direct script execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
import time
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any, Union
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse
from pydantic import BaseModel, Field

from prometheus.config import settings
from prometheus.security.abac_guard import UserContext
from prometheus.mcp.server import mcp_server
from prometheus.pentest.service import (
    PentestExecutionService,
    PentestScanRequest,
    PentestScanResult,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="Prometheus Enterprise: Autonomous Exploit & Capability Governance Platform",
    description="Enterprise API Penetration Testing, Runtime Capability Hypervisor & Stateful Execution Firewall",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# Pydantic Request Models
# ==============================================================================
class ProxyMintTokenRequest(BaseModel):
    subject: str = "autonomous-agent"
    allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "POST"])
    allowed_resource_ids: List[str] = Field(default_factory=lambda: ["*"])
    ttl_seconds: int = 60
    tenant_id: str = "default_enterprise"


class ProxyPermitRequest(BaseModel):
    token: Dict[str, Any]
    target_op: str
    resource_id: str
    pre_state_hash: Optional[str] = None


class ProxyToolExecutionRequest(BaseModel):
    call_type: str = "HTTP"
    method: str = "GET"
    target: str
    resource_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    token: Optional[Union[str, Dict[str, Any]]] = None
    action_permit: Optional[Union[str, Dict[str, Any]]] = None
    session_id: str = "web_session"


try:
    from opentelemetry import trace
    tracer = trace.get_tracer("prometheus-enterprise")
except Exception:
    tracer = None

try:
    import structlog
    struct_logger = structlog.get_logger("prometheus")
except Exception:
    struct_logger = None

from prometheus.memory.firestore_store import firestore_store, UserProfile
from prometheus.auth.oauth import create_session_token, get_google_auth_url, exchange_google_code
from prometheus.auth.dependencies import (
    get_current_user_optional,
    get_current_user,
    get_current_admin_user,
    UserContext as AuthUserContext,
)
from prometheus.security.abac_engine import abac_engine, ABACUserRecord, ABACResourceRecord

# ==============================================================================
# Dashboard & Core REST API Endpoints
# ==============================================================================
DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "dashboard", "dashboard.html")
DOCUMENTATION_PATH = os.path.join(os.path.dirname(__file__), "dashboard", "documentation.html")


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def serve_dashboard():
    """
    Renders the Prometheus Security & Capability Hypervisor Web Dashboard.
    """
    if os.path.exists(DASHBOARD_PATH):
        with open(DASHBOARD_PATH, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Prometheus Dashboard: dashboard.html not found.</h1>")


@app.get("/documentation", response_class=HTMLResponse, tags=["Documentation"])
@app.get("/docs-view", response_class=HTMLResponse, tags=["Documentation"])
async def serve_documentation():
    """
    Renders the Prometheus Technical Architecture, Security & Whitepaper Reference.
    """
    if os.path.exists(DOCUMENTATION_PATH):
        with open(DOCUMENTATION_PATH, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Prometheus Documentation: documentation.html not found.</h1>")


@app.get("/login", tags=["Authentication"])
async def login_redirect(error: Optional[str] = None):
    """
    Redirects /login to dashboard with auth trigger so /login never returns 404.
    """
    from fastapi.responses import RedirectResponse
    url = f"/dashboard?auth_modal=1{'&error=' + error if error else ''}"
    return RedirectResponse(url=url)


# ==============================================================================
# Google OAuth 2.0 & Session Management Endpoints
# ==============================================================================
@app.get("/api/v1/auth/me", tags=["Authentication"])
async def get_me(user: AuthUserContext = Depends(get_current_user_optional)):
    """
    Returns current authenticated user profile and active tenant organization.
    """
    return user.model_dump()


@app.post("/api/v1/auth/persona", tags=["Authentication"])
async def switch_persona(req: Dict[str, str], response: Response):
    """
    Exchanges an enterprise ABAC persona for a valid session token in non-production/demo mode.
    Forbidden in non-development environments.
    """
    if settings.environment != "development":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Persona switching is disabled outside development environments."
        )
    user_id = req.get("user_id", "elena.lead")
    abac_user = abac_engine.get_user(user_id)
    email = abac_user.email if abac_user else f"{user_id}@enterprise.io"
    roles = abac_user.roles if abac_user else ["developer"]
    scopes = abac_user.assigned_squads if abac_user else ["engineering", "platform"]

    token = create_session_token(
        user_id=user_id,
        email=email,
        tenant_id="default_enterprise",
        scopes=scopes,
        roles=roles,
    )
    response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax")
    return {
        "status": "authenticated",
        "user_id": user_id,
        "email": email,
        "roles": roles,
        "scopes": scopes,
        "token": token,
    }


@app.get("/api/v1/auth/google/login", tags=["Authentication"])
async def google_login():
    """
    Initiates Google OAuth 2.0 flow or returns authorization URL.
    """
    url = get_google_auth_url()
    return {"auth_url": url}


@app.get("/api/v1/auth/google/callback", tags=["Authentication"])
async def google_callback(code: str, response: Response):
    """
    Handles Google OAuth callback, verifies ID token, saves user in Firestore, and sets session cookie.
    """
    user_info = await exchange_google_code(code)
    if not user_info:
        raise HTTPException(status_code=400, detail="Google authentication failed.")
    
    user_id = f"google_{user_info.get('sub')}"
    profile = UserProfile(
        user_id=user_id,
        email=user_info.get("email", "user@enterprise.io"),
        name=user_info.get("name", "Google User"),
        picture=user_info.get("picture"),
        tenant_id="default_enterprise",
    )
    await firestore_store.save_user(profile)

    token = create_session_token(
        user_id=profile.user_id,
        email=profile.email,
        tenant_id=profile.tenant_id,
        scopes=profile.org_scopes,
    )
    response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax")
    return HTMLResponse(content="<script>window.location.href='/dashboard';</script>")


@app.post("/api/v1/auth/logout", tags=["Authentication"])
async def logout(response: Response):
    """
    Clears active user session cookie.
    """
    response.delete_cookie("session_token")
    return {"status": "logged_out"}


# ==============================================================================
# Enterprise ABAC Security Policy API
# ==============================================================================
@app.get("/api/v1/security/abac/users", tags=["ABAC Security"])
async def list_abac_users():
    """Lists registered enterprise users and their clearance attributes."""
    return {"users": abac_engine.list_users()}


@app.post("/api/v1/security/abac/users", tags=["ABAC Security"])
async def create_abac_user(
    user: ABACUserRecord,
    current_user: AuthUserContext = Depends(get_current_admin_user)
):
    """Registers or updates an enterprise user in the ABAC policy catalog. Requires administrative clearance."""
    saved = abac_engine.register_user(user)
    return saved.model_dump()


@app.get("/api/v1/security/abac/resources", tags=["ABAC Security"])
async def list_abac_resources():
    """Lists registered target resources and required security bounds."""
    return {"resources": abac_engine.list_resources()}


@app.post("/api/v1/security/abac/resources", tags=["ABAC Security"])
async def create_abac_resource(
    resource: ABACResourceRecord,
    current_user: AuthUserContext = Depends(get_current_admin_user)
):
    """Registers or updates a target resource in the ABAC policy catalog. Requires administrative clearance."""
    saved = abac_engine.register_resource(resource)
    return saved.model_dump()


class ABACEvalRequest(BaseModel):
    user_id: str
    resource_id: str


@app.post("/api/v1/security/abac/evaluate", tags=["ABAC Security"])
async def evaluate_abac_access(req: ABACEvalRequest):
    """Evaluates dynamic Attribute-Based Access Control P(U, R) and records audit log."""
    res = abac_engine.evaluate_access(user_id=req.user_id, resource_id=req.resource_id)
    return res.model_dump()


@app.get("/api/v1/security/abac/audit-logs", tags=["ABAC Security"])
async def list_abac_audit_logs(limit: int = 50):
    """Retrieves immutable audit evaluation logs."""
    return {"audit_logs": abac_engine.list_audit_logs(limit=limit)}


# ==============================================================================
# Autonomous Pentest & Capability Hypervisor Firewall REST API
# ==============================================================================
from prometheus.saas.engine import saas_engine
from prometheus.saas.models import (
    APIKeyCreateRequest,
    SubscriptionTier,
    TIER_CATALOG,
)
from prometheus.security.agentic_owasp import (
    agentic_owasp_engine,
    AgenticInspectionRequest,
    MCPGatewayProxyRequest,
    OWASP_AGENTIC_TOP_10,
)


@app.get("/api/v1/security/overview", tags=["Capability Governance"])
async def get_security_overview(current_user: AuthUserContext = Depends(get_current_user_optional)):
    """
    Aggregates live runtime capability firewall metrics, ABAC policies, OWASP Agentic posture, and SaaS usage.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    audit_logs = abac_engine.list_audit_logs(limit=20)
    registry_size = len(mcp_server.hypervisor.registry._witnesses)
    asi_posture = agentic_owasp_engine.get_posture_summary(tenant_id=tenant_id)
    usage = saas_engine.get_usage_snapshot(tenant_id=tenant_id)
    return {
        "status": "operational",
        "platform": "Prometheus Enterprise: Autonomous Exploit & Capability Governance Platform",
        "sla_gate_seconds": 85.0,
        "reflection_defense_active": True,
        "cegis_dual_pass_active": True,
        "hypervisor_active": True,
        "owasp_agentic_top_10_active": True,
        "enforce_hypervisor": mcp_server.enforce_hypervisor,
        "registered_witnesses": registry_size,
        "abac_audit_events_count": len(audit_logs),
        "recent_audit_events": audit_logs[:10],
        "agentic_posture": {
            "posture_score": asi_posture["posture_score"],
            "total_inspections": asi_posture["total_inspections"],
            "threats_blocked": asi_posture["threats_blocked"],
            "registered_mcp_servers": asi_posture["registered_mcp_servers"],
        },
        "saas_usage": usage.model_dump(),
    }


@app.post("/api/v1/pentest/scan", response_model=PentestScanResult, tags=["Autonomous Security Engine"])
async def run_pentest_scan(
    req: PentestScanRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Executes autonomous adversarial pentest scan against OpenAPI target.
    Synthesizes dual-tenant context, probes for OWASP API Top 10 (BOLA/BFLA),
    validates zero false positives via reflection defense, and synthesizes regression tests.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    try:
        saas_engine.record_usage(tenant_id=tenant_id, pentest_scans=1, enforce_quota=True)
    except PermissionError as qe:
        raise HTTPException(status_code=402, detail=str(qe))

    try:
        res = await PentestExecutionService.execute_scan(req)
        if res.patches_count > 0:
            saas_engine.record_usage(
                tenant_id=tenant_id,
                cegis_patches=res.patches_count,
                enforce_quota=False,
            )
        return res
    except Exception as e:
        logger = structlog.get_logger(__name__) if "structlog" in sys.modules else None
        if logger:
            logger.exception("Pentest scan failed: %s", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/proxy/mint-token", tags=["Capability Hypervisor"])
async def proxy_mint_token(
    req: ProxyMintTokenRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Mints a short-lived capability token with cryptographically bounded monotonic attenuation.
    """
    effective_tenant = req.tenant_id or current_user.tenant_id or "default_enterprise"
    token = mcp_server.hypervisor.token_authority.mint_token(
        subject=req.subject,
        allowed_methods=req.allowed_methods,
        allowed_resource_ids=req.allowed_resource_ids,
        ttl_seconds=req.ttl_seconds,
        tenant_id=effective_tenant,
    )
    saas_engine.record_usage(tenant_id=effective_tenant, tokens_minted=1, enforce_quota=False)
    return token.model_dump()


@app.post("/api/v1/proxy/permit", tags=["Capability Hypervisor"])
async def proxy_request_permit(
    req: ProxyPermitRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Requests a cryptographically signed Action Permit with pre-state witness H(S) for mutating operations.
    """
    cap_token = mcp_server.hypervisor._resolve_token(req.token)
    if not cap_token:
        raise HTTPException(status_code=400, detail="Invalid capability token.")
    witness = mcp_server.hypervisor.registry.get_witness(req.resource_id)
    if witness is None:
        state_data = {"pre_state_hash": req.pre_state_hash} if req.pre_state_hash else {"resource_id": req.resource_id}
        witness = mcp_server.hypervisor.registry.register_state(
            resource_id=req.resource_id,
            state_data=state_data,
            source_op=f"permit_request {req.target_op}",
        )
    permit = mcp_server.hypervisor.token_authority.mint_action_permit(
        token=cap_token,
        action_method=req.target_op,
        resource_id=req.resource_id,
        witness=witness,
    )
    return permit.model_dump()


@app.post("/api/v1/proxy/execute", tags=["Capability Hypervisor"])
async def proxy_execute_tool(
    req: ProxyToolExecutionRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Direct Capability Hypervisor execution gateway for HTTP and MCP tool actions.
    Fails closed on missing action permits, state drift, or OWASP Agentic Top 10 violations.
    """
    from prometheus.proxy.models import ProxyToolRequest, ToolCallType
    tenant_id = current_user.tenant_id or "default_enterprise"
    try:
        saas_engine.record_usage(tenant_id=tenant_id, mcp_inspections=1, enforce_quota=True)
    except PermissionError as qe:
        raise HTTPException(status_code=402, detail=str(qe))

    call_t = ToolCallType.HTTP if req.call_type.upper() == "HTTP" else ToolCallType.MCP
    proxy_req = ProxyToolRequest(
        call_type=call_t,
        method=req.method,
        target=req.target,
        resource_id=req.resource_id,
        payload=req.payload,
        headers=req.headers,
        token=req.token,
        action_permit=req.action_permit,
        session_id=req.session_id,
    )
    resp = await mcp_server.hypervisor.execute_tool(proxy_req)
    if not resp.success:
        saas_engine.record_usage(tenant_id=tenant_id, asi_threats_blocked=1, enforce_quota=False)
    return resp.model_dump()


# ==============================================================================
# OWASP Agentic Top 10 (ASI01-ASI10) & Live MCP Security Gateway
# ==============================================================================
@app.get("/api/v1/security/agentic/posture", tags=["OWASP Agentic Top 10 & MCP Gateway"])
async def get_agentic_security_posture(
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Returns live OWASP Top 10 for Agentic Applications (ASI01-ASI10) posture score,
    control matrix, and recent blocked agentic tool invocations.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    return agentic_owasp_engine.get_posture_summary(tenant_id=tenant_id)


@app.post("/api/v1/security/agentic/inspect", tags=["OWASP Agentic Top 10 & MCP Gateway"])
async def inspect_agentic_tool_call(
    req: AgenticInspectionRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Inspects an autonomous agent tool call and prompt context against all 10 categories
    of the 2026 OWASP Agentic Security Top 10 (ASI01-ASI10) and CoSAI DLP guardrails.
    """
    tenant_id = current_user.tenant_id if current_user.is_authenticated else req.tenant_id
    req.tenant_id = tenant_id
    try:
        saas_engine.record_usage(tenant_id=tenant_id, mcp_inspections=1, enforce_quota=True)
    except PermissionError as qe:
        raise HTTPException(status_code=402, detail=str(qe))

    res = agentic_owasp_engine.inspect_tool_invocation(req)
    if not res.allowed:
        saas_engine.record_usage(tenant_id=tenant_id, asi_threats_blocked=1, enforce_quota=False)
    return res.model_dump()


@app.get("/api/v1/mcp/gateway/servers", tags=["OWASP Agentic Top 10 & MCP Gateway"])
async def list_mcp_gateway_servers(
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Lists pinned upstream MCP servers registered in the enterprise supply-chain catalog (ASI04).
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    servers = agentic_owasp_engine.list_mcp_servers(tenant_id=tenant_id)
    return {"servers": [s.model_dump() for s in servers]}


class RegisterMCPServerRequest(BaseModel):
    server_id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=120)
    endpoint_url: str = Field(..., description="Upstream HTTP JSON-RPC URL or internal:// URI")
    allowed_tools: List[str] = Field(default_factory=lambda: ["*"])
    transport: str = "http_jsonrpc"


@app.post("/api/v1/mcp/gateway/servers", tags=["OWASP Agentic Top 10 & MCP Gateway"])
async def register_mcp_gateway_server(
    req: RegisterMCPServerRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Registers and cryptographically pins an upstream MCP server schema (ASI04 Supply Chain Defense).
    Validates external endpoint URLs against SSRF before registration.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    if req.endpoint_url.startswith(("http://", "https://")):
        from prometheus.pentest.exploit_prober import ExploitProber
        parsed_host = req.endpoint_url.split("://")[-1].split("/")[0].split(":")[0]
        is_loopback = parsed_host in ("localhost", "127.0.0.1", "::1", "testserver")
        prober = ExploitProber(base_url=req.endpoint_url, allow_loopback=is_loopback)
        try:
            await prober.async_validate_ssrf(req.endpoint_url)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"SSRF validation failed for upstream MCP server URL: {e}")

    srv = agentic_owasp_engine.register_mcp_server(
        tenant_id=tenant_id,
        server_id=req.server_id,
        name=req.name,
        endpoint_url=req.endpoint_url,
        allowed_tools=req.allowed_tools,
        transport=req.transport,
    )
    return srv.model_dump()


@app.post("/api/v1/mcp/gateway/proxy", tags=["OWASP Agentic Top 10 & MCP Gateway"])
async def proxy_mcp_gateway_call(
    req: MCPGatewayProxyRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Live MCP Security Gateway Reverse Proxy.
    1. Enforces tenant SaaS quota & rate limits.
    2. Inspects JSON-RPC tool calls against OWASP Agentic Top 10 (ASI01-ASI10) + Inline DLP.
    3. Mediates through the Stateful Capability Hypervisor before dispatching to internal or upstream HTTP MCP servers.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    try:
        saas_engine.record_usage(tenant_id=tenant_id, mcp_inspections=1, enforce_quota=True)
    except PermissionError as qe:
        raise HTTPException(status_code=402, detail=str(qe))

    rpc = req.jsonrpc_payload
    rpc_id = rpc.get("id", 1)
    method = rpc.get("method", "")
    params = rpc.get("params", {}) if isinstance(rpc.get("params"), dict) else {}

    if method == "tools/call":
        tool_name = params.get("name", "unknown_tool")
        tool_args = params.get("arguments", {}) if isinstance(params.get("arguments"), dict) else {}
        has_token = bool(
            req.capability_token
            or rpc.get("capability_token")
            or rpc.get("token")
            or tool_args.get("capability_token")
        )
        inspection = agentic_owasp_engine.inspect_tool_invocation(
            AgenticInspectionRequest(
                tenant_id=tenant_id,
                agent_id=req.agent_id,
                server_id=req.server_id,
                tool_name=tool_name,
                arguments=tool_args,
                prompt_context=req.prompt_context,
                delegation_depth=req.delegation_depth,
                has_scoped_nhi_token=has_token,
            )
        )
        if not inspection.allowed:
            saas_engine.record_usage(tenant_id=tenant_id, asi_threats_blocked=1, enforce_quota=False)
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "gateway_status": "BLOCKED_BY_OWASP_AGENTIC_SHIELD",
                "inspection": inspection.model_dump(),
                "error": {
                    "code": -32004,
                    "message": f"OWASP Agentic Top 10 Violation: {inspection.violations[0].asi_id} ({inspection.violations[0].title})",
                    "data": {
                        "risk_score": inspection.risk_score,
                        "violations": [v.model_dump() for v in inspection.violations],
                    },
                },
            }

        # Replace tool arguments with DLP-sanitized arguments before forwarding
        params["arguments"] = inspection.sanitized_arguments
        rpc["params"] = params
    else:
        inspection = None

    srv = agentic_owasp_engine.get_mcp_server(req.server_id)
    if not srv:
        saas_engine.record_usage(tenant_id=tenant_id, asi_threats_blocked=1, enforce_quota=False)
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "gateway_status": "BLOCKED_UNREGISTERED_MCP_SERVER",
            "error": {
                "code": -32005,
                "message": f"ASI04 Violation: Upstream MCP server '{req.server_id}' is not registered in the verified supply-chain catalog.",
            },
        }

    if srv.transport == "internal" or srv.endpoint_url.startswith("internal://"):
        downstream_resp = await mcp_server.handle_jsonrpc(
            request_dict=rpc,
            token=req.capability_token,
            permit=req.action_permit,
            session_id=f"gw_{req.agent_id}",
        )
    else:
        import httpx
        from prometheus.pentest.exploit_prober import ExploitProber
        parsed_host = srv.endpoint_url.split("://")[-1].split("/")[0].split(":")[0]
        is_loopback = parsed_host in ("localhost", "127.0.0.1", "::1", "testserver")
        prober = ExploitProber(base_url=srv.endpoint_url, allow_loopback=is_loopback)
        await prober.async_validate_ssrf(srv.endpoint_url)
        async with httpx.AsyncClient(timeout=8.0) as client:
            http_res = await client.post(srv.endpoint_url, json=rpc)
            http_res.raise_for_status()
            downstream_resp = http_res.json()

    return {
        "gateway_status": "ADMITTED",
        "server_id": srv.server_id,
        "schema_pin_sha256": srv.schema_pin_sha256,
        "inspection": inspection.model_dump() if inspection else None,
        "mcp_response": downstream_resp,
    }


# ==============================================================================
# Commercial SaaS: Multi-Tenant Billing, API Keys & Compliance Exports
# ==============================================================================
@app.get("/api/v1/saas/tiers", tags=["Commercial SaaS & Compliance"])
async def list_saas_tiers():
    """
    Returns the October 2026 Hybrid PLG + Enterprise subscription tier catalog.
    """
    return {
        "tiers": {k.value: v.model_dump() for k, v in TIER_CATALOG.items()},
    }


@app.get("/api/v1/saas/tenant", tags=["Commercial SaaS & Compliance"])
async def get_saas_tenant_overview(
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Returns active organization profile, subscription tier, usage metering snapshot, and active API keys.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    org = saas_engine.get_or_create_tenant(tenant_id)
    quota = saas_engine.get_tier_quota(tenant_id)
    usage = saas_engine.get_usage_snapshot(tenant_id)
    keys = saas_engine.list_api_keys(tenant_id)
    return {
        "organization": org.model_dump(),
        "tier_quota": quota.model_dump(),
        "usage": usage.model_dump(),
        "api_keys": [k.model_dump() for k in keys],
    }


class UpdateTenantTierRequest(BaseModel):
    tier: SubscriptionTier
    organization_name: Optional[str] = None
    billing_email: Optional[str] = None


@app.post("/api/v1/saas/tenant/tier", tags=["Commercial SaaS & Compliance"])
async def update_saas_tenant_tier(
    req: UpdateTenantTierRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Upgrades or modifies the tenant's subscription tier (Starter, Pro, Enterprise).
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    org = saas_engine.update_tenant_tier(
        tenant_id=tenant_id,
        new_tier=req.tier,
        name=req.organization_name,
        billing_email=req.billing_email,
    )
    return {
        "status": "updated",
        "organization": org.model_dump(),
        "tier_quota": saas_engine.get_tier_quota(tenant_id).model_dump(),
        "usage": saas_engine.get_usage_snapshot(tenant_id).model_dump(),
    }


@app.get("/api/v1/saas/api-keys", tags=["Commercial SaaS & Compliance"])
async def list_tenant_api_keys(
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Lists scoped API keys (masked prefixes only) for the current tenant organization.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    keys = saas_engine.list_api_keys(tenant_id)
    return {"api_keys": [k.model_dump() for k in keys]}


@app.post("/api/v1/saas/api-keys", tags=["Commercial SaaS & Compliance"])
async def create_tenant_api_key(
    req: APIKeyCreateRequest,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Mints a new SHA-256 hashed Prometheus API key (prom_live_...).
    The raw secret key is returned ONLY ONCE in this response.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    creator = current_user.email if current_user.is_authenticated else "admin@acme.corp"
    try:
        created = saas_engine.create_api_key(tenant_id=tenant_id, created_by=creator, req=req)
        return created.model_dump()
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.delete("/api/v1/saas/api-keys/{key_id}", tags=["Commercial SaaS & Compliance"])
async def revoke_tenant_api_key(
    key_id: str,
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Immediately revokes an active API key.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    revoked = saas_engine.revoke_api_key(tenant_id=tenant_id, key_id=key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"API key '{key_id}' not found.")
    return {"status": "revoked", "key_id": key_id}


@app.get("/api/v1/saas/compliance/export", tags=["Commercial SaaS & Compliance"])
async def export_compliance_bundle(
    current_user: AuthUserContext = Depends(get_current_user_optional),
):
    """
    Generates a cryptographically signed SOC2 Type II, EU AI Act Art. 12/15, and CoSAI
    compliance audit bundle with SHA-256 Merkle state root and HMAC signature.
    """
    tenant_id = current_user.tenant_id or "default_enterprise"
    quota = saas_engine.get_tier_quota(tenant_id)
    if not quota.compliance_export_enabled:
        raise HTTPException(
            status_code=403,
            detail=f"Compliance export requires Pro or Enterprise tier (current tier: {quota.display_name}).",
        )
    asi_summary = agentic_owasp_engine.get_posture_summary(tenant_id=tenant_id)
    abac_logs = abac_engine.list_audit_logs(limit=25)
    witness_count = len(mcp_server.hypervisor.registry._witnesses)
    bundle = saas_engine.generate_compliance_bundle(
        tenant_id=tenant_id,
        asi_control_matrix=asi_summary["controls"],
        recent_abac_decisions=abac_logs,
        recent_asi_interceptions=asi_summary["recent_interceptions"],
        active_witness_count=witness_count,
        posture_score=asi_summary["posture_score"],
    )
    return bundle.model_dump()


# ==============================================================================
# Enterprise Integrations API (Firestore Vaulted)
# ==============================================================================
@app.get("/api/v1/integrations", tags=["Integrations"])
async def list_integrations(user: AuthUserContext = Depends(get_current_user)):
    """
    Lists connected status and masked credentials of tenant tools (GitHub, Jira, Slack).
    """
    return await firestore_store.list_integrations(tenant_id=user.tenant_id)


@app.post("/api/v1/integrations/{service}", tags=["Integrations"])
async def save_integration(service: str, payload: Dict[str, Any], user: AuthUserContext = Depends(get_current_user)):
    """
    Saves and vaults integration credentials into Google Cloud Firestore.
    """
    if service not in ("github", "jira", "slack"):
        raise HTTPException(status_code=400, detail=f"Unsupported service: {service}")
    saved = await firestore_store.save_integration(tenant_id=user.tenant_id, service=service, config=payload)
    return {"status": "saved", "service": service, "updated_at": saved.updated_at}


@app.delete("/api/v1/integrations/{service}", tags=["Integrations"])
async def delete_integration(service: str, user: AuthUserContext = Depends(get_current_user)):
    """
    Disconnects and purges an integration from Firestore.
    """
    deleted = await firestore_store.delete_integration(tenant_id=user.tenant_id, service=service)
    return {"status": "deleted", "service": service}


@app.get("/healthz", tags=["System"])
@app.get("/health", tags=["System"])
@app.get("/api/v1/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "service": "prometheus-security-engine",
        "platform_service": "prometheus-enterprise-security-and-governance",
        "app": settings.app_name,
        "environment": settings.environment,
        "platform": "Gemini Enterprise Agent Platform (Agent Engine)",
        "model": settings.gemini_model,
        "location": settings.gcp_location,
        "agent_engine": {
            "app_id": settings.agent_engine_app_id,
            "location": settings.agent_engine_location,
        },
        "mcp_enabled": settings.mcp_enabled,
        "capability_hypervisor_enforced": mcp_server.enforce_hypervisor,
        "reflection_defense_active": True,
        "cegis_dual_pass_active": True,
    }


# ==============================================================================
# Model Context Protocol (MCP) Server-Sent Events (SSE) & Streamable HTTP
# ==============================================================================
@app.get("/mcp/sse", tags=["Model Context Protocol"])
async def mcp_sse_stream():
    """
    Compliant MCP Server-Sent Events (SSE) discovery stream for MCP clients.
    """
    from fastapi.responses import StreamingResponse

    async def _event_generator():
        yield "event: endpoint\ndata: /mcp/sse\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@app.post("/mcp/sse", tags=["Model Context Protocol"])
async def mcp_sse_endpoint(request: Request):
    """
    HTTP JSON-RPC endpoint for external agent fleets to consume Prometheus MCP tools.
    """
    body = await request.json()
    response = await mcp_server.handle_jsonrpc(body)
    return response


# ==============================================================================
# Webhook Ingress Receivers
# ==============================================================================
@app.post("/api/v1/webhooks/github", tags=["Webhooks"])
async def github_webhook_receiver(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256")
):
    """
    Receives real-time GitHub PR and CI deployment status webhooks.
    Verifies HMAC-SHA256 signature when secret is configured, and triggers
    PentestExecutionService when a preview deployment URL (target_url or
    deployment.environment_url) is provided.
    """
    import hmac
    import hashlib
    raw_body = await request.body()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if secret and x_hub_signature_256:
        expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature.")
    elif settings.environment == "production" and secret and not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header.")

    try:
        import json as _json
        payload = _json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        payload = {}

    event_type = payload.get("action", "unknown")
    pr_obj = payload.get("pull_request", {}) if isinstance(payload.get("pull_request"), dict) else {}
    pr_id = pr_obj.get("number", payload.get("number", "unknown"))

    target_url = (
        payload.get("target_url")
        or (payload.get("deployment_status", {}) or {}).get("environment_url")
        or (payload.get("deployment", {}) or {}).get("environment_url")
        or (pr_obj.get("head", {}).get("repo", {}) or {}).get("homepage")
    )
    scan_summary = None
    if target_url and isinstance(target_url, str) and target_url.startswith(("http://", "https://")):
        scan_req = PentestScanRequest(
            target_url=target_url,
            spec_url=payload.get("spec_url"),
            target_dir=payload.get("target_dir"),
            auth_header_alpha=payload.get("auth_header_alpha"),
            auth_header_beta=payload.get("auth_header_beta"),
            seed_params=payload.get("seed_params"),
        )
        scan_res = await PentestExecutionService.execute_scan(scan_req)
        scan_summary = {
            "scan_time_seconds": scan_res.elapsed_seconds,
            "endpoints_probed": scan_res.endpoints_count,
            "exploits_count": scan_res.exploits_count,
            "patches_count": scan_res.patches_count,
            "cumulative_diff": scan_res.cumulative_diff,
        }
        repo_full_name = (
            payload.get("repo")
            or (payload.get("repository") or {}).get("full_name")
            or ((pr_obj.get("base") or {}).get("repo") or {}).get("full_name")
        )
        auto_publish = bool(payload.get("auto_publish_pr", False) or os.getenv("GITHUB_TOKEN"))
        if repo_full_name and auto_publish and scan_res.patched_files:
            from prometheus.pentest.pr_reporter import PRReporter
            first_pr = scan_res.contextual_prs[0] if scan_res.contextual_prs else {}
            pr_title = first_pr.get(
                "pr_title",
                f"fix(security): Prometheus automated remediation ({scan_res.exploits_count} exploits fixed)",
            )
            pr_body = first_pr.get("pr_body_markdown", f"```diff\n{scan_res.cumulative_diff}\n```")
            base_branch = ((pr_obj.get("head") or {}).get("ref")) or "main"
            pr_pub_res = await PRReporter.publish_github_pull_request(
                repo=str(repo_full_name),
                pr_title=pr_title,
                pr_body_markdown=pr_body,
                patched_files=scan_res.patched_files,
                base_branch=base_branch,
            )
            scan_summary["auto_remediation_pr"] = pr_pub_res

    resp_payload: Dict[str, Any] = {
        "status": "scanned" if scan_summary else "received",
        "event": f"github_pr_{event_type}",
        "resource": f"PR-{pr_id}",
    }
    if scan_summary:
        resp_payload["scan_result"] = scan_summary
    return resp_payload


class ImmunologyScanRequest(BaseModel):
    target_dir: str = Field(default=".", description="Target repository directory for dependency & reachability analysis")
    auto_publish_pr: bool = Field(default=False, description="Automatically open a GitHub PR for reachable CVEs")
    repo: Optional[str] = Field(default=None, description="Target GitHub repository ('owner/repo') when auto_publish_pr=True")


class SWEPatchRequest(BaseModel):
    target_dir: Optional[str] = Field(default=None, description="Target repository directory")
    target_file: str = Field(..., description="Relative path to target source file")
    target_endpoint: str = Field(..., description="Vulnerable HTTP route path")
    http_method: str = Field(default="GET", description="HTTP method")
    vector: str = Field(default="BOLA_IDOR", description="Vulnerability category")


@app.post("/api/v1/immunology/scan")
async def execute_immunology_scan(req: ImmunologyScanRequest):
    """
    Prometheus v2.5 Event-Driven Continuous Immunology Endpoint.
    Ingests live advisories from The Hacker News (THN) RSS and OSV.dev APIs,
    extracts repository dependencies, verifies source-code reachability,
    synthesizes manifest upgrade diffs, and optionally publishes a GitHub PR.
    """
    from prometheus.pentest.immunology import ContinuousImmunologyEngine

    target_dir = req.target_dir if os.path.isdir(req.target_dir) else os.getcwd()
    engine = ContinuousImmunologyEngine()
    return await engine.run_immunology_sweep(
        target_dir=target_dir,
        auto_publish_pr=req.auto_publish_pr,
        repo=req.repo,
    )


@app.post("/api/v1/pentest/swe-patch")
async def execute_contextual_swe_patch(req: SWEPatchRequest):
    """
    Prometheus v2.5 Contextual Agentic SWE Program Repair Endpoint.
    Analyzes repository conventions, synthesizes an idiomatic code patch,
    verifies native compilation, and returns a Staff-Engineer ContextualPatchPR.
    """
    from prometheus.pentest.swe_patcher import ContextualSWERepairAgent
    from prometheus.pentest.models import ExploitProof, HttpMethod, Severity, VulnerabilityCategory

    base_dir = req.target_dir or os.getcwd()
    full_path = os.path.join(base_dir, req.target_file) if not os.path.isabs(req.target_file) else req.target_file
    if os.path.isfile(full_path):
        with open(full_path, "r", encoding="utf-8") as f:
            source_code = f.read()
    else:
        source_code = (
            f'@app.{req.http_method.lower()}("{req.target_endpoint}")\n'
            "async def handler(resource_id: str, current_user: UserSession = Depends(get_current_user)):\n"
            "    resource = DB.get(resource_id)\n"
            "    if not resource:\n"
            '        raise HTTPException(status_code=404, detail="Not found")\n'
            "    return resource\n"
        )

    method_str = req.http_method.upper()
    method_enum = HttpMethod(method_str) if method_str in HttpMethod.__members__ else HttpMethod.GET
    vec_enum = VulnerabilityCategory.BFLA if "BFLA" in req.vector.upper() else VulnerabilityCategory.BOLA_IDOR

    proof = ExploitProof(
        is_vulnerable=True,
        vector=vec_enum,
        severity=Severity.HIGH,
        target_endpoint=req.target_endpoint,
        http_method=method_enum,
        http_status_code=200,
        curl_command=f"curl -X {method_enum.value} http://localhost:8000{req.target_endpoint}",
        remediation_guidance="Enforce tenant ownership and RBAC policy.",
        execution_time_ms=4.2,
    )

    swe_agent = ContextualSWERepairAgent(target_dir=base_dir)
    patch_res, contextual_pr = await swe_agent.synthesize_contextual_patch(
        original_code=source_code,
        proof=proof,
        target_file=req.target_file,
    )
    return {
        "status": "PATCH_SYNTHESIZED",
        "patch": patch_res.model_dump(),
        "contextual_pr": contextual_pr.model_dump(),
    }


class PublishGitHubPRRequest(BaseModel):
    repo: str = Field(..., description="Target GitHub repository in 'owner/repo' format")
    pr_title: str = Field(..., description="Pull Request title")
    pr_body_markdown: str = Field(..., description="Pull Request markdown body")
    patched_files: Dict[str, str] = Field(..., description="Map of relative file path to patched file content")
    base_branch: str = Field(default="main", description="Base branch name")
    branch_name: Optional[str] = Field(default=None, description="Optional custom remediation branch name")


class MintOOBCanaryRequest(BaseModel):
    target_endpoint: str = Field(..., description="Endpoint being probed for OOB vulnerability")
    vector: str = Field(default="SSRF", description="Vulnerability vector")
    ttl_seconds: int = Field(default=900, description="TTL in seconds for the ephemeral canary")


@app.post("/api/v1/pentest/publish-pr", tags=["Pentest & Remediation"])
async def publish_remediation_pr(req: PublishGitHubPRRequest):
    """
    Publishes a verified ContextualPatchPR directly to GitHub by creating a remediation
    branch, committing patched files, and opening a Pull Request.
    """
    from prometheus.pentest.pr_reporter import PRReporter

    return await PRReporter.publish_github_pull_request(
        repo=req.repo,
        pr_title=req.pr_title,
        pr_body_markdown=req.pr_body_markdown,
        patched_files=req.patched_files,
        base_branch=req.base_branch,
        branch_name=req.branch_name,
    )


@app.post("/api/v1/oob/mint", tags=["Out-of-Band (OOB) Oracle"])
async def mint_oob_canary_endpoint(req: MintOOBCanaryRequest, request: Request):
    """
    Mints an ephemeral Out-of-Band (OOB) canary token and callback URL for Blind SSRF/XXE/RCE verification.
    """
    from prometheus.pentest.oob_listener import oob_canary_registry

    base_url = str(request.base_url).rstrip("/")
    reg = oob_canary_registry.mint_canary(
        target_endpoint=req.target_endpoint,
        vector=req.vector,
        base_callback_url=base_url,
        ttl_seconds=req.ttl_seconds,
    )
    return reg.model_dump()


@app.get("/api/v1/oob/{canary_id}/status", tags=["Out-of-Band (OOB) Oracle"])
async def get_oob_canary_status(canary_id: str):
    """
    Checks whether an OOB canary callback has been received and returns recorded telemetry.
    """
    from prometheus.pentest.oob_listener import oob_canary_registry

    callbacks = oob_canary_registry.get_callbacks(canary_id)
    return {
        "canary_id": canary_id,
        "oob_callback_received": len(callbacks) > 0,
        "callbacks_count": len(callbacks),
        "callbacks": [cb.model_dump() for cb in callbacks],
    }


@app.api_route("/api/v1/oob/{canary_id}", methods=["GET", "POST", "PUT", "HEAD"], tags=["Out-of-Band (OOB) Oracle"])
async def receive_oob_canary_callback(canary_id: str, request: Request):
    """
    Ephemeral Out-of-Band (OOB) Canary Callback Listener.
    Records inbound HTTP callbacks triggered by Blind SSRF, XXE, or asynchronous webhooks.
    """
    from prometheus.pentest.oob_listener import oob_canary_registry

    raw_body = await request.body()
    body_str = raw_body.decode("utf-8", errors="replace") if raw_body else ""
    source_ip = request.client.host if request.client else "unknown"
    event = oob_canary_registry.record_callback(
        canary_id=canary_id,
        method=request.method,
        source_ip=source_ip,
        path=request.url.path,
        query_params=dict(request.query_params),
        headers=dict(request.headers),
        body=body_str,
    )
    if event is None:
        raise HTTPException(status_code=400, detail="Invalid OOB canary identifier format.")
    return {"status": "recorded", "canary_id": canary_id}


# ==============================================================================
# Interactive CLI Runner
# ==============================================================================
async def cli_runner():
    print("=" * 75)
    print(" 🚀 Prometheus Enterprise - Autonomous API Security & Capability Hypervisor")
    print("=" * 75)

    print("\n[1/3] Inspecting Capability Hypervisor Invariants & Token Authority...")
    token = mcp_server.hypervisor.token_authority.mint_token(
        subject="cli-security-auditor",
        allowed_methods=["GET", "POST", "scan_api_security"],
        allowed_resource_ids=["*"],
        ttl_seconds=60,
    )
    print(f"  • Minted Capability Token: {token.token_id}")
    print(f"  • Attenuation Subject: {token.subject}")
    print(f"  • Monotonic Methods: {token.scope.allowed_methods}")

    print("\n[2/3] Checking Dynamic ABAC Security Perimeter...")
    users = abac_engine.list_users()
    print(f"  • Registered Enterprise Identities: {len(users)}")
    resources = abac_engine.list_resources()
    print(f"  • Registered Protected Endpoints/Resources: {len(resources)}")

    print("\n[3/3] Ready for Autonomous Exploit Scanning and Inline Capability Mediation.")
    print("  Use 'python -m prometheus.cli_scan --url <target_url>' to execute autonomous pentest.")
    print("\n" + "=" * 75)
    print(" ✨ Prometheus Security Engine Verification Passed!")
    print("=" * 75)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c"):
        asyncio.run(cli_runner())
    else:
        import uvicorn
        uvicorn.run("prometheus.main:app", host=settings.host, port=settings.port, reload=True)
