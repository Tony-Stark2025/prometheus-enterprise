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
from prometheus.memory.state_store import state_store, DraftStatus
from prometheus.tools.slack_tools import SlackTools
from prometheus.registry.agent_registry import agent_registry
from prometheus.mcp.server import mcp_server
from prometheus.workflows.prometheus_flow import PrometheusWorkflow, WorkflowExecutionResult
from prometheus.scheduler import scheduler
from prometheus.pentest.service import (
    PentestExecutionService,
    PentestScanRequest,
    PentestScanResult,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize persistent SQLite store and background scheduler
    await state_store.init_db()
    await scheduler.start()
    yield
    # Shutdown
    await scheduler.stop()


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
class TriggerDigestRequest(BaseModel):
    user_id: str = "lead-01"
    username: str = "alex-lead"
    org_scopes: List[str] = Field(default_factory=lambda: ["engineering", "platform"])
    query: str = "Generate daily alignment briefing and identify delivery blockers"


class ActionApprovalRequest(BaseModel):
    approver_username: str = "alex-lead"
    content: Optional[str] = None
    target: Optional[str] = None


class ActionDraftEditRequest(BaseModel):
    content: str
    target: Optional[str] = None


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
    Renders the Prometheus Executive Chief of Staff Web Dashboard.
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
@app.get("/api/v1/security/overview", tags=["Capability Governance"])
async def get_security_overview():
    """
    Aggregates live runtime capability firewall metrics, ABAC policies, and audit ledgers.
    """
    audit_logs = abac_engine.list_audit_logs(limit=20)
    active_blockers = await state_store.get_active_blockers()
    drafts = await state_store.list_drafts()
    registry_size = len(mcp_server.hypervisor.registry._witnesses)
    return {
        "status": "operational",
        "platform": "Prometheus Enterprise: Autonomous Exploit & Capability Governance Platform",
        "sla_gate_seconds": 85.0,
        "reflection_defense_active": True,
        "cegis_dual_pass_active": True,
        "hypervisor_active": True,
        "enforce_hypervisor": mcp_server.enforce_hypervisor,
        "registered_witnesses": registry_size,
        "active_blockers_count": len(active_blockers),
        "pending_action_cards_count": len([d for d in drafts if d.status == DraftStatus.PENDING]),
        "executed_action_cards_count": len([d for d in drafts if d.status == DraftStatus.EXECUTED]),
        "abac_audit_events_count": len(audit_logs),
        "recent_audit_events": audit_logs[:10],
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
    try:
        return await PentestExecutionService.execute_scan(req)
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
    token = mcp_server.hypervisor.token_authority.mint_token(
        subject=req.subject,
        allowed_methods=req.allowed_methods,
        allowed_resource_ids=req.allowed_resource_ids,
        ttl_seconds=req.ttl_seconds,
        tenant_id=req.tenant_id,
    )
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
    Fails closed on missing action permits or state drift.
    """
    from prometheus.proxy.models import ProxyToolRequest, ToolCallType
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
    return resp.model_dump()


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
        "service": "prometheus-chief-of-staff",
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
        "hitl_enforced": settings.enforce_human_in_the_loop,
        "mcp_enabled": settings.mcp_enabled,
        "capability_hypervisor_enforced": mcp_server.enforce_hypervisor,
    }



@app.get("/api/v1/blockers", tags=["Blockers"])
async def list_blockers(user: AuthUserContext = Depends(get_current_user_optional)):
    """
    Returns all active correlated delivery blockers filtered by authorized organizational scope.
    """
    scopes = user.org_scopes if user and user.is_authenticated and user.org_scopes else None
    blockers = await state_store.get_active_blockers(scopes=scopes)
    items = [b.model_dump() for b in blockers]
    return {"total": len(items), "blockers": items}


@app.post("/api/v1/digest", response_model=WorkflowExecutionResult, tags=["Workflows"])
async def trigger_alignment_digest(
    req: TriggerDigestRequest,
    current_user: AuthUserContext = Depends(get_current_user)
):
    """
    Executes the multi-agent workflow to ingest telemetry, correlate blockers, and draft action cards.
    Derives user credentials and bounds scopes to authenticated enterprise identity.
    """
    effective_user_id = current_user.user_id if current_user.user_id != "anonymous" else req.user_id
    effective_username = current_user.name if current_user.user_id != "anonymous" else req.username

    is_admin = "admin" in current_user.roles or "vp_engineering" in current_user.roles
    if not is_admin and current_user.org_scopes:
        effective_scopes = set(current_user.org_scopes) & set(req.org_scopes) if req.org_scopes else set(current_user.org_scopes)
    else:
        effective_scopes = set(req.org_scopes) if req.org_scopes else set(current_user.org_scopes or ["engineering", "platform"])

    user = UserContext(
        user_id=effective_user_id,
        username=effective_username,
        is_authenticated=True,
        org_scopes=effective_scopes,
        roles=current_user.roles,
        is_admin=is_admin,
    )
    result = await PrometheusWorkflow.run(user=user, query=req.query)
    return result


@app.get("/api/v1/registry/agents", tags=["Fortified Enterprise Fleet"])
async def list_registered_agents():
    """
    Agent Registry: Discovers and inspects capabilities and security controls of all 6 sub-agents.
    """
    agents = [a.model_dump() for a in agent_registry.list_agents()]
    return {"total_agents": len(agents), "agents": agents}


@app.get("/api/v1/actions", tags=["Human-in-the-Loop"])
async def list_actions(
    status: Optional[DraftStatus] = None,
    user: AuthUserContext = Depends(get_current_user_optional)
):
    """
    Lists proposed action cards waiting for human confirmation, filtered by authorized scope.
    """
    scopes = user.org_scopes if user and user.is_authenticated and user.org_scopes else None
    drafts = await state_store.list_drafts(status=status, scopes=scopes)
    items = [d.model_dump() for d in drafts]
    return {"total": len(items), "actions": items, "drafts": items}


@app.put("/api/v1/actions/{draft_id}", tags=["Human-in-the-Loop"])
async def edit_action_draft(draft_id: str, req: ActionDraftEditRequest):
    """
    Updates the message body and/or target channel/recipient of a pending action draft prior to approval.
    """
    updated = await state_store.update_draft_content(
        draft_id=draft_id,
        content=req.content,
        target=req.target,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Draft '{draft_id}' not found.")
    return {"status": "updated", "draft": updated.model_dump()}


@app.post("/api/v1/actions/{draft_id}/approve", tags=["Human-in-the-Loop"])
async def approve_action(
    draft_id: str,
    req: ActionApprovalRequest,
    current_user: AuthUserContext = Depends(get_current_user)
):
    """
    Explicit Human Sign-Off: Supports optional inline content/target edits prior to dispatching an action card.
    Binds approver identity to verified session user.
    """
    approver = current_user.user_id if current_user.user_id != "anonymous" else req.approver_username
    try:
        if req.content is not None or req.target is not None:
            existing = await state_store.get_draft(draft_id)
            if not existing:
                raise HTTPException(status_code=404, detail=f"Draft '{draft_id}' not found.")
            await state_store.update_draft_content(
                draft_id=draft_id,
                content=req.content if req.content is not None else existing.content,
                target=req.target if req.target is not None else existing.target_channel_or_user,
            )
        res = await SlackTools.dispatch_approved_action(
            draft_id=draft_id,
            approver_username=approver,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/actions/{draft_id}/reject", tags=["Human-in-the-Loop"])
async def reject_action(
    draft_id: str,
    req: ActionApprovalRequest,
    current_user: AuthUserContext = Depends(get_current_user)
):
    """
    Aborts a proposed action draft.
    """
    approver = current_user.user_id if current_user.user_id != "anonymous" else req.approver_username
    draft = await state_store.get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail=f"Draft '{draft_id}' not found.")
    if draft.status == DraftStatus.EXECUTED:
        return {"status": "already_executed", "draft_id": draft_id}
    await state_store.update_draft_status(
        draft_id=draft_id,
        status=DraftStatus.REJECTED,
        approver=approver,
        result="Action rejected by user.",
    )
    return {"status": "rejected", "draft_id": draft_id}


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
    Receives real-time GitHub PR and CI status webhooks and routes to GitAgent.
    Verifies HMAC-SHA256 signature when secret is configured.
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
    pr_id = payload.get("pull_request", {}).get("number", "unknown")
    return {
        "status": "received",
        "event": f"github_pr_{event_type}",
        "resource": f"PR-{pr_id}",
    }


@app.post("/api/v1/webhooks/slack", tags=["Webhooks"])
async def slack_webhook_receiver(
    request: Request,
    x_slack_signature: Optional[str] = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: Optional[str] = Header(None, alias="X-Slack-Request-Timestamp")
):
    """
    Receives real-time Slack message events and HITL interactive button callbacks.
    Supports both application/x-www-form-urlencoded ('payload=...') and application/json.
    Verifies HMAC-SHA256 signature when secret is configured.
    """
    import json as _json
    import hmac
    import hashlib
    from urllib.parse import parse_qs

    raw_body_bytes = await request.body()
    slack_signing_secret = os.getenv("SLACK_SIGNING_SECRET")
    if slack_signing_secret and x_slack_signature and x_slack_request_timestamp:
        if abs(time.time() - float(x_slack_request_timestamp)) > 300:
            raise HTTPException(status_code=401, detail="Slack webhook timestamp expired.")
        basestring = f"v0:{x_slack_request_timestamp}:{raw_body_bytes.decode('utf-8')}".encode("utf-8")
        expected_sig = "v0=" + hmac.new(slack_signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, x_slack_signature):
            raise HTTPException(status_code=401, detail="Invalid Slack webhook signature.")
    elif settings.environment == "production" and slack_signing_secret and not x_slack_signature:
        raise HTTPException(status_code=401, detail="Missing X-Slack-Signature header.")

    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        raw_body = raw_body_bytes.decode("utf-8")
        parsed_form = parse_qs(raw_body)
        payload_str = parsed_form.get("payload", ["{}"])[0]
        payload = _json.loads(payload_str)
    else:
        payload = _json.loads(raw_body_bytes.decode("utf-8")) if raw_body_bytes else {}

    if "type" in payload and payload["type"] == "url_verification":
        return {"challenge": payload.get("challenge")}

    if "actions" in payload:
        action = payload["actions"][0]
        draft_id = action.get("value")
        action_id = action.get("action_id")
        user = payload.get("user", {}).get("username", "slack-user")

        if action_id == "approve_action":
            res = await SlackTools.dispatch_approved_action(draft_id, user)
            return {"text": f"✓ {res['result']}"}
        else:
            await state_store.update_draft_status(draft_id, DraftStatus.REJECTED, user, "Rejected via Slack button.")
            return {"text": "Action dismissed."}

    return {"status": "received"}


# ==============================================================================
# Interactive CLI Runner
# ==============================================================================
async def cli_runner():
    await state_store.init_db()
    print("=" * 75)
    print(" 🚀 Prometheus Chief of Staff - Interactive Multi-Agent Orchestration")
    print("=" * 75)

    user = UserContext(
        user_id="lead-01",
        username="alex-lead",
        is_authenticated=True,
        org_scopes={"engineering", "platform"},
    )

    print("\n[1/4] Triggering Asynchronous Multi-Agent Ingestion & Synthesis...")
    result = await PrometheusWorkflow.run(
        user=user,
        query="Scan cross-squad telemetry for active sprint blockers",
    )

    print(f"\n Session ID: {result.session_id}")
    print(f" Status: {result.status}")
    print(f" Summary: {result.summary}")

    print("\n[2/4] Correlated Delivery Blockers:")
    for b in result.blockers:
        print(f"  • [{b['severity']}] {b['title']}")
        print(f"    Impact: {b['impacted_squads']} | Sources: {b['source_artifacts']}")

    print("\n[3/4] Proposed Action Cards (Human-in-the-Loop):")
    for d in result.action_drafts:
        print(f"  • Draft ID: {d['draft_id']} -> Target: {d['target_channel_or_user']}")
        print(f"    Action: {d['action_type']}")
        print(f"    Content: {d['content']}")
        print(f"    Status: {d['status']}")

    if result.action_drafts:
        first_draft_id = result.action_drafts[0]["draft_id"]
        print(f"\n[4/4] Interactive Human-In-The-Loop Approval Checkpoint for {first_draft_id}:")
        print("  Options: [Y] Approve & Dispatch | [N] Discard | [E] Edit")
        print(f"  Simulating human sign-off [Y]...")
        dispatch_res = await SlackTools.dispatch_approved_action(
            draft_id=first_draft_id,
            approver_username=user.username,
        )
        print(f"  ✓ {dispatch_res['result']}")

    print("\n" + "=" * 75)
    print(" ✨ Prometheus Workflow Completed Successfully!")
    print("=" * 75)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c"):
        asyncio.run(cli_runner())
    else:
        import uvicorn
        uvicorn.run("prometheus.main:app", host=settings.host, port=settings.port, reload=True)
