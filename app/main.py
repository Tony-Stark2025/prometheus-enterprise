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
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Request, Response, Depends
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize persistent SQLite store and background scheduler
    await state_store.init_db()
    await scheduler.start()
    yield
    # Shutdown
    await scheduler.stop()


app = FastAPI(
    title="Prometheus: Chief of Staff Observability Platform",
    description="Enterprise Workstream Observability & Asynchronous Multi-Agent Orchestration Platform",
    version="1.1.0",
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


from prometheus.memory.firestore_store import firestore_store, UserProfile
from prometheus.auth.oauth import create_session_token, get_google_auth_url, exchange_google_code
from prometheus.auth.dependencies import get_current_user_optional, UserContext as AuthUserContext
from prometheus.security.abac_engine import abac_engine

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


# ==============================================================================
# Google OAuth 2.0 & Session Management Endpoints
# ==============================================================================
@app.get("/api/v1/auth/me", tags=["Authentication"])
async def get_me(user: AuthUserContext = Depends(get_current_user_optional)):
    """
    Returns current authenticated user profile and active tenant organization.
    """
    return user.model_dump()


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


class DemoLoginRequest(BaseModel):
    user_id: Optional[str] = "brightonwe30"


@app.post("/api/v1/auth/demo-login", tags=["Authentication"])
async def demo_login(response: Response, payload: Optional[DemoLoginRequest] = None):
    """
    Provides instant enterprise session for selected profile (default: Bright Onwe).
    """
    requested_id = payload.user_id if payload and payload.user_id else "brightonwe30"
    
    profiles = {
        "brightonwe30": UserProfile(
            user_id="brightonwe30",
            email="brightonwe30@gmail.com",
            name="Bright Onwe",
            tenant_id="default_enterprise",
            roles=["lead", "admin", "chief_of_staff"],
            org_scopes=["engineering", "platform"],
        ),
        "brightbutler7": UserProfile(
            user_id="brightbutler7",
            email="brightbutler7@gmail.com",
            name="Bright Butler",
            tenant_id="default_enterprise",
            roles=["staff_engineer", "reviewer"],
            org_scopes=["engineering"],
        ),
        "sarah.chen": UserProfile(
            user_id="sarah.chen",
            email="sarah.chen@acme.corp",
            name="Sarah Chen",
            tenant_id="default_enterprise",
            roles=["senior_engineer"],
            org_scopes=["engineering"],
        ),
    }
    
    profile = profiles.get(requested_id, profiles["brightonwe30"])
    await firestore_store.save_user(profile)

    token = create_session_token(
        user_id=profile.user_id,
        email=profile.email,
        tenant_id=profile.tenant_id,
        scopes=profile.org_scopes,
    )
    response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax")
    return {"status": "authenticated", "user": profile.model_dump(), "token": token}


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


@app.get("/api/v1/security/abac/resources", tags=["ABAC Security"])
async def list_abac_resources():
    """Lists registered target resources and required security bounds."""
    return {"resources": abac_engine.list_resources()}


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
# Enterprise Integrations API (Firestore Vaulted)
# ==============================================================================
@app.get("/api/v1/integrations", tags=["Integrations"])
async def list_integrations(user: AuthUserContext = Depends(get_current_user_optional)):
    """
    Lists connected status and masked credentials of tenant tools (GitHub, Jira, Slack).
    """
    return await firestore_store.list_integrations(tenant_id=user.tenant_id)


@app.post("/api/v1/integrations/{service}", tags=["Integrations"])
async def save_integration(service: str, payload: Dict[str, Any], user: AuthUserContext = Depends(get_current_user_optional)):
    """
    Saves and vaults integration credentials into Google Cloud Firestore.
    """
    if service not in ("github", "jira", "slack"):
        raise HTTPException(status_code=400, detail=f"Unsupported service: {service}")
    saved = await firestore_store.save_integration(tenant_id=user.tenant_id, service=service, config=payload)
    return {"status": "saved", "service": service, "updated_at": saved.updated_at}


@app.delete("/api/v1/integrations/{service}", tags=["Integrations"])
async def delete_integration(service: str, user: AuthUserContext = Depends(get_current_user_optional)):
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
    }


@app.get("/api/v1/blockers", tags=["Blockers"])
async def list_blockers():
    """
    Returns all active correlated delivery blockers.
    """
    blockers = await state_store.get_active_blockers()
    items = [b.model_dump() for b in blockers]
    return {"total": len(items), "blockers": items}


@app.post("/api/v1/digest", response_model=WorkflowExecutionResult, tags=["Workflows"])
async def trigger_alignment_digest(req: TriggerDigestRequest):
    """
    Executes the multi-agent workflow to ingest telemetry, correlate blockers, and draft action cards.
    """
    user = UserContext(
        user_id=req.user_id,
        username=req.username,
        is_authenticated=True,
        org_scopes=set(req.org_scopes),
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
async def list_actions(status: Optional[DraftStatus] = None):
    """
    Lists proposed action cards waiting for human confirmation.
    """
    drafts = await state_store.list_drafts(status=status)
    items = [d.model_dump() for d in drafts]
    return {"total": len(items), "actions": items, "drafts": items}


@app.post("/api/v1/actions/{draft_id}/approve", tags=["Human-in-the-Loop"])
async def approve_action(draft_id: str, req: ActionApprovalRequest):
    """
    Explicit Human Sign-Off: Dispatches an action card only upon approval.
    """
    try:
        res = await SlackTools.dispatch_approved_action(
            draft_id=draft_id,
            approver_username=req.approver_username,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/actions/{draft_id}/reject", tags=["Human-in-the-Loop"])
async def reject_action(draft_id: str, req: ActionApprovalRequest):
    """
    Aborts a proposed action draft.
    """
    draft = await state_store.get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail=f"Draft '{draft_id}' not found.")
    if draft.status == DraftStatus.EXECUTED:
        return {"status": "already_executed", "draft_id": draft_id}
    await state_store.update_draft_status(
        draft_id=draft_id,
        status=DraftStatus.REJECTED,
        approver=req.approver_username,
        result="Action rejected by user.",
    )
    return {"status": "rejected", "draft_id": draft_id}


# ==============================================================================
# Model Context Protocol (MCP) Server-Sent Events (SSE) Endpoint
# ==============================================================================
@app.post("/mcp/sse", tags=["Model Context Protocol"])
async def mcp_sse_endpoint(request: Request):
    """
    HTTP/SSE endpoint for external agent fleets to consume Prometheus MCP tools.
    """
    body = await request.json()
    response = await mcp_server.handle_jsonrpc(body)
    return response


# ==============================================================================
# Webhook Ingress Receivers
# ==============================================================================
@app.post("/api/v1/webhooks/github", tags=["Webhooks"])
async def github_webhook_receiver(payload: Dict[str, Any]):
    """
    Receives real-time GitHub PR and CI status webhooks and routes to GitAgent.
    """
    event_type = payload.get("action", "unknown")
    pr_id = payload.get("pull_request", {}).get("number", "unknown")
    return {
        "status": "received",
        "event": f"github_pr_{event_type}",
        "resource": f"PR-{pr_id}",
    }


@app.post("/api/v1/webhooks/slack", tags=["Webhooks"])
async def slack_webhook_receiver(payload: Dict[str, Any]):
    """
    Receives real-time Slack message events and HITL interactive button callbacks.
    """
    if "type" in payload and payload["type"] == "url_verification":
        return {"challenge": payload.get("challenge")}

    if "actions" in payload:
        # Handle Slack interactive button callback
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
