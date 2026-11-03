"""
Tests for Prometheus Security Engine Web, API, MCP SSE, and Cloud Endpoints.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from prometheus.main import app


@pytest.mark.asyncio
async def test_healthz_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/healthz")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["service"] == "prometheus-security-engine"
        assert "Gemini Enterprise Agent Platform" in data["platform"]
        assert data["model"] == "gemini-3.7-flash"
        assert data["mcp_enabled"] is True
        assert data["capability_hypervisor_enforced"] is False or data["capability_hypervisor_enforced"] is True


@pytest.mark.asyncio
async def test_dashboard_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/dashboard")
        assert res.status_code == 200
        assert "text/html" in res.headers.get("content-type", "")

        res_root = await ac.get("/")
        assert res_root.status_code == 200
        assert "text/html" in res_root.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_mcp_sse_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. MCP initialize
        init_payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        res = await ac.post("/mcp/sse", json=init_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["result"]["serverInfo"]["name"] == "prometheus-mcp-server"

        # 2. MCP tools/list
        list_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        res = await ac.post("/mcp/sse", json=list_payload)
        assert res.status_code == 200
        data = res.json()
        tool_names = [t["name"] for t in data["result"]["tools"]]
        assert "scan_api_security" in tool_names
        assert "mint_capability_token" in tool_names
        assert "request_action_permit" in tool_names
        assert "verify_action_permit" in tool_names

        # 3. MCP tools/call (mint_capability_token)
        call_payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "mint_capability_token",
                "arguments": {"subject": "test-agent", "ttl_seconds": 30},
            },
        }
        res = await ac.post("/mcp/sse", json=call_payload)
        assert res.status_code == 200
        data = res.json()
        assert "content" in data["result"]

        # 4. MCP unknown method
        unk_payload = {"jsonrpc": "2.0", "id": 5, "method": "nonexistent_rpc_method", "params": {}}
        res_unk = await ac.post("/mcp/sse", json=unk_payload)
        assert res_unk.status_code == 200
        data_unk = res_unk.json()
        assert "error" in data_unk
        assert data_unk["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_api_webhooks_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # GitHub webhook
        gh_payload = {"action": "opened", "pull_request": {"number": 402}}
        res_gh = await ac.post("/api/v1/webhooks/github", json=gh_payload)
        assert res_gh.status_code == 200
        assert res_gh.json()["event"] == "github_pr_opened"


@pytest.mark.asyncio
async def test_documentation_and_auth_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Documentation endpoint
        res_doc = await ac.get("/documentation")
        assert res_doc.status_code == 200
        assert "text/html" in res_doc.headers.get("content-type", "")
        assert "Documentation" in res_doc.text

        # 2. Auth me endpoint
        res_me = await ac.get("/api/v1/auth/me")
        assert res_me.status_code == 200
        data_me = res_me.json()
        assert "user_id" in data_me
        assert "tenant_id" in data_me

        # 3. Google login URL endpoint
        res_glogin = await ac.get("/api/v1/auth/google/login")
        assert res_glogin.status_code == 200
        assert "auth_url" in res_glogin.json()

        # 4. Verify demo-login endpoint is removed (404) and test ABAC registration endpoints
        res_demo = await ac.post("/api/v1/auth/demo-login")
        assert res_demo.status_code == 404

        # Verify unauthenticated/non-admin request fails closed (403)
        res_abac_unauth = await ac.post(
            "/api/v1/security/abac/users",
            json={
                "user_id": "test.engineer",
                "username": "test.engineer",
                "email": "test.engineer@enterprise.io",
                "department": "engineering",
                "clearance_level": "L4",
                "assigned_squads": ["platform"],
                "roles": ["staff_engineer"],
                "is_admin": False,
            },
        )
        assert res_abac_unauth.status_code == 403

        # Authenticated admin request succeeds (200)
        from prometheus.auth.oauth import create_session_token
        admin_token = create_session_token(
            user_id="admin.lead",
            email="admin@enterprise.io",
            roles=["admin"],
            tenant_id="default_enterprise",
        )
        res_abac_user = await ac.post(
            "/api/v1/security/abac/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "user_id": "test.engineer",
                "username": "test.engineer",
                "email": "test.engineer@enterprise.io",
                "department": "engineering",
                "clearance_level": "L4",
                "assigned_squads": ["platform"],
                "roles": ["staff_engineer"],
                "is_admin": False,
            },
        )
        assert res_abac_user.status_code == 200
        assert res_abac_user.json()["user_id"] == "test.engineer"

        # 5. Integrations API (list, save, delete)
        res_int_list = await ac.get("/api/v1/integrations")
        assert res_int_list.status_code == 200
        int_data = res_int_list.json()
        assert "github" in int_data
        assert "jira" in int_data
        assert "slack" in int_data

        # Save GitHub integration
        res_save_gh = await ac.post("/api/v1/integrations/github", json={"token": "ghp_mock123", "repos": ["org/repo"]})
        assert res_save_gh.status_code == 200
        assert res_save_gh.json()["status"] == "saved"

        # Delete GitHub integration
        res_del_gh = await ac.delete("/api/v1/integrations/github")
        assert res_del_gh.status_code == 200
        assert res_del_gh.json()["status"] == "deleted"

        # 6. Logout
        res_logout = await ac.post("/api/v1/auth/logout")
        assert res_logout.status_code == 200
        assert res_logout.json()["status"] == "logged_out"
