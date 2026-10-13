"""
Unit and Integration Tests for Prometheus Enterprise Security & Capability Governance REST & MCP Endpoints.
Verifies /api/v1/security/overview, /api/v1/proxy/* endpoints, /api/v1/pentest/scan, and MCP hypervisor tools.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from prometheus.main import app
from prometheus.proxy.token_authority import TokenAuthority


@pytest.fixture
def test_client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_security_overview_endpoint(test_client):
    res = await test_client.get("/api/v1/security/overview")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert "Autonomous Exploit & Capability Governance" in data["platform"]
    assert data["sla_gate_seconds"] == 85.0
    assert data["reflection_defense_active"] is True
    assert data["cegis_dual_pass_active"] is True
    assert data["hypervisor_active"] is True
    assert "registered_witnesses" in data
    assert "recent_audit_events" in data


@pytest.mark.asyncio
async def test_proxy_mint_token_and_permit_endpoints(test_client):
    # 1. Mint capability token via REST
    mint_payload = {
        "subject": "agent-worker-01",
        "allowed_methods": ["GET", "PUT"],
        "allowed_resource_ids": ["res-999"],
        "ttl_seconds": 60,
        "tenant_id": "org-corp",
    }
    res_token = await test_client.post("/api/v1/proxy/mint-token", json=mint_payload)
    assert res_token.status_code == 200
    token_data = res_token.json()
    assert token_data["subject"] == "agent-worker-01"
    assert "signature" in token_data
    assert token_data["scope"]["allowed_methods"] == ["GET", "PUT"]

    # 2. Request action permit
    permit_payload = {
        "token": token_data,
        "target_op": "PUT",
        "resource_id": "res-999",
    }
    res_permit = await test_client.post("/api/v1/proxy/permit", json=permit_payload)
    assert res_permit.status_code == 200
    permit_data = res_permit.json()
    assert permit_data["token_id"] == token_data["token_id"]
    assert permit_data["action_method"] == "PUT"
    assert permit_data["resource_id"] == "res-999"
    assert "signature" in permit_data


@pytest.mark.asyncio
async def test_proxy_execute_tool_interception(test_client):
    # Mint token with read-only permission
    res_token = await test_client.post("/api/v1/proxy/mint-token", json={
        "subject": "reader-agent",
        "allowed_methods": ["GET"],
        "allowed_resource_ids": ["*"],
        "ttl_seconds": 60,
    })
    token_data = res_token.json()

    # Attempt to execute PUT (mutation) -> should be denied by capability authority
    res_exec_denied = await test_client.post("/api/v1/proxy/execute", json={
        "call_type": "HTTP",
        "method": "PUT",
        "target": "/api/v1/invoices/inv-001",
        "resource_id": "inv-001",
        "payload": {"amount": 9999},
        "token": token_data,
    })
    assert res_exec_denied.status_code == 200
    exec_data = res_exec_denied.json()
    assert exec_data["success"] is False
    assert exec_data["status_code"] == 403
    assert exec_data["denial"]["denial_code"] == "UNAUTHORIZED_METHOD_SCOPE"
    assert "PUT" in exec_data["denial"]["details"]

    # Execute allowed GET -> passes
    res_exec_ok = await test_client.post("/api/v1/proxy/execute", json={
        "call_type": "HTTP",
        "method": "GET",
        "target": "/api/v1/invoices/inv-001",
        "resource_id": "inv-001",
        "token": token_data,
    })
    assert res_exec_ok.status_code == 200
    exec_ok_data = res_exec_ok.json()
    assert exec_ok_data["success"] is True
    assert exec_ok_data["status_code"] == 200
    assert exec_ok_data["pre_state_witness"] is not None


@pytest.mark.asyncio
async def test_mcp_security_tools_integration(test_client):
    # 1. Test tools/list exposes new security tools
    list_res = await test_client.post("/mcp/sse", json={
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/list",
        "params": {},
    })
    assert list_res.status_code == 200
    tools = list_res.json()["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "scan_api_security" in tool_names
    assert "mint_capability_token" in tool_names
    assert "request_action_permit" in tool_names
    assert "verify_action_permit" in tool_names

    # 2. Call mint_capability_token via MCP
    mint_res = await test_client.post("/mcp/sse", json={
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "mint_capability_token",
            "arguments": {
                "subject": "mcp-agent-77",
                "allowed_methods": ["GET", "approve_action"],
                "allowed_resources": ["*"],
                "ttl_seconds": 45,
            },
        },
    })
    assert mint_res.status_code == 200
    mint_data = mint_res.json()["result"]
    import json
    token_json = json.loads(mint_data["content"][0]["text"])
    assert token_json["subject"] == "mcp-agent-77"
    assert token_json["scope"]["max_ttl_seconds"] == 45


@pytest.mark.asyncio
async def test_pentest_scan_endpoint_on_benchmark_app(test_client):
    # Run scan against benchmark app OpenAPI spec
    from prometheus.pentest.benchmark_app import app as bench_app
    bench_spec = bench_app.openapi()

    scan_payload = {
        "target_url": "http://testserver",
        "spec_dict": bench_spec,
        "max_time_s": 40.0,
    }
    # Use ASGITransport for bench_app
    from httpx import ASGITransport
    bench_transport = ASGITransport(app=bench_app)

    from prometheus.pentest.service import PentestExecutionService, PentestScanRequest
    req = PentestScanRequest.model_validate(scan_payload)
    scan_result = await PentestExecutionService.execute_scan(req, transport=bench_transport)

    assert scan_result.status == "VULNERABILITIES_FOUND"
    assert scan_result.endpoints_count >= 3
    assert scan_result.exploits_count >= 1
    assert scan_result.patches_count >= 1
    assert len(scan_result.regression_tests) >= 1
    first_key = list(scan_result.regression_tests.keys())[0]
    assert "pytest" in scan_result.regression_tests[first_key]
    assert "typescript" in scan_result.regression_tests[first_key]
    assert "ATTACKER_AUTH_TOKEN" in scan_result.regression_tests[first_key]["pytest"]
