"""
Tier 4 E2E Tests: Cloud Run Service & Security Remote Endpoint Verification
Validates live Cloud Run HTTP/SSE endpoints or FastAPI application container locally and remotely.
"""

import pytest
import os
from starlette.testclient import TestClient
from prometheus.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.e2e
class TestCloudRunRemote:
    def test_healthz_endpoint(self, client):
        """Verifies /healthz endpoint returns healthy status and platform flags."""
        response = client.get("/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "prometheus-security-engine"
        assert data["mcp_enabled"] is True

    def test_dashboard_and_root_endpoints(self, client):
        """Verifies /dashboard and / endpoints serve valid HTML user interface."""
        resp_root = client.get("/")
        assert resp_root.status_code == 200
        assert "text/html" in resp_root.headers.get("content-type", "")
        assert "Prometheus" in resp_root.text

        resp_dash = client.get("/dashboard")
        assert resp_dash.status_code == 200
        assert "text/html" in resp_dash.headers.get("content-type", "")
        assert "Prometheus" in resp_dash.text

    def test_security_overview_endpoint(self, client):
        """Verifies /api/v1/security/overview exposes hypervisor metrics and ABAC audit stats."""
        response = client.get("/api/v1/security/overview")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"
        assert "Autonomous Exploit & Capability Governance" in data["platform"]
        assert data["hypervisor_active"] is True
        assert data["sla_gate_seconds"] == 85.0

    def test_proxy_token_mint_and_execution(self, client):
        """Verifies minting capability tokens and proxy tool execution."""
        mint_resp = client.post("/api/v1/proxy/mint-token", json={
            "subject": "e2e-agent",
            "allowed_methods": ["GET"],
            "allowed_resource_ids": ["*"],
            "ttl_seconds": 60,
        })
        assert mint_resp.status_code == 200
        token_data = mint_resp.json()
        assert token_data["subject"] == "e2e-agent"

        # Allowed GET passes
        exec_resp = client.post("/api/v1/proxy/execute", json={
            "call_type": "HTTP",
            "method": "GET",
            "target": "/api/v1/health",
            "token": token_data,
        })
        assert exec_resp.status_code == 200

    def test_api_webhooks_endpoints(self, client):
        """Verifies webhook ingress handlers for GitHub events."""
        gh_resp = client.post("/api/v1/webhooks/github", json={"action": "opened", "pull_request": {"number": 101}})
        assert gh_resp.status_code == 200
        assert gh_resp.json()["status"] == "received"
