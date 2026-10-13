"""
Unit and integration tests for Dynamic Resource Harvesting and Canary Derivation (Finding F-01).
Verifies:
1. Producer (POST) and listing (GET) endpoint inspection and dynamic resource harvesting.
2. Dynamic canary derivation from payload and victim identifying markers (tenant_id, organization_id, user_id).
3. Elimination of rigid fallbacks to 'invoice' / 'inv-alpha-992' and 'CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832'.
4. Integration with PrometheusAdversarialEngine and ProofValidator with zero false negatives on arbitrary APIs.
"""

from typing import Dict, Optional
import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Header, status
from pydantic import BaseModel

from prometheus.pentest.engine import PrometheusAdversarialEngine
from prometheus.pentest.exploit_prober import ExploitProber
import jwt
from prometheus.pentest.models import (
    DualTenantContext,
    ExploitProbeRequest,
    HttpMethod,
    RouteEndpoint,
    Severity,
    VulnerabilityCategory,
)
from prometheus.pentest.proof_validator import ProofValidator
from prometheus.pentest.state_synthesizer import StateSynthesizer


# --- Test FastAPI Microservice with Arbitrary Domain Entities ---
test_app = FastAPI(title="Harvesting Test Service")

PROJECTS_DB = {
    "proj-alpha-101": {
        "id": "proj-alpha-101",
        "tenant_id": "org-alpha-victim-001",
        "name": "Classified Project Falcon",
        "budget": 500000,
    }
}

REPORTS_DB: Dict[str, Dict] = {}


def get_auth_tenant(
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> str:
    if x_tenant_id:
        return x_tenant_id
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("tenant_id", "unknown")
    except Exception:
        return "unknown"


@test_app.get("/api/v1/projects")
async def list_projects(tenant_id: str = Depends(get_auth_tenant)):
    # Returns list of projects belonging to authenticated tenant
    return [p for p in PROJECTS_DB.values() if p["tenant_id"] == tenant_id]


@test_app.get("/api/v1/projects/{project_id}")
async def get_project_vulnerable(project_id: str, tenant_id: str = Depends(get_auth_tenant)):
    # BOLA: Cross-tenant access permitted
    proj = PROJECTS_DB.get(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj


class ReportCreate(BaseModel):
    id: Optional[str] = None
    title: str
    secret_marker: Optional[str] = None


@test_app.post("/api/v1/reports", status_code=201)
async def create_report(payload: ReportCreate, tenant_id: str = Depends(get_auth_tenant)):
    rep_id = payload.id or f"rep-alpha-{len(REPORTS_DB) + 1}"
    report = {
        "id": rep_id,
        "tenant_id": tenant_id,
        "title": payload.title,
        "secret_marker": payload.secret_marker or "DYNAMIC_REPORT_CANARY_777",
    }
    REPORTS_DB[rep_id] = report
    return report


@test_app.get("/api/v1/reports/{report_id}")
async def get_report_vulnerable(report_id: str, tenant_id: str = Depends(get_auth_tenant)):
    # BOLA: Cross-tenant access permitted
    report = REPORTS_DB.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@test_app.delete("/api/v1/admin/clusters/{cluster_id}")
async def delete_cluster_vulnerable(cluster_id: str, tenant_id: str = Depends(get_auth_tenant)):
    # BFLA: Unprivileged users can delete clusters
    return {"status": "DELETED", "cluster_id": cluster_id, "deleted_by_tenant": tenant_id}


WORKSPACES_DB = {
    "ws-alpha-501": {
        "id": "ws-alpha-501",
        "tenant_id": "org-alpha-victim-001",
        "name": "Workspace Red Team",
    }
}

DOCS_DB = {
    "ws-alpha-501": [
        {
            "id": "doc-alpha-900",
            "workspace_id": "ws-alpha-501",
            "name": "Confidential Blueprint",
            "tenant_id": "org-alpha-victim-001",
        }
    ]
}


@test_app.get("/api/v1/workspaces")
async def list_workspaces(tenant_id: str = Depends(get_auth_tenant)):
    return [w for w in WORKSPACES_DB.values() if w["tenant_id"] == tenant_id]


@test_app.get("/api/v1/workspaces/{workspace_id}/documents")
async def list_workspace_docs(workspace_id: str, tenant_id: str = Depends(get_auth_tenant)):
    return DOCS_DB.get(workspace_id, [])


@test_app.get("/api/v1/workspaces/{workspace_id}/documents/{document_id}")
async def get_workspace_doc_vulnerable(workspace_id: str, document_id: str, tenant_id: str = Depends(get_auth_tenant)):
    # BOLA: cross-tenant access permitted
    docs = DOCS_DB.get(workspace_id, [])
    doc = next((d for d in docs if d["id"] == document_id), None)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@test_app.get("/api/v1/spring/categories")
async def list_categories_envelope(tenant_id: str = Depends(get_auth_tenant)):
    # Spring Boot envelope style with 'content' and irregular plural
    return {
        "content": [
            {"id": "cat-alpha-01", "name": "Secret Category Alpha", "tenant_id": tenant_id}
        ],
        "totalElements": 1,
    }


# --- Unit Tests ---

@pytest.mark.asyncio
async def test_harvest_resource_from_listing_endpoint():
    """Verifies that ExploitProber dynamically harvests victim resource state from GET listing routes."""
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )
    assert "project" not in context.seeded_resources

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    listing_route = RouteEndpoint(
        path="/api/v1/projects",
        method=HttpMethod.GET,
        path_parameters=[],
    )

    harvested = await prober.harvest_resource(listing_route, context, entity_name="project")

    assert harvested is not None
    assert harvested["resource_id"] == "proj-alpha-101"
    # Canary should be derived from payload (e.g. name) or tenant_id
    assert harvested["confidential_marker"] in ("Classified Project Falcon", "org-alpha-victim-001")
    assert "project" in context.seeded_resources
    assert context.seeded_resources["project"]["resource_id"] == "proj-alpha-101"


@pytest.mark.asyncio
async def test_harvest_resource_from_producer_endpoint():
    """Verifies that ExploitProber dynamically seeds and extracts victim resource state from POST producer routes."""
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )
    assert "report" not in context.seeded_resources

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    producer_route = RouteEndpoint(
        path="/api/v1/reports",
        method=HttpMethod.POST,
        path_parameters=[],
        request_body_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "title": {"type": "string"},
                "secret_marker": {"type": "string"},
            },
        },
    )

    harvested = await prober.harvest_resource(producer_route, context, entity_name="report")

    assert harvested is not None
    assert harvested["resource_id"].startswith("report-alpha-") or harvested["resource_id"].startswith("rep-alpha-")
    assert "CONFIDENTIAL_CANARY_ALPHA_" in harvested["confidential_marker"]
    assert "report" in context.seeded_resources
    assert context.seeded_resources["report"]["resource_id"] == harvested["resource_id"]


@pytest.mark.asyncio
async def test_harvest_resources_from_endpoints():
    """Verifies batch harvesting across multiple OpenAPI routes."""
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    endpoints = [
        RouteEndpoint(path="/api/v1/projects", method=HttpMethod.GET, path_parameters=[]),
        RouteEndpoint(path="/api/v1/projects/{project_id}", method=HttpMethod.GET, path_parameters=["project_id"]),
        RouteEndpoint(path="/api/v1/reports", method=HttpMethod.POST, path_parameters=[]),
        RouteEndpoint(path="/api/v1/reports/{report_id}", method=HttpMethod.GET, path_parameters=["report_id"]),
    ]

    harvested_map = await prober.harvest_resources_from_endpoints(endpoints, context)

    assert "project" in harvested_map
    assert "report" in harvested_map
    assert context.seeded_resources["project"]["resource_id"] == "proj-alpha-101"
    assert "report" in context.seeded_resources


@pytest.mark.asyncio
async def test_dynamic_resource_harvesting_in_adversarial_engine():
    """
    End-to-end verification that PrometheusAdversarialEngine dynamically harvests
    victim resources before running attack hypotheses, without any pre-seeded invoice/payroll defaults.
    """
    synthesizer = StateSynthesizer()
    # Empty seeded resources - engine must discover everything dynamically!
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
        beta_role="member",
    )
    assert len(context.seeded_resources) == 0

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    endpoints = [
        RouteEndpoint(path="/api/v1/projects", method=HttpMethod.GET, path_parameters=[]),
        RouteEndpoint(path="/api/v1/projects/{project_id}", method=HttpMethod.GET, path_parameters=["project_id"]),
        RouteEndpoint(path="/api/v1/admin/clusters/{cluster_id}", method=HttpMethod.DELETE, path_parameters=["cluster_id"]),
    ]

    engine = PrometheusAdversarialEngine(
        base_url="http://testserver",
        endpoints=endpoints,
        context=context,
        prober=prober,
        max_turns=5,
    )

    results = await engine.run()

    assert results["status"] == "COMPLETED"
    vulnerabilities = results["vulnerabilities"]

    # Verify BOLA vulnerability detected on projects using harvested ID
    bola_vuln = next((v for v in vulnerabilities if v.vector == VulnerabilityCategory.BOLA_IDOR), None)
    assert bola_vuln is not None
    assert bola_vuln.severity == Severity.CRITICAL
    assert "proj-alpha-101" in bola_vuln.target_endpoint
    # Ensure no rigid invoice fallback occurred
    assert "inv-alpha-992" not in bola_vuln.target_endpoint
    assert "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832" not in bola_vuln.canary_marker

    # Verify BFLA vulnerability detected on clusters using dynamic cluster ID
    bfla_vuln = next((v for v in vulnerabilities if v.vector == VulnerabilityCategory.BFLA), None)
    assert bfla_vuln is not None
    assert "ws-alpha-001" not in bfla_vuln.target_endpoint
    assert "cluster" in bfla_vuln.target_endpoint


@pytest.mark.asyncio
async def test_canary_verification_matches_victim_identifying_markers():
    """
    Verifies canary verification matching victim identifying markers
    (tenant_id, organization_id, user_id) when arbitrary APIs return standard object attributes.
    """
    validator = ProofValidator()
    probe_req = ExploitProbeRequest(
        target_url="http://testserver/api/v1/custom-items/item-01",
        method=HttpMethod.GET,
        headers={"Authorization": "Bearer token_beta"},
        path_params={"item_id": "item-01"},
        query_params={},
        body=None,
        vector=VulnerabilityCategory.BOLA_IDOR,
        hypothesis="Testing victim identifying markers matching",
    )

    # Response does NOT have any synthetic 'CONFIDENTIAL_PAYROLL...' marker,
    # but DOES have the victim's tenant_id and user_id!
    response_payload = {
        "id": "item-01",
        "tenant_id": "org-alpha-victim-001",
        "owner_user_id": "user-alpha-999",
        "title": "Ordinary Item",
    }

    proof = validator.evaluate_bola_response(
        probe=probe_req,
        status_code=200,
        response_body=response_payload,
        expected_victim_marker=None,
        execution_time_ms=5.0,
        victim_headers={
            "X-Tenant-ID": "org-alpha-victim-001",
            "X-Organization-ID": "org-alpha-victim-001",
        },
        candidate_markers=["org-alpha-victim-001", "user-alpha-999"],
    )

    # Must confirm vulnerability without false negatives!
    assert proof.is_vulnerable is True
    assert proof.severity == Severity.CRITICAL
    assert proof.canary_marker == "org-alpha-victim-001"


@pytest.mark.asyncio
async def test_elimination_of_rigid_invoice_fallback():
    """
    Explicit test ensuring that unknown resource types do NOT fallback
    to 'invoice' / 'inv-alpha-992' / 'CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832'.
    """
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    unknown_route = RouteEndpoint(
        path="/api/v1/devices/{device_id}",
        method=HttpMethod.GET,
        path_parameters=["device_id"],
    )

    # Executing probe_bola without any seeded resources
    proof = await prober.probe_bola(route=unknown_route, context=context)

    # Target path should be device-based, NEVER inv-alpha-992!
    assert "inv-alpha-992" not in proof.target_endpoint
    assert "device-alpha-001" in proof.target_endpoint
    # Canary marker should NOT be CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832!
    assert proof.canary_marker != "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832"
    assert proof.canary_marker == "org-alpha-victim-001"


@pytest.mark.asyncio
async def test_hierarchical_dynamic_harvesting_across_parent_child_endpoints():
    """
    Verifies that ExploitProber iteratively resolves hierarchical dependencies across
    parent and child endpoints: discovering workspace first, then resolving
    /api/v1/workspaces/{workspace_id}/documents to discover documents.
    """
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )
    assert len(context.seeded_resources) == 0

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    endpoints = [
        RouteEndpoint(path="/api/v1/workspaces", method=HttpMethod.GET, path_parameters=[]),
        RouteEndpoint(path="/api/v1/workspaces/{workspace_id}", method=HttpMethod.GET, path_parameters=["workspace_id"]),
        RouteEndpoint(path="/api/v1/workspaces/{workspace_id}/documents", method=HttpMethod.GET, path_parameters=["workspace_id"]),
        RouteEndpoint(path="/api/v1/workspaces/{workspace_id}/documents/{document_id}", method=HttpMethod.GET, path_parameters=["workspace_id", "document_id"]),
    ]

    harvested = await prober.harvest_resources_from_endpoints(endpoints, context)

    assert "workspace" in harvested
    assert "document" in harvested
    assert context.seeded_resources["workspace"]["resource_id"] == "ws-alpha-501"
    assert context.seeded_resources["workspace"]["confidential_marker"] == "Workspace Red Team"
    assert context.seeded_resources["document"]["resource_id"] == "doc-alpha-900"
    assert context.seeded_resources["document"]["confidential_marker"] == "Confidential Blueprint"


@pytest.mark.asyncio
async def test_nested_multiparameter_route_bola_probing_avoids_parameter_corruption():
    """
    Verifies that probe_bola correctly substitutes multi-parameter nested routes
    without corrupting parent IDs (e.g. workspace_id) with child target IDs (e.g. document_id).
    """
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )
    context.seeded_resources["workspace"] = {
        "resource_id": "ws-alpha-501",
        "confidential_marker": "Workspace Red Team",
    }
    context.seeded_resources["document"] = {
        "resource_id": "doc-alpha-900",
        "confidential_marker": "Confidential Blueprint",
    }

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    nested_route = RouteEndpoint(
        path="/api/v1/workspaces/{workspace_id}/documents/{document_id}",
        method=HttpMethod.GET,
        path_parameters=["workspace_id", "document_id"],
    )

    proof = await prober.probe_bola(nested_route, context, target_resource_type="document")

    # Critical check: workspace_id must NOT be overwritten with document_id!
    assert "/api/v1/workspaces/ws-alpha-501/documents/doc-alpha-900" in proof.target_endpoint
    assert proof.is_vulnerable is True
    assert proof.severity == Severity.CRITICAL
    assert proof.canary_marker == "Confidential Blueprint"


@pytest.mark.asyncio
async def test_harvest_resource_envelope_and_irregular_plural():
    """
    Verifies dynamic harvesting from Spring Boot style 'content' envelope
    and irregular plural mapping ('categories' -> 'category').
    """
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
    )

    transport = httpx.ASGITransport(app=test_app)
    prober = ExploitProber(base_url="http://testserver", transport=transport)

    route = RouteEndpoint(
        path="/api/v1/spring/categories",
        method=HttpMethod.GET,
        path_parameters=[],
    )

    harvested = await prober.harvest_resource(route, context, entity_name="category")

    assert harvested is not None
    assert harvested["resource_id"] == "cat-alpha-01"
    assert harvested["confidential_marker"] == "Secret Category Alpha"
    assert context.seeded_resources["category"]["resource_id"] == "cat-alpha-01"

