"""
Integration tests for Prometheus SOTA Modules:
1. OpenAPIRouteGraph (Topological execution tiers and parameter lineage)
2. ASTPatchSynthesizer (Safe AST rewriting for ORM authorization filters)
3. DualPassVerifier (CEGIS live dual-pass regression verification)
"""

import pytest
import httpx

from prometheus.pentest.ast_patcher import ASTPatchSynthesizer
from prometheus.pentest.benchmark_app import app
from prometheus.pentest.cegis_verifier import DualPassVerifier
from prometheus.pentest.exploit_prober import ExploitProber
from prometheus.pentest.models import (
    HttpMethod,
    RouteEndpoint,
    VulnerabilityCategory,
    ExploitProof,
    Severity,
)
from prometheus.pentest.pr_ingestor import OpenAPIngestor
from prometheus.pentest.route_graph import OpenAPIRouteGraph
from prometheus.pentest.state_synthesizer import StateSynthesizer


def test_openapi_route_graph_lineage_and_tiers():
    spec = app.openapi()
    endpoints = OpenAPIngestor.parse_spec(spec)
    assert len(endpoints) >= 4

    graph = OpenAPIRouteGraph.from_endpoints(endpoints)
    tiers = graph.get_execution_tiers()

    assert len(tiers) >= 1
    # Check that operations are grouped properly
    all_ops = [op for tier in tiers for op in tier]
    assert len(all_ops) == len(endpoints)


def test_ast_patch_synthesizer_rewrites_cleanly():
    sample_code = (
        '@app.get("/api/v1/invoices/{invoice_id}")\n'
        "async def get_invoice(invoice_id: str, current_user: UserSession = Depends(get_current_user)):\n"
        "    invoice = INVOICES_DB.get(invoice_id)\n"
        "    if not invoice:\n"
        '        raise HTTPException(status_code=404, detail="Invoice not found")\n'
        "    return invoice\n"
    )

    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/invoices/inv-alpha-992",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"secret": "leak"},
        curl_command="curl -s http://testserver",
        remediation_guidance="Fix tenant check",
        execution_time_ms=10.0,
    )

    result = ASTPatchSynthesizer.synthesize_bola_patch(
        original_code=sample_code,
        proof=proof,
        target_file="app/api/invoices.py",
    )

    assert result.target_file == "app/api/invoices.py"
    assert "current_user.tenant_id" in result.git_diff
    assert "--- a/app/api/invoices.py" in result.git_diff
    assert "+++ b/app/api/invoices.py" in result.git_diff


@pytest.mark.asyncio
async def test_cegis_dual_pass_verifier_against_benchmark():
    synthesizer = StateSynthesizer()
    synthesizer.register_seeded_resource(
        resource_type="invoice",
        resource_id="inv-alpha-992",
        confidential_marker="CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832",
    )
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
        beta_role="member",
    )

    transport = httpx.ASGITransport(app=app)
    prober = ExploitProber(
        base_url="http://testserver",
        transport=transport,
    )

    verifier = DualPassVerifier(prober)

    # 1. Test against SECURED route: should pass CEGIS certification
    secured_route = RouteEndpoint(
        path="/api/v1/secure-invoices/{invoice_id}",
        method=HttpMethod.GET,
        path_parameters=["invoice_id"],
        requires_auth=True,
    )

    certified, status_reason, status_attacker, status_victim = await verifier.verify_patch_dual_pass(
        route=secured_route,
        context=context,
        target_resource_type="invoice",
    )

    assert certified is True
    assert status_reason == "CERTIFIED_FIX"
    assert status_attacker == 404
    assert status_victim == 200

    # 2. Test against VULNERABLE route: should fail Pass 1 (Unresolved exploit)
    vulnerable_route = RouteEndpoint(
        path="/api/v1/invoices/{invoice_id}",
        method=HttpMethod.GET,
        path_parameters=["invoice_id"],
        requires_auth=True,
    )

    certified, status_reason, status_attacker, status_victim = await verifier.verify_patch_dual_pass(
        route=vulnerable_route,
        context=context,
        target_resource_type="invoice",
    )

    assert certified is False
    assert status_reason == "UNRESOLVED_EXPLOIT"
    assert status_attacker == 200

    await prober.aclose()
