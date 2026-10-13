"""
Unit tests for Sprint 2 Live CEGIS Loop & Dynamic AI Fallback:
- Verifies ProviderManager dynamic fallback synthesizer integration in ASTPatchSynthesizer.
- Verifies dynamic source file discovery for target routes.
- Verifies DualPassVerifier verify_patch_oracle alias.
"""

from unittest.mock import AsyncMock, MagicMock
import pytest

from prometheus.pentest.ast_patcher import ASTPatchSynthesizer
from prometheus.pentest.cegis_verifier import DualPassVerifier
from prometheus.pentest.engine import PrometheusAdversarialEngine
from prometheus.pentest.models import ExploitProof, HttpMethod, RouteEndpoint, Severity, VulnerabilityCategory


@pytest.mark.asyncio
async def test_ast_patch_synthesizer_ai_fallback_on_unsupported_framework():
    # Framework pattern not matching standard FastAPI or Express patterns (e.g., custom framework)
    custom_code = """
def handle_invoice_query(req, res):
    inv = custom_orm_get(req.params.id)
    return res.json(inv)
"""
    proof = ExploitProof(
        target_endpoint="/custom/invoices/123",
        http_method=HttpMethod.GET,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        is_vulnerable=True,
        evidence_payload={"secret": "leak"},
        http_status_code=200,
        curl_command="curl http://test/custom/invoices/123",
        remediation_guidance="Enforce tenant check",
        execution_time_ms=10.0,
    )

    # Mock ProviderManager returning structured JSON patch
    mock_pm = MagicMock()
    mock_pm.generate_structured_json = AsyncMock(return_value={
        "patched_code": """
def handle_invoice_query(req, res):
    inv = custom_orm_get(req.params.id)
    if inv.tenant_id != req.user.tenant_id:
        return res.status(404).json({"error": "Not found"})
    return res.json(inv)
""",
        "explanation": "Added tenant isolation check",
    })

    result = await ASTPatchSynthesizer.synthesize_patch_with_fallback(
        original_code=custom_code,
        proof=proof,
        target_file="custom_app.py",
        provider_manager=mock_pm,
    )

    assert result.git_diff != ""
    assert "inv.tenant_id != req.user.tenant_id" in result.git_diff
    assert mock_pm.generate_structured_json.called


def test_locate_target_file_for_route_finds_real_source():
    route = RouteEndpoint(
        path="/api/v1/invoices/{invoice_id}",
        method=HttpMethod.GET,
        path_parameters=["invoice_id"],
    )
    rel_path, content = PrometheusAdversarialEngine._locate_target_file_for_route(route)
    assert "benchmark_app.py" in rel_path
    assert "/api/v1/invoices/{invoice_id}" in content


def test_dual_pass_verifier_has_oracle_alias():
    prober_mock = MagicMock()
    verifier = DualPassVerifier(prober_mock)
    assert hasattr(verifier, "verify_patch_oracle")
    assert verifier.verify_patch_oracle == verifier.verify_patch_dual_pass
