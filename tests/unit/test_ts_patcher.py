"""
Unit tests for Polyglot AST Program Repair (TypeScript/JavaScript & Python BOLA/BFLA Patching).
"""

import pytest
from prometheus.pentest.models import (
    ExploitProof,
    HttpMethod,
    Severity,
    VulnerabilityCategory,
)
from prometheus.pentest.ast_patcher import (
    ASTPatchSynthesizer,
    TypeScriptPatchSynthesizer,
)


@pytest.fixture
def ts_fixture_content():
    with open("tests/fixtures/ts_express_app.ts", "r", encoding="utf-8") as f:
        return f.read()


def test_is_typescript_or_javascript_detection(ts_fixture_content):
    assert TypeScriptPatchSynthesizer.is_typescript_or_javascript(ts_fixture_content, "server.ts") is True
    assert TypeScriptPatchSynthesizer.is_typescript_or_javascript(ts_fixture_content, "api.js") is True
    assert TypeScriptPatchSynthesizer.is_typescript_or_javascript("def foo(): pass", "main.py") is False


def test_ts_prisma_bola_patch_synthesis(ts_fixture_content):
    proof = ExploitProof(
        target_endpoint="/api/v1/invoices/inv-alpha-992",
        http_method=HttpMethod.GET,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        is_vulnerable=True,
        evidence_payload={"secret_marker": "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832"},
        http_status_code=200,
        curl_command="curl -X GET http://localhost:8000/api/v1/invoices/inv-alpha-992",
        remediation_guidance="Enforce tenant isolation on invoice lookup.",
        execution_time_ms=12.4,
    )

    result = ASTPatchSynthesizer.synthesize_patch(
        original_code=ts_fixture_content,
        proof=proof,
        target_file="src/routes/invoices.ts",
    )

    assert result.verification_status == "PENDING_VERIFICATION"
    assert result.post_patch_status == 404
    assert result.git_diff != ""

    # Verify that tenant boundary condition was injected
    assert "tenantId" in result.git_diff
    assert "req.user?.tenantId" in result.git_diff
    assert "-  if (!invoice) {" in result.git_diff or "if (!invoice ||" in result.git_diff


def test_ts_bfla_delete_patch_synthesis(ts_fixture_content):
    proof = ExploitProof(
        target_endpoint="/api/v1/workspaces/ws-alpha-001",
        http_method=HttpMethod.DELETE,
        vector=VulnerabilityCategory.BFLA,
        severity=Severity.HIGH,
        is_vulnerable=True,
        evidence_payload={"status": "DELETED"},
        http_status_code=200,
        curl_command="curl -X DELETE http://localhost:8000/api/v1/workspaces/ws-alpha-001",
        remediation_guidance="Enforce admin role requirement for workspace deletion.",
        execution_time_ms=8.5,
    )

    result = ASTPatchSynthesizer.synthesize_patch(
        original_code=ts_fixture_content,
        proof=proof,
        target_file="src/routes/workspaces.ts",
    )

    assert result.verification_status == "PENDING_VERIFICATION"
    assert result.post_patch_status == 403
    assert result.git_diff != ""

    # Verify that admin role check was injected
    assert "req.user?.role !== 'admin'" in result.git_diff
    assert "403" in result.git_diff


def test_python_bola_patch_still_works():
    py_code = """
@app.get("/api/v1/invoices/{invoice_id}")
def get_invoice(invoice_id: str, db: Session = Depends(get_db)):
    return db.query(Invoice).filter(Invoice.id == invoice_id).first()
"""
    proof = ExploitProof(
        target_endpoint="/api/v1/invoices/123",
        http_method=HttpMethod.GET,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        is_vulnerable=True,
        evidence_payload={"id": "123"},
        http_status_code=200,
        curl_command="curl ...",
        remediation_guidance="Enforce tenant check.",
        execution_time_ms=5.0,
    )

    result = ASTPatchSynthesizer.synthesize_patch(
        original_code=py_code,
        proof=proof,
        target_file="app/api.py",
    )

    assert result.verification_status == "PENDING_VERIFICATION"
    assert result.git_diff != ""
    assert "current_user" in result.git_diff
    assert "tenant_id" in result.git_diff


def test_python_bfla_patch_synthesis():
    py_code = """
@app.delete("/api/v1/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str):
    return {"status": "DELETED"}
"""
    proof = ExploitProof(
        target_endpoint="/api/v1/workspaces/123",
        http_method=HttpMethod.DELETE,
        vector=VulnerabilityCategory.BFLA,
        severity=Severity.HIGH,
        is_vulnerable=True,
        evidence_payload={"status": "DELETED"},
        http_status_code=200,
        curl_command="curl ...",
        remediation_guidance="Enforce admin check.",
        execution_time_ms=4.2,
    )

    result = ASTPatchSynthesizer.synthesize_patch(
        original_code=py_code,
        proof=proof,
        target_file="app/api.py",
    )

    assert result.verification_status == "PENDING_VERIFICATION"
    assert result.post_patch_status == 403
    assert "current_user" in result.git_diff
    assert "admin" in result.git_diff
