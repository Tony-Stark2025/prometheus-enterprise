"""
Unit tests for Prometheus Auto-Patch Synthesizer.
"""

from prometheus.pentest.models import (
    ExploitProof,
    HttpMethod,
    Severity,
    VulnerabilityCategory,
)
from prometheus.pentest.patch_synthesizer import PatchSynthesizer


def test_synthesize_bola_patch_for_dictionary_lookup():
    vulnerable_snippet = """@app.get("/api/v1/invoices/{invoice_id}")
async def get_invoice(invoice_id: str, current_user: UserSession = Depends(get_current_user)):
    invoice = INVOICES_DB.get(invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice
"""

    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/invoices/inv-001",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"leaked": "payroll"},
        curl_command="curl -s -i http://localhost/invoices/inv-001",
        remediation_guidance="Add tenant boundary check",
        execution_time_ms=10.0,
    )

    result = PatchSynthesizer.synthesize_bola_patch(
        original_code=vulnerable_snippet,
        proof=proof,
        target_file="app/api/invoices.py",
    )

    assert result.verification_status == "VERIFIED_FIX"
    assert result.previous_exploit_status == 200
    assert result.post_patch_status == 404
    assert "--- a/app/api/invoices.py" in result.git_diff
    assert "+++ b/app/api/invoices.py" in result.git_diff
    assert "+    if not invoice or invoice.tenant_id != current_user.tenant_id:" in result.git_diff


def test_synthesize_bola_patch_skips_non_vulnerable():
    proof = ExploitProof(
        is_vulnerable=False,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.INFO,
        target_endpoint="/api/v1/secure-invoices/inv-001",
        http_method=HttpMethod.GET,
        http_status_code=404,
        evidence_payload={},
        curl_command="",
        remediation_guidance="Secure",
        execution_time_ms=5.0,
    )

    result = PatchSynthesizer.synthesize_bola_patch(
        original_code="code",
        proof=proof,
        target_file="app/api/invoices.py",
    )

    assert result.verification_status == "NO_VULNERABILITY_TO_PATCH"
    assert result.git_diff == ""
