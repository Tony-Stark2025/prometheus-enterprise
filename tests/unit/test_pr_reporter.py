"""
Unit tests for Prometheus GitHub PR Reporter and Slack alert formatter.
"""

from prometheus.pentest.models import (
    AutoPatchResult,
    ExploitProof,
    HttpMethod,
    Severity,
    VulnerabilityCategory,
)
from prometheus.pentest.pr_reporter import PRReporter


def test_format_github_pr_comment_vulnerable():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/invoices/inv-001",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"leaked": "payroll_secret"},
        curl_command="curl -s -i -X GET http://test/api/v1/invoices/inv-001",
        remediation_guidance="Filter by tenant_id",
        execution_time_ms=15.4,
    )

    patch = AutoPatchResult(
        target_file="app/api/invoices.py",
        git_diff="--- a/invoices.py\n+++ b/invoices.py\n+ tenant filter",
        verification_status="VERIFIED_FIX",
        previous_exploit_status=200,
        post_patch_status=404,
    )

    comment = PRReporter.format_github_pr_comment(proof, patch)

    assert "CRITICAL Exploit Verified" in comment
    assert "Broken Object Level Authorization" in comment
    assert "curl -s -i -X GET http://test/api/v1/invoices/inv-001" in comment
    assert "payroll_secret" in comment
    assert "--- a/invoices.py" in comment
    assert "15.4ms" in comment


def test_format_github_pr_comment_clean():
    proof = ExploitProof(
        is_vulnerable=False,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.INFO,
        target_endpoint="/api/v1/secure-invoices/inv-001",
        http_method=HttpMethod.GET,
        http_status_code=404,
        evidence_payload={},
        curl_command="",
        remediation_guidance="Clean",
        execution_time_ms=8.2,
    )

    comment = PRReporter.format_github_pr_comment(proof)
    assert "Clean Bill of Health" in comment
    assert "Zero cross-tenant data leakage detected" in comment


def test_format_slack_alert():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/invoices/inv-001",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={},
        curl_command="curl -s -i http://test",
        remediation_guidance="",
        execution_time_ms=10.0,
    )

    alert = PRReporter.format_slack_alert(proof, repo="acme/backend", pr_number=42)
    assert "CRITICAL Exploit in acme/backend PR #42" in alert["text"]
    assert len(alert["blocks"]) == 3
