"""
Unit tests for Prometheus Automated Regression Test Synthesizer.
Verifies autonomous synthesis of runnable Python (pytest with httpx & requests)
and TypeScript (vitest & jest with fetch) regression tests.
"""

import ast
import json
import pytest

from prometheus.pentest.models import (
    AutoPatchResult,
    ExploitProof,
    HttpMethod,
    Severity,
    VulnerabilityCategory,
)
from prometheus.pentest.pr_reporter import PRReporter
from prometheus.pentest.regression_test_generator import RegressionTestGenerator


def test_generate_pytest_httpx_syntax_and_assertions():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="http://127.0.0.1:8000/api/v1/invoices/inv-alpha-992",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"id": "inv-alpha-992", "confidential": "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832"},
        curl_command="curl -s -i -X GET http://127.0.0.1:8000/api/v1/invoices/inv-alpha-992 -H 'Authorization: Bearer <AUTH_TOKEN_REDACTED>'",
        remediation_guidance="Enforce tenant check",
        execution_time_ms=12.5,
        attacker_headers={
            "Authorization": "Bearer token_beta_attacker",
            "X-Tenant-ID": "org-beta-attacker-002",
        },
        victim_headers={
            "Authorization": "Bearer token_alpha_victim",
            "X-Tenant-ID": "org-alpha-victim-001",
        },
        canary_marker="CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832",
    )

    code = RegressionTestGenerator.generate_pytest(proof, client_library="httpx")

    # 1. Valid Python syntax
    parsed_ast = ast.parse(code)
    assert parsed_ast is not None

    # 2. Key assertions
    assert "import httpx" in code
    assert "assert attacker_response.status_code in (403, 404)" in code
    assert "assert canary_marker not in attacker_response.text" in code
    assert "assert victim_response.status_code == 200" in code
    assert "assert canary_marker in victim_response.text" in code
    assert "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832" in code
    assert "/api/v1/invoices/inv-alpha-992" in code
    assert "org-beta-attacker-002" in code
    assert "org-alpha-victim-001" in code
    assert "token_beta_attacker" not in code
    assert "token_alpha_victim" not in code
    assert 'os.environ.get("ATTACKER_AUTH_TOKEN", "<ATTACKER_AUTH_TOKEN>")' in code
    assert 'os.environ.get("VICTIM_AUTH_TOKEN", "<VICTIM_AUTH_TOKEN>")' in code


def test_generate_pytest_requests_syntax_and_assertions():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/documents/doc-456",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"data": "CONFIDENTIAL_DOC_CANARY_99"},
        curl_command="curl -s -i -X GET http://testserver/api/v1/documents/doc-456",
        remediation_guidance="Enforce tenant check",
        execution_time_ms=15.0,
        canary_marker="CONFIDENTIAL_DOC_CANARY_99",
    )

    code = RegressionTestGenerator.generate_pytest(proof, client_library="requests")

    # Valid Python syntax
    parsed_ast = ast.parse(code)
    assert parsed_ast is not None

    assert "import requests" in code
    assert "assert attacker_response.status_code in (403, 404)" in code
    assert "assert canary_marker not in attacker_response.text" in code
    assert "assert victim_response.status_code == 200" in code
    assert "assert canary_marker in victim_response.text" in code
    assert "CONFIDENTIAL_DOC_CANARY_99" in code


def test_generate_typescript_vitest_and_jest():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="http://127.0.0.1:8000/api/v1/workspaces/ws-victim-100",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"secret": "CONFIDENTIAL_WS_CANARY_777"},
        curl_command="curl -s -i -X GET http://127.0.0.1:8000/api/v1/workspaces/ws-victim-100",
        remediation_guidance="Filter by tenant",
        execution_time_ms=9.8,
        canary_marker="CONFIDENTIAL_WS_CANARY_777",
    )

    vitest_code = RegressionTestGenerator.generate_typescript(proof, test_runner="vitest")
    assert 'import { describe, expect, it } from "vitest";' in vitest_code
    assert "fetch(targetUrl" in vitest_code
    assert "expect([403, 404]).toContain(response.status)" in vitest_code
    assert "expect(responseText).not.toContain(canaryMarker)" in vitest_code
    assert "expect(response.status).toBe(200)" in vitest_code
    assert "expect(responseText).toContain(canaryMarker)" in vitest_code
    assert "CONFIDENTIAL_WS_CANARY_777" in vitest_code

    jest_code = RegressionTestGenerator.generate_typescript(proof, test_runner="jest")
    assert 'import { describe, expect, it } from "@jest/globals";' in jest_code
    assert "expect([403, 404]).toContain(response.status)" in jest_code
    assert "expect(response.status).toBe(200)" in jest_code


def test_generate_with_request_body_mutation():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/invoices/inv-alpha-992/update",
        http_method=HttpMethod.PUT,
        http_status_code=200,
        evidence_payload={"updated": True, "token": "CONFIDENTIAL_CANARY_TOKEN"},
        curl_command="curl -s -i -X PUT http://test/api/v1/invoices/inv-alpha-992/update --data '{\"amount\": 9999}'",
        remediation_guidance="Fix mutation check",
        execution_time_ms=20.0,
        canary_marker="CONFIDENTIAL_CANARY_TOKEN",
        request_body={"amount": 9999, "status": "approved"},
    )

    py_code = RegressionTestGenerator.generate_pytest(proof, client_library="httpx")
    assert ast.parse(py_code) is not None
    assert "json=request_payload" in py_code
    assert '"amount": 9999' in py_code

    ts_code = RegressionTestGenerator.generate_typescript(proof)
    assert 'body: JSON.stringify({"amount": 9999, "status": "approved"})' in ts_code


def test_fallback_canary_extraction_from_evidence_payload():
    # Proof without explicit canary_marker or headers
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/accounts/acc-01",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"confidential_key": "SUPER_SECRET_TENANT_DATA"},
        curl_command="curl -s -i -X GET http://localhost/api/v1/accounts/acc-01",
        remediation_guidance="Check account tenant",
        execution_time_ms=11.2,
    )

    py_code = RegressionTestGenerator.generate_pytest(proof)
    assert ast.parse(py_code) is not None
    assert "SUPER_SECRET_TENANT_DATA" in py_code


def test_generate_all_variants():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/orders/ord-99",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"order": "CONFIDENTIAL_ORDER_INFO"},
        curl_command="curl -s -i -X GET http://test/api/v1/orders/ord-99",
        remediation_guidance="Check order",
        execution_time_ms=10.0,
        canary_marker="CONFIDENTIAL_ORDER_INFO",
    )

    all_tests = RegressionTestGenerator.generate_all(proof)
    assert "pytest_httpx" in all_tests
    assert "pytest_requests" in all_tests
    assert "typescript_vitest" in all_tests
    assert "typescript_jest" in all_tests

    assert "import httpx" in all_tests["pytest_httpx"]
    assert "import requests" in all_tests["pytest_requests"]
    assert "vitest" in all_tests["typescript_vitest"]
    assert "@jest/globals" in all_tests["typescript_jest"]


def test_pr_reporter_integrates_regression_tests():
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

    # Asserts that the regression test sections are present in markdown
    assert "### 🧪 Automated CI/CD Regression Tests" in comment
    assert "Python (pytest + httpx)" in comment
    assert "TypeScript (vitest / jest + fetch)" in comment
    assert "assert attacker_response.status_code in (403, 404)" in comment
    assert "expect([403, 404]).toContain(response.status)" in comment


def test_generate_with_template_placeholders_and_special_chars():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/workspaces/{workspace_id}/items?filter=active&sort=desc",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"data": "quote \"canary\" and backslash \\ test"},
        curl_command="curl -s -i -X GET 'http://testserver/api/v1/workspaces/{workspace_id}/items?filter=active&sort=desc'",
        remediation_guidance="Enforce isolation",
        execution_time_ms=18.0,
        canary_marker='quote "canary" and backslash \\ test',
    )

    py_code = RegressionTestGenerator.generate_pytest(proof, client_library="httpx")
    # Must parse without SyntaxError
    parsed_py = ast.parse(py_code)
    assert parsed_py is not None
    # Function name must be valid and clean
    assert "def test_api_v1_workspaces_workspace_id_items_tenant_isolation():" in py_code
    # Canary string must be properly escaped
    assert r'"quote \"canary\" and backslash \\ test"' in py_code

    ts_code = RegressionTestGenerator.generate_typescript(proof)
    assert "describe(" in ts_code
    assert r'"quote \"canary\" and backslash \\ test"' in ts_code


def test_generate_redacts_custom_auth_tokens_and_api_keys():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/tenants/t1",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"marker": "canary123"},
        curl_command="curl -s -i -X GET http://test/api/v1/tenants/t1",
        remediation_guidance="Enforce tenant check",
        execution_time_ms=10.0,
        attacker_headers={
            "Authorization": "Bearer sensitive_attacker_token_xyz",
            "X-API-Key": "super_secret_attacker_api_key",
        },
        victim_headers={
            "Authorization": "Bearer sensitive_victim_token_abc",
            "X-API-Key": "super_secret_victim_api_key",
        },
        canary_marker="canary123",
    )

    redacted_py = RegressionTestGenerator.generate_pytest(proof, redact_tokens=True)
    assert "sensitive_attacker_token_xyz" not in redacted_py
    assert "super_secret_attacker_api_key" not in redacted_py
    assert "sensitive_victim_token_abc" not in redacted_py
    assert "super_secret_victim_api_key" not in redacted_py
    assert "<ATTACKER_AUTH_TOKEN>" in redacted_py
    assert "<VICTIM_AUTH_TOKEN>" in redacted_py
    assert 'os.environ.get("ATTACKER_AUTH_TOKEN", "<ATTACKER_AUTH_TOKEN>")' in redacted_py
    assert 'os.environ.get("VICTIM_AUTH_TOKEN", "<VICTIM_AUTH_TOKEN>")' in redacted_py
    assert 'os.environ.get("ATTACKER_API_KEY", "<ATTACKER_API_KEY>")' in redacted_py
    assert 'os.environ.get("VICTIM_API_KEY", "<VICTIM_API_KEY>")' in redacted_py


def test_generate_typescript_parameterizes_credentials_via_process_env():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/projects/prj-77",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"marker": "canary-prj-77"},
        curl_command="curl -s -i -X GET http://test/api/v1/projects/prj-77",
        remediation_guidance="Enforce tenant check",
        execution_time_ms=10.0,
        attacker_headers={
            "Authorization": "Bearer secret_jwt_beta",
            "X-API-Key": "secret_api_key_beta",
            "X-Tenant-ID": "org-beta-attacker-002",
        },
        victim_headers={
            "Authorization": "Bearer secret_jwt_alpha",
            "X-API-Key": "secret_api_key_alpha",
            "X-Tenant-ID": "org-alpha-victim-001",
        },
        canary_marker="canary-prj-77",
    )

    ts_code = RegressionTestGenerator.generate_typescript(proof)
    assert "secret_jwt_beta" not in ts_code
    assert "secret_api_key_beta" not in ts_code
    assert "secret_jwt_alpha" not in ts_code
    assert "secret_api_key_alpha" not in ts_code

    # Verify process.env parameterization
    assert 'process.env.ATTACKER_AUTH_TOKEN || "<ATTACKER_AUTH_TOKEN>"' in ts_code
    assert 'process.env.VICTIM_AUTH_TOKEN || "<VICTIM_AUTH_TOKEN>"' in ts_code
    assert 'process.env.ATTACKER_API_KEY || "<ATTACKER_API_KEY>"' in ts_code
    assert 'process.env.VICTIM_API_KEY || "<VICTIM_API_KEY>"' in ts_code

    # Verify operational tenant IDs are preserved
    assert '"X-Tenant-ID": "org-beta-attacker-002"' in ts_code
    assert '"X-Tenant-ID": "org-alpha-victim-001"' in ts_code


def test_fallback_canary_extraction_from_victim_headers():
    proof = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        target_endpoint="/api/v1/workspaces/ws-01",
        http_method=HttpMethod.GET,
        http_status_code=200,
        evidence_payload={"status": "ok"},
        curl_command="curl -s -i -X GET http://localhost/api/v1/workspaces/ws-01",
        remediation_guidance="Check workspace tenant",
        execution_time_ms=10.0,
        canary_marker="",
        victim_headers={"X-Tenant-ID": "tenant-alpha-custom-777"},
    )

    py_code = RegressionTestGenerator.generate_pytest(proof)
    assert "tenant-alpha-custom-777" in py_code
    assert "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832" not in py_code



