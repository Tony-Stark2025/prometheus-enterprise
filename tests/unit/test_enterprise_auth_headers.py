"""
Unit tests for Prometheus Enterprise IdP Authentication Headers.
Verifies custom Bearer / Okta / Keycloak auth header injection and HS256 JWT bypass.
"""

import argparse
from unittest.mock import MagicMock
import jwt
import pytest
import httpx

from prometheus.pentest.benchmark_app import app as benchmark_fastapi_app
from prometheus.pentest.state_synthesizer import StateSynthesizer
from prometheus.cli_scan import run_scan


def test_state_synthesizer_bypasses_jwt_for_alpha():
    synthesizer = StateSynthesizer()
    synthesizer.mint_token = MagicMock(side_effect=synthesizer.mint_token)

    custom_header_alpha = "Bearer okta_victim_live_token_alpha_999"
    context = synthesizer.create_dual_context(
        auth_header_alpha=custom_header_alpha,
    )

    # Tenant Alpha should use the pre-minted enterprise token directly
    assert context.tenant_alpha.headers["Authorization"] == custom_header_alpha
    assert context.tenant_alpha.jwt_token == "okta_victim_live_token_alpha_999"

    # mint_token should NOT have been called for Alpha
    called_tenant_ids = [call.kwargs.get("tenant_id") for call in synthesizer.mint_token.call_args_list]
    assert "org-alpha-victim-001" not in called_tenant_ids
    # But Beta should still be minted normally
    assert "org-beta-attacker-002" in called_tenant_ids


def test_state_synthesizer_bypasses_jwt_for_beta():
    synthesizer = StateSynthesizer()
    synthesizer.mint_token = MagicMock(side_effect=synthesizer.mint_token)

    custom_header_beta = "Bearer keycloak_attacker_live_token_beta_888"
    context = synthesizer.create_dual_context(
        auth_header_beta=custom_header_beta,
    )

    # Tenant Beta should use the pre-minted enterprise token directly
    assert context.tenant_beta.headers["Authorization"] == custom_header_beta
    assert context.tenant_beta.jwt_token == "keycloak_attacker_live_token_beta_888"

    # mint_token should NOT have been called for Beta
    called_tenant_ids = [call.kwargs.get("tenant_id") for call in synthesizer.mint_token.call_args_list]
    assert "org-beta-attacker-002" not in called_tenant_ids
    # Alpha should still be minted
    assert "org-alpha-victim-001" in called_tenant_ids


def test_state_synthesizer_both_enterprise_headers_no_minting():
    synthesizer = StateSynthesizer()
    synthesizer.mint_token = MagicMock()

    context = synthesizer.create_dual_context(
        auth_header_alpha="Bearer okta_alpha_token_111",
        auth_header_beta="Bearer okta_beta_token_222",
    )

    # Zero local HS256 tokens minted
    synthesizer.mint_token.assert_not_called()
    assert context.tenant_alpha.headers["Authorization"] == "Bearer okta_alpha_token_111"
    assert context.tenant_beta.headers["Authorization"] == "Bearer okta_beta_token_222"


def test_state_synthesizer_formats_raw_tokens_without_bearer():
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        auth_header_alpha="raw_token_alpha_xyz",
        auth_header_beta="raw_token_beta_uvw",
    )

    assert context.tenant_alpha.jwt_token == "raw_token_alpha_xyz"
    assert context.tenant_alpha.headers["Authorization"] == "Bearer raw_token_alpha_xyz"
    assert context.tenant_beta.jwt_token == "raw_token_beta_uvw"
    assert context.tenant_beta.headers["Authorization"] == "Bearer raw_token_beta_uvw"


def test_state_synthesizer_extracts_claims_from_enterprise_jwt():
    synthesizer = StateSynthesizer()

    # Create dummy unverified Keycloak/Okta JWT
    token_claims = {
        "tenant_id": "org-enterprise-okta-456",
        "user_id": "usr-okta-chief-architect",
        "email": "architect@enterprise.corp",
        "role": "admin",
    }
    raw_jwt = jwt.encode(token_claims, "dummy-secret-key", algorithm="HS256")

    context = synthesizer.create_dual_context(
        auth_header_alpha=f"Bearer {raw_jwt}",
    )

    assert context.tenant_alpha.tenant_id == "org-enterprise-okta-456"
    assert context.tenant_alpha.user_id == "usr-okta-chief-architect"
    assert context.tenant_alpha.email == "architect@enterprise.corp"
    assert context.tenant_alpha.role == "admin"


def test_cli_scan_parser_accepts_auth_header_args():
    from prometheus.cli_scan import build_parser

    parser = build_parser()
    parsed = parser.parse_args([
        "--target-url", "http://127.0.0.1:9000",
        "--spec", "dummy.json",
        "--auth-header-alpha", "Bearer okta_alpha_token",
        "--auth-header-beta", "Bearer keycloak_beta_token",
        "--output-test", "test_regression.py",
    ])
    assert parsed.auth_header_alpha == "Bearer okta_alpha_token"
    assert parsed.auth_header_beta == "Bearer keycloak_beta_token"
    assert parsed.output_test == "test_regression.py"


def test_state_synthesizer_supports_full_authorization_header_format():
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        auth_header_alpha="Authorization: Bearer okta_alpha_full_hdr",
        auth_header_beta="Authorization: raw_keycloak_beta_hdr",
    )

    # Must NOT create duplicate "Authorization: Authorization: ..."
    assert context.tenant_alpha.headers["Authorization"] == "Bearer okta_alpha_full_hdr"
    assert context.tenant_alpha.jwt_token == "okta_alpha_full_hdr"
    assert context.tenant_beta.headers["Authorization"] == "Bearer raw_keycloak_beta_hdr"
    assert context.tenant_beta.jwt_token == "raw_keycloak_beta_hdr"


def test_state_synthesizer_supports_custom_header_format():
    synthesizer = StateSynthesizer()
    context = synthesizer.create_dual_context(
        auth_header_alpha="X-API-Key: okta-api-key-999",
        auth_header_beta="X-Auth-Token: keycloak-token-888",
    )

    assert context.tenant_alpha.headers["X-API-Key"] == "okta-api-key-999"
    assert context.tenant_alpha.headers["Authorization"] == "Bearer okta-api-key-999"
    assert context.tenant_beta.headers["X-Auth-Token"] == "keycloak-token-888"
    assert context.tenant_beta.headers["Authorization"] == "Bearer keycloak-token-888"


@pytest.mark.asyncio
async def test_run_scan_with_enterprise_auth_headers_execution():
    spec = benchmark_fastapi_app.openapi()
    transport = httpx.ASGITransport(app=benchmark_fastapi_app)

    # Run scan passing enterprise auth headers
    exit_code = await run_scan(
        target_url="http://testserver",
        spec_data=spec,
        transport=transport,
        auth_header_alpha="Bearer enterprise_alpha_token",
        auth_header_beta="Bearer enterprise_beta_token",
        fail_on_exploit=False,
    )

    assert exit_code == 0


@pytest.mark.asyncio
async def test_run_scan_with_github_step_summary_and_ts_export(tmp_path):
    import os
    spec = benchmark_fastapi_app.openapi()
    transport = httpx.ASGITransport(app=benchmark_fastapi_app)

    step_summary_file = tmp_path / "step_summary.md"
    ts_test_file = tmp_path / "test_regression.ts"

    old_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    os.environ["GITHUB_STEP_SUMMARY"] = str(step_summary_file)
    try:
        exit_code = await run_scan(
            target_url="http://testserver",
            spec_data=spec,
            transport=transport,
            output_test_file=str(ts_test_file),
            fail_on_exploit=False,
        )
        assert exit_code == 0
        assert step_summary_file.exists()
        summary_content = step_summary_file.read_text(encoding="utf-8")
        assert "Prometheus Autonomous Security Gate Summary" in summary_content
        # If vulnerabilities were found, regression test was written and embedded in summary
        if ts_test_file.exists():
            ts_content = ts_test_file.read_text(encoding="utf-8")
            assert "vitest" in ts_content or "fetch" in ts_content
            assert "describe(" in ts_content
    finally:
        if old_summary is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = old_summary
        else:
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
