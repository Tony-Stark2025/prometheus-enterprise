"""
Unit tests for Sprint 1 AppSec & SRE Hardening:
- SSRF defense against IPv6-mapped IPv4, decimal IP literals, hex literals, and cloud metadata.
- Token redaction in ProofValidator and PRReporter.
- Safe process-tree termination helper.
"""

import subprocess
import sys
import pytest

from prometheus.cli_scan import terminate_process_tree
from prometheus.pentest.exploit_prober import ExploitProber, SSRFValidationError, validate_ssrf
from prometheus.pentest.models import ExploitProbeRequest, HttpMethod, VulnerabilityCategory
from prometheus.pentest.proof_validator import ProofValidator
from prometheus.pentest.pr_reporter import PRReporter


def test_ssrf_blocks_ipv6_mapped_ipv4_metadata():
    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://[::ffff:169.254.169.254]/latest/meta-data")


def test_ssrf_blocks_decimal_ip_metadata():
    # 2852039166 is decimal representation of 169.254.169.254
    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://2852039166/latest/meta-data")


def test_ssrf_blocks_hex_ip_metadata():
    # 0xa9fea9fe is hex representation of 169.254.169.254
    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://0xa9fea9fe/latest/meta-data")


def test_ssrf_strict_mode_blocks_loopback_and_private():
    with pytest.raises(SSRFValidationError, match="strict SSRF mode"):
        validate_ssrf("http://127.0.0.1:8000/spec", allow_loopback=False)

    with pytest.raises(SSRFValidationError, match="strict SSRF mode"):
        validate_ssrf("http://[::ffff:127.0.0.1]:8000/spec", allow_loopback=False)


def test_ssrf_blocks_unsupported_schemes():
    with pytest.raises(SSRFValidationError, match="Unsupported URL scheme"):
        validate_ssrf("file:///etc/passwd")

    with pytest.raises(SSRFValidationError, match="Unsupported URL scheme"):
        validate_ssrf("gopher://127.0.0.1:8000")


def test_ssrf_blocks_octal_ip_metadata():
    # 025177524776 is octal representation of 169.254.169.254
    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://025177524776/latest/meta-data")

    # Dotted octal 0251.0376.0251.0376
    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://0251.0376.0251.0376/latest/meta-data")


def test_ssrf_blocks_rebinding_domains_embedding_metadata():
    # nip.io embedding metadata IP is blocked even in loopback mode
    with pytest.raises(SSRFValidationError, match="blocked cloud metadata IP"):
        validate_ssrf("http://169.254.169.254.nip.io/latest/meta-data", allow_loopback=True)

    # Dynamic rebinding domains blocked in strict mode
    with pytest.raises(SSRFValidationError, match="dynamic DNS rebinding service"):
        validate_ssrf("http://preview.localtest.me/spec", allow_loopback=False)


def test_ssrf_strict_mode_blocks_unresolvable_hosts():
    with pytest.raises(SSRFValidationError, match="Cannot resolve target hostname"):
        validate_ssrf("http://nonexistent-host-99999.invalid/spec", allow_loopback=False)


def test_proof_validator_redact_tokens():
    probe = ExploitProbeRequest(
        target_url="http://example.com/api/v1/invoices/inv-001",
        method=HttpMethod.GET,
        headers={"Authorization": "Bearer super_sensitive_jwt_token_12345", "X-Custom": "val"},
        path_params={},
        query_params={},
        body=None,
        vector=VulnerabilityCategory.BOLA_IDOR,
        hypothesis="test",
    )

    unredacted = ProofValidator.generate_curl_command(probe, redact_tokens=False)
    assert "super_sensitive_jwt_token_12345" in unredacted

    redacted = ProofValidator.generate_curl_command(probe, redact_tokens=True)
    assert "super_sensitive_jwt_token_12345" not in redacted
    assert "<AUTH_TOKEN_REDACTED>" in redacted

    # Test that DEFAULT generate_curl_command is redacted
    default_curl = ProofValidator.generate_curl_command(probe)
    assert "super_sensitive_jwt_token_12345" not in default_curl
    assert "<AUTH_TOKEN_REDACTED>" in default_curl

    # Test redact_curl_tokens utility
    redacted_from_raw = ProofValidator.redact_curl_tokens(unredacted)
    assert "super_sensitive_jwt_token_12345" not in redacted_from_raw
    assert "<AUTH_TOKEN_REDACTED>" in redacted_from_raw

    # Test Slack Alert token redaction
    validator = ProofValidator()
    proof = validator.evaluate_bola_response(
        probe=probe,
        status_code=200,
        response_body={"secret": "canary"},
        expected_victim_marker="canary",
        execution_time_ms=5.0,
    )
    assert "super_sensitive_jwt_token_12345" not in proof.curl_command
    assert "<AUTH_TOKEN_REDACTED>" in proof.curl_command

    slack_alert = PRReporter.format_slack_alert(proof, "org/repo", 42)
    alert_str = str(slack_alert)
    assert "super_sensitive_jwt_token_12345" not in alert_str
    assert "<AUTH_TOKEN_REDACTED>" in alert_str


def test_terminate_process_tree_noop_on_none():
    terminate_process_tree(None)


@pytest.mark.asyncio
async def test_admin_dependency_fails_closed(monkeypatch):
    from fastapi import HTTPException
    from prometheus.auth.dependencies import get_current_admin_user, UserContext
    from prometheus.config import settings

    monkeypatch.setattr(settings, "allow_insecure_admin", False)
    non_admin_user = UserContext(user_id="normal-user", roles=["developer"])

    with pytest.raises(HTTPException) as exc_info:
        await get_current_admin_user(user=non_admin_user)
    assert exc_info.value.status_code == 403

    # Even if allow_insecure_admin is True, production must still reject non-admin
    monkeypatch.setattr(settings, "allow_insecure_admin", True)
    monkeypatch.setattr(settings, "environment", "production")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_admin_user(user=non_admin_user)
    assert exc_info.value.status_code == 403

    # Valid admin user passes
    admin_user = UserContext(user_id="admin-user", roles=["admin"])
    result = await get_current_admin_user(user=admin_user)
    assert result.user_id == "admin-user"


def test_ssrf_blocks_aws_ipv6_and_oci_metadata():
    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://[fd00:ec2::254]/latest/meta-data")

    with pytest.raises(SSRFValidationError, match="cloud metadata endpoint"):
        validate_ssrf("http://192.0.0.192/latest/meta-data")


def test_ssrf_disentangles_loopback_from_rfc1918_private():
    # allow_loopback=True allows 127.0.0.1 without raising
    validate_ssrf("http://127.0.0.1:8000/spec", allow_loopback=True)

    # allow_loopback=True MUST STILL BLOCK RFC1918 private subnets
    with pytest.raises(SSRFValidationError, match="RFC1918 private subnet"):
        validate_ssrf("http://10.0.0.1:8000/spec", allow_loopback=True)

    with pytest.raises(SSRFValidationError, match="RFC1918 private subnet"):
        validate_ssrf("http://172.16.0.1:8000/spec", allow_loopback=True)

    with pytest.raises(SSRFValidationError, match="RFC1918 private subnet"):
        validate_ssrf("http://192.168.1.1:8000/spec", allow_loopback=True)


@pytest.mark.asyncio
async def test_persona_endpoint_locked_outside_development(monkeypatch):
    from httpx import AsyncClient, ASGITransport
    from prometheus.main import app
    from prometheus.config import settings

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. In production -> 403 Forbidden
        monkeypatch.setattr(settings, "environment", "production")
        res_prod = await ac.post("/api/v1/auth/persona", json={"user_id": "elena.lead"})
        assert res_prod.status_code == 403
        assert "Forbidden" in res_prod.json()["detail"]

        # 2. In staging -> 403 Forbidden
        monkeypatch.setattr(settings, "environment", "staging")
        res_staging = await ac.post("/api/v1/auth/persona", json={"user_id": "elena.lead"})
        assert res_staging.status_code == 403

        # 3. In development -> 200 OK
        monkeypatch.setattr(settings, "environment", "development")
        res_dev = await ac.post("/api/v1/auth/persona", json={"user_id": "elena.lead"})
        assert res_dev.status_code == 200
        assert res_dev.json()["status"] == "authenticated"
        assert "token" in res_dev.json()


def test_token_authority_tenant_confinement_attenuation():
    from prometheus.proxy.token_authority import TokenAuthority, AttenuationViolationError
    ta = TokenAuthority()

    # Mint unconfined root token
    root = ta.mint_token(
        subject="admin-agent",
        allowed_methods=["GET", "POST", "PUT"],
        allowed_resource_ids=["*"],
        ttl_seconds=50,
        tenant_id=None,
    )
    assert root.scope.tenant_id is None

    # Attenuate into specific tenant boundary
    child_alpha = ta.attenuate_token(root, tenant_id="tenant-alpha-001")
    assert child_alpha.scope.tenant_id == "tenant-alpha-001"

    # Attenuating child to a different tenant must fail with AttenuationViolationError
    with pytest.raises(AttenuationViolationError, match="Tenant escalation forbidden"):
        ta.attenuate_token(child_alpha, tenant_id="tenant-beta-002")

    # Validate action on matching tenant succeeds
    denial = ta.validate_action(child_alpha, method="GET", resource_id="res-1", tenant_id="tenant-alpha-001")
    assert denial is None

    # Validate action on mismatched tenant fails with TenantConfinementViolation
    denial_mismatch = ta.validate_action(child_alpha, method="GET", resource_id="res-1", tenant_id="tenant-beta-002")
    assert denial_mismatch is not None
    assert "TenantConfinementViolation" in denial_mismatch.violated_invariant


def test_state_invariant_nested_resource_id_extraction():
    from prometheus.proxy.state_invariants import StateInvariantGate

    # Direct top-level
    assert StateInvariantGate.extract_resource_id_from_body_or_query(
        "http://target/items", {"resource_id": "res-direct-01"}
    ) == "res-direct-01"

    # Nested under args (MCP / JSON-RPC pattern)
    assert StateInvariantGate.extract_resource_id_from_body_or_query(
        "http://target/items", {"args": {"resource_id": "res-nested-args"}}
    ) == "res-nested-args"

    # Nested under params
    assert StateInvariantGate.extract_resource_id_from_body_or_query(
        "http://target/items", {"params": {"draft_id": "draft-nested-999"}}
    ) == "draft-nested-999"

    # Nested under body
    assert StateInvariantGate.extract_resource_id_from_body_or_query(
        "http://target/items", {"body": {"invoice_id": "inv-nested-111"}}
    ) == "inv-nested-111"


@pytest.mark.asyncio
async def test_agent_handles_unbound_hypothesis_safely():
    from prometheus.pentest.agent import AutonomousExploitAgent, AttackHypothesis
    from prometheus.pentest.models import RouteEndpoint
    from prometheus.pentest.state_synthesizer import StateSynthesizer

    synth = StateSynthesizer()
    ctx = synth.create_dual_context()
    prober = ExploitProber(base_url="http://127.0.0.1:8000", allow_loopback=True)

    dummy_ep = RouteEndpoint(
        path="/api/v1/custom",
        method=HttpMethod.POST,
        summary="Custom",
        tags=["custom"],
    )

    agent = AutonomousExploitAgent(
        base_url="http://127.0.0.1:8000",
        endpoints=[dummy_ep],
        context=ctx,
        prober=prober,
        max_steps=5,
        llm_engine=lambda prompt: "Reasoning step",
    )

    # Add hypothesis with non-BOLA/non-BFLA vector (e.g. MASS_ASSIGNMENT)
    hyp = AttackHypothesis(
        hypothesis_id="HYP-CUSTOM-01",
        vector=VulnerabilityCategory.BOPLA_MASS_ASSIGNMENT,
        endpoint=dummy_ep,
        description="Mass assignment probe",
        priority=5,
    )
    agent.hypotheses.append(hyp)

    # Executing run must complete without UnboundLocalError
    result = await agent.run()
    assert result["status"] == "COMPLETED"
    assert len(agent.events) > 0

