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
