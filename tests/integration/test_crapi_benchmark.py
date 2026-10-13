"""
Sprint 3 Enterprise External Benchmark Integration Test:
Validates autonomous API exploit prober and CEGIS dual-pass oracle against
realistic OWASP crAPI benchmark specification and live multi-tenant microservice.
"""

import json
import pytest
import httpx

from prometheus.pentest.engine import PrometheusAdversarialEngine
from prometheus.pentest.exploit_prober import ExploitProber
from prometheus.pentest.models import Severity, VulnerabilityCategory
from prometheus.pentest.pr_ingestor import OpenAPIngestor
from prometheus.pentest.pr_reporter import PRReporter
from prometheus.pentest.proof_validator import ProofValidator
from prometheus.pentest.state_synthesizer import StateSynthesizer
from tests.fixtures.crapi_benchmark_app import crapi_app, DEFAULT_JWT_SECRET


@pytest.mark.asyncio
async def test_crapi_benchmark_scan_and_dual_pass_neutralization():
    # 1. Ingest OpenAPI 3.0 specification for crAPI
    with open("tests/fixtures/crapi_openapi.json", "r", encoding="utf-8") as f:
        spec_dict = json.load(f)

    endpoints = OpenAPIngestor.parse_spec(spec_dict)
    assert len(endpoints) == 3

    # 2. Synthesize authentic multi-tenant cryptographic state
    synthesizer = StateSynthesizer(jwt_secret=DEFAULT_JWT_SECRET)
    synthesizer.register_seeded_resource(
        resource_type="vehicle",
        resource_id="veh-alpha-771",
        confidential_marker="CONFIDENTIAL_VEHICLE_GPS_COORDINATES_ALPHA_481",
    )
    synthesizer.register_seeded_resource(
        resource_type="order",
        resource_id="order-alpha-001",
        confidential_marker="CONFIDENTIAL_ORDER_ALPHA_001",
    )
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
        beta_role="member",
    )

    # 3. Setup Prober with in-memory ASGI transport targeting crAPI application
    transport = httpx.ASGITransport(app=crapi_app)
    validator = ProofValidator(redact_tokens=True)
    prober = ExploitProber(
        base_url="http://crapiserver",
        transport=transport,
        proof_validator=validator,
        allow_loopback=True,
    )

    # 4. Execute Autonomous Adversarial Reasoning Loop
    engine = PrometheusAdversarialEngine(
        base_url="http://crapiserver",
        endpoints=endpoints,
        context=context,
        prober=prober,
        max_turns=10,
    )

    results = await engine.run()

    # 5. Verify Benchmark Scan Results
    assert results["status"] == "COMPLETED"
    vulnerabilities = results["vulnerabilities"]
    patches = results["patches"]

    # Verify at least BOLA and BFLA vulnerabilities were detected and confirmed
    assert len(vulnerabilities) >= 2

    # Check BOLA detection on vehicle location
    bola_vuln = next((v for v in vulnerabilities if v.vector == VulnerabilityCategory.BOLA_IDOR), None)
    assert bola_vuln is not None
    assert bola_vuln.severity == Severity.CRITICAL
    assert bola_vuln.http_status_code == 200
    assert "CONFIDENTIAL_VEHICLE_GPS_COORDINATES_ALPHA_481" in str(bola_vuln.evidence_payload)

    # Check generated curl reproduction command
    assert "curl" in bola_vuln.curl_command
    assert "crapiserver" in bola_vuln.curl_command

    # Check token redaction in curl reproduction and PR report
    assert context.tenant_beta.jwt_token not in bola_vuln.curl_command
    assert "<AUTH_TOKEN_REDACTED>" in bola_vuln.curl_command

    pr_comment = PRReporter.format_github_pr_comment(bola_vuln)
    assert "🚨 Prometheus Security Gate: CRITICAL Exploit Verified" in pr_comment
    assert context.tenant_beta.jwt_token not in pr_comment

    # Check BFLA detection on mechanic orders
    bfla_vuln = next((v for v in vulnerabilities if v.vector == VulnerabilityCategory.BFLA), None)
    assert bfla_vuln is not None
    assert bfla_vuln.severity == Severity.HIGH

    # Verify trajectory events audit
    trajectory = results["trajectory"]
    events = [e["event_type"] for e in trajectory]
    assert "verification_stop_gate_passed" in events
    assert "engine_settled" in events

    await prober.aclose()
