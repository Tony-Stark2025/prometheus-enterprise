"""
Integration tests for Prometheus Bleeding-Edge Adversarial Engine.
Verifies dynamic tool dispatch, repetition guard, and trajectory logging.
"""

import pytest
import httpx

from prometheus.pentest.benchmark_app import app
from prometheus.pentest.engine import (
    PrometheusAdversarialEngine,
    RepetitionGuard,
    TrajectoryStore,
)
from prometheus.pentest.exploit_prober import ExploitProber
from prometheus.pentest.pr_ingestor import OpenAPIngestor
from prometheus.pentest.state_synthesizer import StateSynthesizer


def test_repetition_guard_detects_loops():
    guard = RepetitionGuard(max_identical_calls=2)

    # First call: allowed
    assert guard.record_and_check("probe_bola", {"path": "/invoices/1"}) is True

    # Second identical call: allowed
    assert guard.record_and_check("probe_bola", {"path": "/invoices/1"}) is True

    # Third identical call: TRIPPED (Loop prevented!)
    assert guard.record_and_check("probe_bola", {"path": "/invoices/1"}) is False

    # Different call: allowed
    assert guard.record_and_check("probe_bola", {"path": "/invoices/2"}) is True


def test_trajectory_store_records_and_sanitizes():
    store = TrajectoryStore()
    store.record(
        step=1,
        event_type="auth_created",
        payload={"user_id": "usr_1", "jwt_token": "secret_ey_token", "role": "admin"},
    )

    events = store.get_events()
    assert len(events) == 1
    assert events[0]["step"] == 1
    assert events[0]["event_type"] == "auth_created"
    assert "jwt_token" not in events[0]["payload"]  # Sanitized!
    assert events[0]["payload"]["user_id"] == "usr_1"


@pytest.mark.asyncio
async def test_adversarial_engine_end_to_end_execution():
    spec = app.openapi()
    endpoints = OpenAPIngestor.parse_spec(spec)

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

    engine = PrometheusAdversarialEngine(
        base_url="http://testserver",
        endpoints=endpoints,
        context=context,
        prober=prober,
        max_turns=10,
    )

    result = await engine.run()

    assert result["status"] == "COMPLETED"
    assert result["total_turns"] > 0
    assert len(result["vulnerabilities"]) >= 2
    assert len(result["patches"]) >= 1

    # Check trajectory ledger
    trajectory = result["trajectory"]
    event_names = [e["event_type"] for e in trajectory]
    assert "engine_initialized" in event_names
    assert "hypotheses_prioritized" in event_names
    assert "turn_action_dispatched" in event_names
    assert "verification_stop_gate_passed" in event_names
    assert "patch_certified" in event_names
    assert "engine_settled" in event_names
