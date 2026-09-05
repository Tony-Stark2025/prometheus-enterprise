import pytest
import tempfile
import os
from prometheus.security.abac_engine import ABACPolicyEngine, CLEARANCE_HIERARCHY


@pytest.fixture
def temp_abac_engine():
    engine = ABACPolicyEngine(db_path=":memory:")
    yield engine


def test_abac_admin_override(temp_abac_engine):
    """Admin users (L5) have system-wide access with full audit logging."""
    res = temp_abac_engine.evaluate_access("elena.lead", "PR-102")
    assert res.decision == "ALLOW"
    assert "Admin access granted" in res.reason
    assert res.clearance_met is True
    assert res.latency_ms >= 0

    # Admin access on restricted vault
    res_vault = temp_abac_engine.evaluate_access("elena.lead", "PROD-PAYMENT-VAULT")
    assert res_vault.decision == "ALLOW"


def test_abac_squad_and_clearance_match(temp_abac_engine):
    """Staff engineer with matching department, squad, and clearance is allowed."""
    res = temp_abac_engine.evaluate_access("david.kim", "PR-102")
    assert res.decision == "ALLOW"
    assert res.clearance_met is True
    assert res.department_matched is True
    assert res.squad_matched is True


def test_abac_clearance_denial(temp_abac_engine):
    """Senior engineer (L3) denied access to L4 security audit."""
    res = temp_abac_engine.evaluate_access("sarah.chen", "SEC-AUDIT-2026")
    assert res.decision == "DENY"
    assert "Insufficient clearance" in res.reason
    assert res.clearance_met is False


def test_abac_department_isolation_denial(temp_abac_engine):
    """Product manager denied access to engineering internal PR."""
    res = temp_abac_engine.evaluate_access("marcus.vance", "PR-102")
    assert res.decision == "DENY"
    assert "Department mismatch" in res.reason
    assert res.department_matched is False


def test_abac_restricted_vault_isolation(temp_abac_engine):
    """Non-admin user denied access to isolated restricted resource."""
    res = temp_abac_engine.evaluate_access("david.kim", "PROD-PAYMENT-VAULT")
    assert res.decision == "DENY"
    assert "RESTRICTED" in res.reason


def test_abac_unknown_identity_denial(temp_abac_engine):
    """Unregistered identity rejected with explicit audit reason."""
    res = temp_abac_engine.evaluate_access("unregistered_attacker", "PR-102")
    assert res.decision == "DENY"
    assert "not found in enterprise identity catalog" in res.reason


def test_abac_audit_log_fidelity(temp_abac_engine):
    """Evaluations produce immutable records in the audit log table."""
    temp_abac_engine.evaluate_access("elena.lead", "PR-102")
    temp_abac_engine.evaluate_access("sarah.chen", "SEC-AUDIT-2026")
    logs = temp_abac_engine.list_audit_logs(limit=10)
    assert len(logs) >= 2
    assert logs[0]["user_id"] in ("elena.lead", "sarah.chen")
    assert logs[0]["decision"] in ("ALLOW", "DENY")
    assert logs[0]["latency_ms"] >= 0

