"""
Unit tests for Red-Team Vulnerability Remediation (Sprint 3 / Phase 1 Reconciliation):
- SEC-05: TypeScript BOLA fail-closed check & BFLA route keyword targeting.
- SEC-06: Python AST module-level import injection (`from fastapi import Depends`).
- SEC-07: Dynamic JWT secret generation and environment variable precedence.
- SEC-08: Secure default loopback detection in ExploitProber.
- SRE-02: Non-blocking async SSRF validation (async_validate_ssrf).
- SRE-04: Tarjan's Strongly Connected Components (SCC) for cyclic route dependencies.
- SRE-05: Bounded TrajectoryStore deque & O(1) OrderedDict LRU TelemetryCache.
"""

import asyncio
import ast
import os
import pytest
import jwt

from prometheus.pentest.ast_patcher import (
    ASTPatchSynthesizer,
    TypeScriptPatchSynthesizer,
    AuthorizationPatchTransformer,
)
from prometheus.pentest.models import (
    ExploitProof,
    HttpMethod,
    Severity,
    VulnerabilityCategory,
)
from prometheus.pentest.state_synthesizer import StateSynthesizer
from prometheus.pentest.exploit_prober import ExploitProber, async_validate_ssrf, SSRFValidationError
from prometheus.pentest.route_graph import OpenAPIRouteGraph, RouteOperation
from prometheus.pentest.engine import TrajectoryStore
from prometheus.llm.provider_manager import TelemetryCache


def test_sec_05_ts_bola_fails_closed_on_undefined_user():
    code = """
router.get("/api/v1/invoices/:id", async (req, res) => {
    const invoice = await getInvoice(req.params.id);
    if (!invoice) {
        return res.status(404).json({ error: "Not found" });
    }
    return res.json(invoice);
});
"""
    proof = ExploitProof(
        target_endpoint="/api/v1/invoices/inv-123",
        http_method=HttpMethod.GET,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.CRITICAL,
        is_vulnerable=True,
        evidence_payload={},
        http_status_code=200,
        curl_command="curl ...",
        remediation_guidance="...",
        execution_time_ms=5.0,
    )
    patched, modified = TypeScriptPatchSynthesizer.synthesize_bola_patch(code, proof, "invoices.ts")
    assert modified is True
    # Verify fail-closed check for missing/undefined user tenant
    assert "!(req.user?.tenantId || req.user?.tenant_id)" in patched


def test_sec_05_ts_bfla_targets_exact_route_keyword():
    code = """
router.post("/public/login", async (req, res) => {
    return res.json({ token: "xyz" });
});

router.delete("/api/v1/workspaces/:id", async (req, res) => {
    await deleteWorkspace(req.params.id);
    return res.status(204).send();
});
"""
    proof = ExploitProof(
        target_endpoint="/api/v1/workspaces/ws-001",
        http_method=HttpMethod.DELETE,
        vector=VulnerabilityCategory.BFLA,
        severity=Severity.HIGH,
        is_vulnerable=True,
        evidence_payload={},
        http_status_code=200,
        curl_command="curl ...",
        remediation_guidance="...",
        execution_time_ms=5.0,
    )
    patched, modified = TypeScriptPatchSynthesizer.synthesize_bfla_patch(code, proof, "workspaces.ts")
    assert modified is True
    # Admin guard must be injected into the delete workspace route, NOT the login route
    assert "router.post(\"/public/login\"" in patched
    assert "if (req.user?.role !== 'admin')" in patched
    login_section = patched.split("router.delete")[0]
    assert "Admin role required" not in login_section
    delete_section = patched.split("router.delete")[1]
    assert "Admin role required" in delete_section


def test_sec_06_python_ast_injects_missing_fastapi_depends():
    code = """
@app.get("/api/v1/items/{item_id}")
def get_item(item_id: str, db: Session = None):
    return db.query(Item).filter(Item.id == item_id).first()
"""
    tree = ast.parse(code)
    transformer = AuthorizationPatchTransformer()
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)
    unparsed = ast.unparse(new_tree)

    assert "from fastapi import Depends" in unparsed
    assert "Depends(get_current_user)" in unparsed


def test_sec_07_state_synthesizer_dynamic_jwt_secret():
    # When dynamic_secret=True is passed, StateSynthesizer must dynamically generate a secure random secret
    s1 = StateSynthesizer(dynamic_secret=True)
    s2 = StateSynthesizer(dynamic_secret=True)
    assert s1.jwt_secret != ""
    assert len(s1.jwt_secret) >= 32
    # Two distinct instances should have unique secrets
    assert s1.jwt_secret != s2.jwt_secret

    token = s1.mint_token(user_id="u1", tenant_id="t1", email="u1@example.com")
    decoded = jwt.decode(token, s1.jwt_secret, algorithms=["HS256"])
    assert decoded["user_id"] == "u1"

    # Environment variable PROMETHEUS_JWT_SECRET override
    os.environ["PROMETHEUS_JWT_SECRET"] = "custom-env-secret-key-at-least-32-chars-long!"
    try:
        s_env = StateSynthesizer()
        assert s_env.jwt_secret == "custom-env-secret-key-at-least-32-chars-long!"
    finally:
        os.environ.pop("PROMETHEUS_JWT_SECRET", None)


def test_sec_08_exploit_prober_auto_detects_loopback():
    # External URL auto-detects allow_loopback = False
    p_ext = ExploitProber(base_url="https://httpbin.org")
    assert p_ext.allow_loopback is False

    # Local development URLs auto-detect allow_loopback = True
    p_local1 = ExploitProber(base_url="http://127.0.0.1:8000")
    assert p_local1.allow_loopback is True

    p_local2 = ExploitProber(base_url="http://localhost:3000")
    assert p_local2.allow_loopback is True

    p_local3 = ExploitProber(base_url="http://testserver")
    assert p_local3.allow_loopback is True


@pytest.mark.asyncio
async def test_sre_02_async_validate_ssrf():
    # Should complete without error for allowed loopback
    await async_validate_ssrf("http://127.0.0.1:8000/api", allow_loopback=True)

    # Should raise for loopback in strict mode
    with pytest.raises(SSRFValidationError):
        await async_validate_ssrf("http://127.0.0.1:8000/api", allow_loopback=False)


def test_sre_04_route_graph_tarjan_scc_cyclic_tiers():
    graph = OpenAPIRouteGraph()
    # Create cyclic dependency: op_a -> op_b -> op_a
    op_a = RouteOperation(
        op_id="op_a",
        method=HttpMethod.POST,
        path="/workspaces/{id}/child",
        summary="Create child",
    )
    op_b = RouteOperation(
        op_id="op_b",
        method=HttpMethod.POST,
        path="/workspaces/{id}/parent",
        summary="Create parent",
    )
    graph.operations["op_a"] = op_a
    graph.operations["op_b"] = op_b
    graph.adj_list["op_a"] = {"op_b"}
    graph.adj_list["op_b"] = {"op_a"}
    graph.in_degree["op_a"] = 1
    graph.in_degree["op_b"] = 1

    tiers = graph.get_execution_tiers()
    # Both operations must be scheduled deterministically in tiers without deadlock or dropping
    all_scheduled = [op.op_id for tier in tiers for op in tier]
    assert "op_a" in all_scheduled
    assert "op_b" in all_scheduled
    assert len(all_scheduled) == 2


def test_sre_05_bounded_trajectory_store():
    store = TrajectoryStore(maxlen=50)
    for i in range(120):
        store.record(step=i, event_type="probe", payload={"id": i})

    events = store.get_events()
    assert len(events) == 50
    # Oldest events (0..69) were evicted; latest event is 119
    assert events[-1]["step"] == 119
    assert events[0]["step"] == 70


def test_sre_05_telemetry_cache_lru_eviction():
    cache = TelemetryCache(ttl_seconds=3600, maxsize=2)
    cache.set("k1", "data_1")
    cache.set("k2", "data_2")

    # Access k1 so k2 becomes least recently used
    assert cache.get("k1") == "data_1"

    # Insert k3, which should evict k2 in O(1)
    cache.set("k3", "data_3")

    assert cache.get("k1") == "data_1"
    assert cache.get("k2") is None
    assert cache.get("k3") == "data_3"
