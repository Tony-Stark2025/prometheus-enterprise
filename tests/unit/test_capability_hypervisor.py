"""
Unit tests for Prometheus Capability Hypervisor and Stateful Execution Firewall.
Verifies monotonic capability attenuation, causal dependency gates, pre-state
witness hashing H(S), action permits, and structured semantic denial envelopes.
"""

import time
import pytest
from unittest.mock import AsyncMock

from prometheus.proxy.models import (
    DenialCode,
    ProxyToolRequest,
    ToolCallType,
)
from prometheus.proxy.token_authority import (
    AttenuationViolationError,
    TokenAuthority,
)
from prometheus.proxy.state_invariants import (
    CausalLineageTracker,
    StateInvariantGate,
    StateWitnessRegistry,
)
from prometheus.proxy.hypervisor import ToolExecutionHypervisor
from prometheus.pentest.models import HttpMethod, RouteEndpoint
from prometheus.pentest.route_graph import OpenAPIRouteGraph


@pytest.fixture
def token_authority():
    return TokenAuthority(secret_key="test-secret-hypervisor-key-2026")


@pytest.fixture
def root_token(token_authority):
    return token_authority.mint_token(
        subject="agent-alpha",
        allowed_methods=["GET", "POST", "PUT", "DELETE", "approve_action", "list_pending_actions"],
        allowed_resource_ids=["res-101", "res-102"],
        ttl_seconds=60,
        tenant_id="tenant-corp",
    )


class TestTokenAuthorityAndAttenuation:
    """Verifies monotonic capability attenuation and cryptographic boundaries."""

    def test_mint_token_bounds_ttl_to_60s(self, token_authority):
        token = token_authority.mint_token(
            subject="agent-worker",
            allowed_methods=["GET"],
            allowed_resource_ids=["*"],
            ttl_seconds=120,  # Exceeds max
        )
        assert token.scope.max_ttl_seconds == 60
        assert token.scope.expires_at <= time.time() + 60.1
        assert token_authority.verify_token(token)

    def test_attenuate_token_valid_subset(self, token_authority, root_token):
        child = token_authority.attenuate_token(
            parent_token=root_token,
            restricted_methods=["GET", "POST"],
            restricted_resources=["res-101"],
            ttl_seconds=30,
        )
        assert child.parent_token_id == root_token.token_id
        assert child.scope.allowed_methods == ["GET", "POST"]
        assert child.scope.allowed_resource_ids == ["res-101"]
        assert child.scope.expires_at <= root_token.scope.expires_at
        assert token_authority.verify_token(child)

    def test_attenuate_token_forbids_method_widening(self, token_authority, root_token):
        with pytest.raises(AttenuationViolationError, match="Method escalation forbidden"):
            token_authority.attenuate_token(
                parent_token=root_token,
                restricted_methods=["GET", "UNAUTHORIZED_ADMIN_METHOD"],
            )

    def test_attenuate_token_forbids_resource_widening(self, token_authority, root_token):
        with pytest.raises(AttenuationViolationError, match="Resource escalation forbidden"):
            token_authority.attenuate_token(
                parent_token=root_token,
                restricted_resources=["res-101", "res-unauthorized-999"],
            )

    def test_attenuate_token_forbids_ttl_extension(self, token_authority, root_token):
        with pytest.raises(AttenuationViolationError, match="TTL extension forbidden"):
            token_authority.attenuate_token(
                parent_token=root_token,
                ttl_seconds=100,  # Exceeds root remaining
            )

    def test_verify_token_detects_tampering(self, token_authority, root_token):
        tampered_token = root_token.model_copy(deep=True)
        tampered_token.scope.allowed_resource_ids.append("res-hacked")
        assert not token_authority.verify_token(tampered_token)

    def test_expired_token_denial(self, token_authority):
        token = token_authority.mint_token(
            subject="agent-short",
            allowed_methods=["GET"],
            allowed_resource_ids=["*"],
            ttl_seconds=1,
        )
        # Validate with simulated future timestamp
        future_time = token.scope.expires_at + 10.0
        denial = token_authority.validate_action(token, "GET", "res-1", current_time=future_time)
        assert denial is not None
        assert denial.denial_code == DenialCode.EXPIRED_ACTION_TOKEN

    def test_unauthorized_method_denial(self, token_authority, root_token):
        denial = token_authority.validate_action(root_token, "PATCH", "res-101")
        assert denial is not None
        assert denial.denial_code == DenialCode.UNAUTHORIZED_METHOD_SCOPE

    def test_unauthorized_resource_denial(self, token_authority, root_token):
        denial = token_authority.validate_action(root_token, "GET", "res-999")
        assert denial is not None
        assert denial.denial_code == DenialCode.UNAUTHORIZED_RESOURCE_SCOPE


class TestPreStateWitnessAndActionPermit:
    """Verifies pre-state hashing H(S) and Action Permit validation."""

    def test_witness_canonical_hashing_and_verification(self, token_authority):
        state_data = {"status": "pending", "amount": 1000, "meta": {"owner": "alice"}}
        witness = token_authority.create_pre_state_witness(
            resource_id="res-101",
            state_data=state_data,
            source_op="GET /api/v1/resources/res-101",
        )
        assert witness.resource_id == "res-101"
        assert token_authority.verify_pre_state_witness(witness)

        # Confirm hash is deterministic
        expected_hash = token_authority.compute_state_hash(state_data)
        assert witness.state_hash == expected_hash

    def test_action_permit_minting_and_verification(self, token_authority, root_token):
        state_data = {"status": "pending"}
        witness = token_authority.create_pre_state_witness("res-101", state_data, "GET")
        permit = token_authority.mint_action_permit(root_token, "POST", "res-101", witness)

        assert permit.token_id == root_token.token_id
        assert permit.resource_id == "res-101"

        # Valid verification with identical live state
        current_hash = token_authority.compute_state_hash(state_data)
        denial = token_authority.verify_action_permit(permit, root_token, current_state_hash=current_hash)
        assert denial is None

    def test_action_permit_fails_closed_on_state_drift(self, token_authority, root_token):
        state_data = {"status": "pending"}
        witness = token_authority.create_pre_state_witness("res-101", state_data, "GET")
        permit = token_authority.mint_action_permit(root_token, "POST", "res-101", witness)

        # Drifted state
        drifted_hash = token_authority.compute_state_hash({"status": "already_approved"})
        denial = token_authority.verify_action_permit(permit, root_token, current_state_hash=drifted_hash)

        assert denial is not None
        assert denial.denial_code == DenialCode.PRESTATE_HASH_MISMATCH
        assert "drift" in denial.details.lower()
        assert denial.suggested_recovery_step.startswith("Re-inspect")

    def test_action_permit_method_mismatch_denied(self, token_authority, root_token):
        state_data = {"status": "pending"}
        witness = token_authority.create_pre_state_witness("res-101", state_data, "GET")
        permit = token_authority.mint_action_permit(root_token, "PUT", "res-101", witness)

        # Attempt to use PUT permit for DELETE
        denial = token_authority.verify_action_permit(
            permit=permit,
            token=root_token,
            expected_method="DELETE",
            expected_resource_id="res-101",
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.UNAUTHORIZED_METHOD_SCOPE
        assert "PermitMethodMismatch" in denial.violated_invariant

    def test_action_permit_resource_mismatch_denied(self, token_authority, root_token):
        state_data = {"status": "pending"}
        witness = token_authority.create_pre_state_witness("res-101", state_data, "GET")
        permit = token_authority.mint_action_permit(root_token, "PUT", "res-101", witness)

        # Attempt to use res-101 permit on res-102
        denial = token_authority.verify_action_permit(
            permit=permit,
            token=root_token,
            expected_method="PUT",
            expected_resource_id="res-102",
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.UNAUTHORIZED_RESOURCE_SCOPE
        assert "PermitResourceMismatch" in denial.violated_invariant

    def test_action_permit_expired_denied(self, token_authority, root_token):
        state_data = {"status": "pending"}
        witness = token_authority.create_pre_state_witness("res-101", state_data, "GET")
        permit = token_authority.mint_action_permit(root_token, "PUT", "res-101", witness)

        # Verify with future time > 60s
        future_time = permit.created_at + 65.0
        denial = token_authority.verify_action_permit(
            permit=permit,
            token=root_token,
            expected_method="PUT",
            expected_resource_id="res-101",
            current_time=future_time,
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.EXPIRED_ACTION_TOKEN


class TestStateInvariantGate:
    """Verifies causal dependencies and out-of-order execution prevention."""

    def test_safe_read_passes_without_lineage(self, token_authority, root_token):
        registry = StateWitnessRegistry(token_authority)
        registry.register_state("res-101", {"status": "active"})
        gate = StateInvariantGate(token_authority, registry)

        denial = gate.verify_execution_gate(
            session_id="ses-1",
            method="GET",
            target="/api/v1/resources/res-101",
            resource_id="res-101",
            permit=None,
            token=root_token,
        )
        assert denial is None

    def test_mutation_on_hallucinated_resource_fails(self, token_authority, root_token):
        registry = StateWitnessRegistry(token_authority)
        registry.register_state("res-101", {"status": "active"})
        gate = StateInvariantGate(token_authority, registry)

        denial = gate.verify_execution_gate(
            session_id="ses-1",
            method="DELETE",
            target="/api/v1/resources/hallucinated-999",
            resource_id="hallucinated-999",
            permit=None,
            token=root_token,
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.HALLUCINATED_RESOURCE_ID

    def test_mutation_without_prior_read_fails_lineage(self, token_authority, root_token):
        registry = StateWitnessRegistry(token_authority)
        registry.register_state("res-101", {"status": "active"})
        gate = StateInvariantGate(token_authority, registry)

        # Attempting mutation without reading res-101 in ses-1
        denial = gate.verify_execution_gate(
            session_id="ses-1",
            method="PUT",
            target="/api/v1/resources/res-101",
            resource_id="res-101",
            permit=None,
            token=root_token,
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.CAUSAL_LINEAGE_VIOLATION
        assert "Mutation requires prior read" in denial.violated_invariant

    def test_mutation_with_prior_read_but_missing_permit(self, token_authority, root_token):
        registry = StateWitnessRegistry(token_authority)
        witness = registry.register_state("res-101", {"status": "active"})
        gate = StateInvariantGate(token_authority, registry)

        # Record prior read
        gate.lineage_tracker.record_read("ses-1", "res-101", witness, "GET /api/v1/resources/res-101")

        # Mutate without permit
        denial = gate.verify_execution_gate(
            session_id="ses-1",
            method="PUT",
            target="/api/v1/resources/res-101",
            resource_id="res-101",
            permit=None,
            token=root_token,
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.MISSING_ACTION_PERMIT

    def test_action_permit_replay_prevented(self, token_authority, root_token):
        registry = StateWitnessRegistry(token_authority)
        witness = registry.register_state("res-101", {"status": "active"})
        gate = StateInvariantGate(token_authority, registry)
        gate.lineage_tracker.record_read("ses-1", "res-101", witness, "GET")

        permit = token_authority.mint_action_permit(root_token, "PUT", "res-101", witness)

        # First use should pass gate
        first_denial = gate.verify_execution_gate(
            session_id="ses-1",
            method="PUT",
            target="/api/v1/resources/res-101",
            resource_id="res-101",
            permit=permit,
            token=root_token,
        )
        assert first_denial is None

        # Simulate execution completion consuming permit
        gate.mark_permit_consumed(permit.permit_id)

        # Second use (replay attempt) must fail closed
        replay_denial = gate.verify_execution_gate(
            session_id="ses-1",
            method="PUT",
            target="/api/v1/resources/res-101",
            resource_id="res-101",
            permit=permit,
            token=root_token,
        )
        assert replay_denial is not None
        assert replay_denial.denial_code == DenialCode.PERMIT_TAMPERED
        assert "PermitAlreadyConsumed" in replay_denial.violated_invariant

    def test_integration_with_openapi_route_graph(self, token_authority):
        endpoints = [
            RouteEndpoint(path="/api/v1/workspaces", method=HttpMethod.POST),
            RouteEndpoint(path="/api/v1/workspaces/{workspace_id}/projects", method=HttpMethod.POST, path_parameters=["workspace_id"]),
        ]
        route_graph = OpenAPIRouteGraph.from_endpoints(endpoints)
        tiers = route_graph.get_execution_tiers()
        assert len(tiers) == 2

        gate = StateInvariantGate(token_authority, route_graph=route_graph)
        assert gate.route_graph is not None

        token = token_authority.mint_token(
            subject="agent-test",
            allowed_methods=["POST"],
            allowed_resource_ids=["*"],
            ttl_seconds=60,
        )

        # Attempt to call Tier-1 endpoint without prior execution of Tier-0 prerequisite
        denial = gate.verify_execution_gate(
            session_id="ses-graph-1",
            method="POST",
            target="/api/v1/workspaces/ws-99/projects",
            resource_id=None,
            permit=None,
            token=token,
        )
        assert denial is not None
        assert denial.denial_code == DenialCode.CAUSAL_LINEAGE_VIOLATION
        assert "POST /api/v1/workspaces" in denial.permitted_alternate_paths

        # Fulfill prerequisite in lineage history
        gate.lineage_tracker.record_read("ses-graph-1", "ws-99", None, "POST /api/v1/workspaces")

        # Now route prerequisite check succeeds
        assert gate._check_route_graph_prerequisites("ses-graph-1", "POST", "/api/v1/workspaces/ws-99/projects") is None


class TestToolExecutionHypervisorProxy:
    """Verifies proxy interception for MCP and HTTP tool calls."""

    def test_extract_resource_id_from_path_robustness(self):
        # Collections and system endpoints should return None
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/invoices") is None
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/workspaces") is None
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/health") is None
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/analytics") is None
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/settings") is None

        # Resource endpoints with IDs should return exact identifiers
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/invoices/inv-001") == "inv-001"
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/orders/12345") == "12345"
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/items/item-123?filter=active") == "item-123"
        assert ToolExecutionHypervisor.extract_resource_id_from_path("/api/v1/users/550e8400-e29b-41d4-a716-446655440000") == "550e8400-e29b-41d4-a716-446655440000"

    @pytest.mark.asyncio
    async def test_dict_token_resolution_and_lowercase_headers(self, token_authority):
        token = token_authority.mint_token(
            subject="agent-dict",
            allowed_methods=["GET"],
            allowed_resource_ids=["res-101"],
            ttl_seconds=60,
        )
        token_dict = token.model_dump(mode="json")

        hypervisor = ToolExecutionHypervisor(token_authority=token_authority)
        hypervisor.registry.register_state("res-101", {"id": "res-101"})

        # Pass token as dictionary
        resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/resources/res-101",
            token=token_dict,
        )
        assert resp.success
        assert resp.status_code == 200

        # Pass token via lowercase authorization header
        resp2 = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/resources/res-101",
            headers={"authorization": f"Bearer {token.model_dump_json()}"},
        )
        assert resp2.success
        assert resp2.status_code == 200

    @pytest.mark.asyncio
    async def test_intercept_http_rejects_missing_token(self, token_authority):
        hypervisor = ToolExecutionHypervisor(token_authority=token_authority)
        resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/resources/res-101",
            token=None,
        )
        assert not resp.success
        assert resp.status_code == 403
        assert resp.denial.denial_code == DenialCode.MISSING_ACTION_TOKEN

    @pytest.mark.asyncio
    async def test_intercept_mcp_out_of_order_denial_envelope(self, token_authority):
        hypervisor = ToolExecutionHypervisor(token_authority=token_authority)
        # Register real draft in registry so it's not considered hallucinated
        hypervisor.registry.register_state("draft-123", {"status": "pending"})

        # Mint token permitted for approve_action on draft-123
        token = token_authority.mint_token(
            subject="agent-lead",
            allowed_methods=["approve_action"],
            allowed_resource_ids=["draft-123"],
            ttl_seconds=60,
        )

        # Try to approve draft without prior read/inspection
        mcp_req = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "approve_action",
                "arguments": {
                    "draft_id": "draft-123",
                    "approver": "alex-lead",
                },
            },
        }

        resp = await hypervisor.handle_mcp_jsonrpc(
            request_dict=mcp_req,
            token=token,
            session_id="ses-agent",
        )
        assert "error" in resp
        assert resp["error"]["code"] == -32003
        error_data = resp["error"]["data"]
        assert error_data["denial_code"] == DenialCode.CAUSAL_LINEAGE_VIOLATION.value
        assert "suggested_recovery_step" in error_data
        assert len(error_data["permitted_alternate_paths"]) > 0
