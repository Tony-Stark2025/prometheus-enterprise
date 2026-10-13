"""
Integration tests for Prometheus Capability Hypervisor Proxy Lifecycle.
Verifies end-to-end enforcement:
a) Interception of out-of-order tool calls and structured denial envelope emission.
b) Successful mutation admission when accompanied by valid pre-state witness and action permit.
c) Attenuated token privilege confinement (preventing cross-resource escalation).
d) State drift fail-closed enforcement and real MCP server integration.
"""

import pytest
import asyncio
from typing import Any, Dict

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
    StateWitnessRegistry,
)
from prometheus.proxy.hypervisor import ToolExecutionHypervisor
from prometheus.mcp.server import PrometheusMCPServer
from prometheus.memory.state_store import state_store, ActionDraftRecord, DraftStatus


@pytest.fixture
def token_authority():
    return TokenAuthority(secret_key="integration-test-secret-vault-key-2026")


@pytest.fixture
def mock_backend():
    """Stateful simulated REST backend service."""
    db: Dict[str, Dict[str, Any]] = {
        "inv-001": {"id": "inv-001", "amount": 5000, "status": "draft", "version": 1},
        "inv-002": {"id": "inv-002", "amount": 12000, "status": "approved", "version": 1},
    }

    async def http_handler(method: str, path: str, body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        parts = path.strip("/").split("/")
        res_id = parts[-1] if len(parts) >= 4 else None

        if method == "GET":
            if res_id in db:
                return dict(db[res_id])
            raise KeyError(f"Resource {res_id} not found")

        elif method in ("PUT", "PATCH"):
            if res_id not in db:
                raise KeyError(f"Resource {res_id} not found")
            db[res_id].update(body)
            db[res_id]["version"] += 1
            return dict(db[res_id])

        elif method == "DELETE":
            if res_id in db:
                deleted = db.pop(res_id)
                return {"deleted": True, "resource": deleted}
            raise KeyError(f"Resource {res_id} not found")

        elif method == "POST":
            new_id = body.get("id", f"inv-new-{len(db)+1}")
            db[new_id] = body
            return dict(db[new_id])

        return {"status": "ok"}

    return db, http_handler


class TestHypervisorProxyLifecycle:
    """Verifies complete end-to-end lifecycle of the capability hypervisor."""

    @pytest.mark.asyncio
    async def test_lifecycle_out_of_order_interception_and_denial(self, token_authority, mock_backend):
        """
        Req 2a: Interception of out-of-order tool calls and structured denial envelope emission.
        """
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )
        # Register backend resource in hypervisor registry
        hypervisor.registry.register_state("inv-001", db["inv-001"])

        # Agent possesses a valid token for inv-001
        token = token_authority.mint_token(
            subject="autonomous-agent-42",
            allowed_methods=["GET", "PUT", "DELETE"],
            allowed_resource_ids=["inv-001"],
            ttl_seconds=60,
        )

        # Agent attempts to PUT (mutate) inv-001 WITHOUT a prior read
        resp = await hypervisor.handle_http_request(
            method="PUT",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            body={"status": "paid"},
            token=token,
            session_id="trace-session-101",
        )

        assert not resp.success
        assert resp.status_code == 403
        assert resp.denial is not None
        assert resp.denial.denial_code == DenialCode.CAUSAL_LINEAGE_VIOLATION
        assert "Mutation requires prior read" in resp.denial.violated_invariant
        assert len(resp.denial.permitted_alternate_paths) > 0
        assert "GET /api/v1/invoices/inv-001" in resp.denial.permitted_alternate_paths[0]
        assert resp.denial.suggested_recovery_step.startswith("Execute an inspection read")

    @pytest.mark.asyncio
    async def test_lifecycle_successful_mutation_with_witness_and_permit(self, token_authority, mock_backend):
        """
        Req 2b: Successful mutation admission when accompanied by valid pre-state witness and action permit.
        """
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )
        hypervisor.registry.register_state("inv-001", db["inv-001"])

        token = token_authority.mint_token(
            subject="autonomous-agent-42",
            allowed_methods=["GET", "PUT", "DELETE"],
            allowed_resource_ids=["inv-001"],
            ttl_seconds=60,
        )

        session_id = "trace-session-happy-path"

        # Step 1: Execute authorized read
        read_resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            token=token,
            session_id=session_id,
        )
        assert read_resp.success
        assert read_resp.status_code == 200
        assert read_resp.pre_state_witness is not None
        witness = read_resp.pre_state_witness
        assert witness.resource_id == "inv-001"
        assert token_authority.verify_pre_state_witness(witness)

        # Step 2: Mint Action Permit bound to the witness
        action_permit = token_authority.mint_action_permit(
            token=token,
            action_method="PUT",
            resource_id="inv-001",
            witness=witness,
        )

        # Step 3: Execute mutation bundled with valid Action Permit
        mutate_resp = await hypervisor.handle_http_request(
            method="PUT",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            body={"status": "paid"},
            token=token,
            permit=action_permit,
            session_id=session_id,
        )

        assert mutate_resp.success
        assert mutate_resp.status_code == 200
        assert mutate_resp.denial is None
        assert mutate_resp.result["status"] == "paid"
        assert mutate_resp.result["version"] == 2
        # Verify state in hypervisor registry updated
        assert hypervisor.registry.get_state("inv-001")["status"] == "paid"

    @pytest.mark.asyncio
    async def test_lifecycle_attenuated_privilege_confinement(self, token_authority, mock_backend):
        """
        Req 2c: Attenuated token privilege confinement (preventing cross-resource escalation).
        """
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )
        hypervisor.registry.register_state("inv-001", db["inv-001"])
        hypervisor.registry.register_state("inv-002", db["inv-002"])

        # Service / Supervisor Root Token with access to multiple resources
        root_token = token_authority.mint_token(
            subject="supervisor-agent",
            allowed_methods=["GET", "PUT"],
            allowed_resource_ids=["inv-001", "inv-002"],
            ttl_seconds=60,
        )

        # Monotonically attenuate token for worker subagent: confined ONLY to inv-001
        subagent_token = token_authority.attenuate_token(
            parent_token=root_token,
            restricted_methods=["GET", "PUT"],
            restricted_resources=["inv-001"],
            ttl_seconds=30,
        )

        # Subagent tries to inspect inv-002
        cross_resource_resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/invoices/inv-002",
            resource_id="inv-002",
            token=subagent_token,
            session_id="subagent-trace-1",
        )

        # Must fail closed at hypervisor gateway: cross-resource access denied
        assert not cross_resource_resp.success
        assert cross_resource_resp.status_code == 403
        assert cross_resource_resp.denial.denial_code == DenialCode.UNAUTHORIZED_RESOURCE_SCOPE
        assert "inv-002" in cross_resource_resp.denial.violated_invariant

    @pytest.mark.asyncio
    async def test_lifecycle_state_drift_fails_closed(self, token_authority, mock_backend):
        """
        Verifies fail-closed behavior on concurrent state drift (TOCTOU prevention).
        """
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )
        hypervisor.registry.register_state("inv-001", db["inv-001"])

        token = token_authority.mint_token(
            subject="autonomous-agent-drift-test",
            allowed_methods=["GET", "PUT"],
            allowed_resource_ids=["inv-001"],
            ttl_seconds=60,
        )
        session_id = "drift-session"

        # Read state and get witness
        read_resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            token=token,
            session_id=session_id,
        )
        witness = read_resp.pre_state_witness
        permit = token_authority.mint_action_permit(token, "PUT", "inv-001", witness)

        # Simulate concurrent external mutation drifting live state
        hypervisor.registry.update_state("inv-001", {"id": "inv-001", "amount": 9999, "status": "tampered", "version": 5})

        # Agent attempts mutation using stale permit
        mutate_resp = await hypervisor.handle_http_request(
            method="PUT",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            body={"status": "paid"},
            token=token,
            permit=permit,
            session_id=session_id,
        )

        assert not mutate_resp.success
        assert mutate_resp.status_code == 403
        assert mutate_resp.denial.denial_code == DenialCode.PRESTATE_HASH_MISMATCH
        assert "drift" in mutate_resp.denial.details.lower()

    @pytest.mark.asyncio
    async def test_mcp_server_real_integration(self, token_authority):
        """
        Verifies integration with PrometheusMCPServer over JSON-RPC 2.0.
        """
        # Create real action draft in state store
        draft_id = "draft-hypervisor-test-99"
        record = ActionDraftRecord(
            draft_id=draft_id,
            target_channel_or_user="#sec-ops",
            action_type="slack_channel_alert",
            content="Emergency hotfix ready",
            status=DraftStatus.PENDING,
        )
        await state_store.save_draft(record)

        mcp_server = PrometheusMCPServer()
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            mcp_handler=mcp_server.handle_jsonrpc,
        )
        # Register draft in hypervisor registry
        hypervisor.registry.register_state(draft_id, {"draft_id": draft_id, "status": DraftStatus.PENDING.value})

        token = token_authority.mint_token(
            subject="mcp-lead-user",
            allowed_methods=["tools/call", "list_pending_actions", "approve_action"],
            allowed_resource_ids=["*", draft_id],
            ttl_seconds=60,
        )

        session_id = "mcp-session-test"

        # 1. Inspect drafts via MCP list_pending_actions (read tool)
        list_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_pending_actions", "arguments": {}},
        }
        list_resp = await hypervisor.handle_mcp_jsonrpc(
            request_dict=list_req,
            token=token,
            session_id=session_id,
        )
        assert "result" in list_resp
        assert list_resp["id"] == 1

        # Read draft to establish lineage for draft_id
        read_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "list_pending_actions", "arguments": {"resource_id": draft_id}},
        }
        read_resp = await hypervisor.handle_mcp_jsonrpc(
            request_dict=read_req,
            token=token,
            session_id=session_id,
        )
        assert "result" in read_resp

        # Retrieve witness from registry and issue permit
        witness = hypervisor.registry.get_witness(draft_id)
        assert witness is not None
        permit = token_authority.mint_action_permit(token, "approve_action", draft_id, witness)

        # 2. Mutate draft via MCP approve_action with valid permit
        approve_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "approve_action",
                "arguments": {
                    "draft_id": draft_id,
                    "approver": "lead-approver",
                },
            },
        }
        approve_resp = await hypervisor.handle_mcp_jsonrpc(
            request_dict=approve_req,
            token=token,
            permit=permit,
            session_id=session_id,
        )
        assert "result" in approve_resp
        assert approve_resp["id"] == 3

    @pytest.mark.asyncio
    async def test_lifecycle_collection_post_entity_creation(self, token_authority, mock_backend):
        """Verifies creating an entity via POST registers it in hypervisor registry and lineage."""
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )

        token = token_authority.mint_token(
            subject="agent-creator",
            allowed_methods=["POST", "PUT", "GET"],
            allowed_resource_ids=["*"],
            ttl_seconds=60,
        )
        session_id = "post-creation-session"

        # 1. Create a new invoice via POST /api/v1/invoices
        create_resp = await hypervisor.handle_http_request(
            method="POST",
            path="/api/v1/invoices",
            body={"id": "inv-new-99", "amount": 7500, "status": "draft", "version": 1},
            token=token,
            session_id=session_id,
        )
        assert create_resp.success
        assert create_resp.status_code == 200

        # Verify entity exists in hypervisor registry and lineage tracker
        assert hypervisor.registry.has_resource("inv-new-99")
        assert hypervisor.gate.lineage_tracker.has_read_witness(session_id, "inv-new-99")

        # 2. Mutate the newly created entity with ActionPermit
        witness = hypervisor.registry.get_witness("inv-new-99")
        assert witness is not None
        permit = token_authority.mint_action_permit(token, "PUT", "inv-new-99", witness)

        mutate_resp = await hypervisor.handle_http_request(
            method="PUT",
            path="/api/v1/invoices/inv-new-99",
            resource_id="inv-new-99",
            body={"status": "submitted"},
            token=token,
            permit=permit,
            session_id=session_id,
        )
        assert mutate_resp.success
        assert mutate_resp.status_code == 200
        assert mutate_resp.result["status"] == "submitted"

    @pytest.mark.asyncio
    async def test_lifecycle_collection_discovery_auto_witnesses_entities(self, token_authority, mock_backend):
        """Verifies querying collection auto-registers witnesses for discovered items."""
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )
        # Seed backend
        hypervisor.registry.register_state("inv-001", db["inv-001"])
        hypervisor.registry.register_state("inv-002", db["inv-002"])

        token = token_authority.mint_token(
            subject="agent-discoverer",
            allowed_methods=["GET", "PUT"],
            allowed_resource_ids=["*"],
            ttl_seconds=60,
        )
        session_id = "discovery-session"

        # Custom handler simulating collection listing
        async def collection_http_handler(method: str, path: str, body: Dict[str, Any], headers: Dict[str, str]):
            if method == "GET" and path == "/api/v1/invoices":
                return {"items": [dict(db["inv-001"]), dict(db["inv-002"])]}
            return await http_handler(method, path, body, headers)

        hypervisor.http_handler = collection_http_handler

        # 1. Execute collection query GET /api/v1/invoices
        list_resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/invoices",
            token=token,
            session_id=session_id,
        )
        assert list_resp.success

        # Both entities must now be witnessed in the lineage tracker
        assert hypervisor.gate.lineage_tracker.has_read_witness(session_id, "inv-001")
        assert hypervisor.gate.lineage_tracker.has_read_witness(session_id, "inv-002")

        # 2. Immediately mint permit on inv-001 and mutate without extra individual read
        witness = hypervisor.gate.lineage_tracker.get_witness(session_id, "inv-001")
        assert witness is not None
        permit = token_authority.mint_action_permit(token, "PUT", "inv-001", witness)

        mutate_resp = await hypervisor.handle_http_request(
            method="PUT",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            body={"status": "processed"},
            token=token,
            permit=permit,
            session_id=session_id,
        )
        assert mutate_resp.success
        assert mutate_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_lifecycle_entity_deletion_removes_from_registry(self, token_authority, mock_backend):
        """Verifies DELETE mutation removes entity from registry and subsequent mutations fail closed."""
        db, http_handler = mock_backend
        hypervisor = ToolExecutionHypervisor(
            token_authority=token_authority,
            http_handler=http_handler,
        )
        hypervisor.registry.register_state("inv-001", db["inv-001"])

        token = token_authority.mint_token(
            subject="agent-cleaner",
            allowed_methods=["GET", "DELETE", "PUT"],
            allowed_resource_ids=["inv-001"],
            ttl_seconds=60,
        )
        session_id = "deletion-session"

        # 1. Read inv-001
        read_resp = await hypervisor.handle_http_request(
            method="GET",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            token=token,
            session_id=session_id,
        )
        assert read_resp.success
        witness = read_resp.pre_state_witness

        # 2. Mint permit for DELETE
        permit = token_authority.mint_action_permit(token, "DELETE", "inv-001", witness)

        del_resp = await hypervisor.handle_http_request(
            method="DELETE",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            token=token,
            permit=permit,
            session_id=session_id,
        )
        assert del_resp.success
        assert del_resp.status_code == 200

        # Entity must be purged from hypervisor registry
        assert not hypervisor.registry.has_resource("inv-001")

        # 3. Subsequent mutation on deleted entity must fail closed as hallucinated
        stale_permit = token_authority.mint_action_permit(token, "PUT", "inv-001", witness)
        subsequent_resp = await hypervisor.handle_http_request(
            method="PUT",
            path="/api/v1/invoices/inv-001",
            resource_id="inv-001",
            body={"status": "revived"},
            token=token,
            permit=stale_permit,
            session_id=session_id,
        )
        assert not subsequent_resp.success
        assert subsequent_resp.status_code == 403
        assert subsequent_resp.denial.denial_code == DenialCode.HALLUCINATED_RESOURCE_ID

