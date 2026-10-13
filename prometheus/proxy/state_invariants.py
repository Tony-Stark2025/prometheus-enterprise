"""
State Invariant & Lineage Gate.
Verifies tool invocation sequences against causal dependency graphs,
enforces read-before-write invariants, and verifies pre-state witness hashes H(S).
"""

import re
import threading
import time
from typing import Any, Dict, List, Optional, Set
import structlog

from prometheus.pentest.route_graph import OpenAPIRouteGraph
from prometheus.proxy.models import (
    ActionPermit,
    CapabilityToken,
    DenialCode,
    PreStateWitness,
    SemanticDenialEnvelope,
)
from prometheus.proxy.denial_envelope import DenialEnvelopeFactory
from prometheus.proxy.token_authority import TokenAuthority

logger = structlog.get_logger(__name__)


class StateWitnessRegistry:
    """
    Thread-safe registry of canonical live states and pre-state witness hashes.
    Simulates / integrates with the active backend persistence layer.
    """

    def __init__(self, token_authority: Optional[TokenAuthority] = None):
        self._lock = threading.RLock()
        self._states: Dict[str, Any] = {}
        self._witnesses: Dict[str, PreStateWitness] = {}
        self._consumed_permits: Set[str] = set()
        self._token_authority = token_authority or TokenAuthority()

    def mark_permit_consumed(self, permit_id: str) -> None:
        with self._lock:
            self._consumed_permits.add(permit_id)

    def is_permit_consumed(self, permit_id: str) -> bool:
        with self._lock:
            return permit_id in self._consumed_permits

    def register_state(self, resource_id: str, state_data: Any, source_op: str = "seed") -> PreStateWitness:
        with self._lock:
            self._states[resource_id] = state_data
            witness = self._token_authority.create_pre_state_witness(
                resource_id=resource_id,
                state_data=state_data,
                source_op=source_op,
            )
            self._witnesses[resource_id] = witness
            return witness

    def get_state(self, resource_id: str) -> Optional[Any]:
        with self._lock:
            return self._states.get(resource_id)

    def get_state_hash(self, resource_id: str) -> Optional[str]:
        with self._lock:
            if resource_id not in self._states:
                return None
            return self._token_authority.compute_state_hash(self._states[resource_id])

    def get_witness(self, resource_id: str) -> Optional[PreStateWitness]:
        with self._lock:
            return self._witnesses.get(resource_id)

    def update_state(self, resource_id: str, new_state_data: Any, source_op: str = "update") -> PreStateWitness:
        with self._lock:
            self._states[resource_id] = new_state_data
            witness = self._token_authority.create_pre_state_witness(
                resource_id=resource_id,
                state_data=new_state_data,
                source_op=source_op,
            )
            self._witnesses[resource_id] = witness
            return witness

    def delete_state(self, resource_id: str) -> None:
        with self._lock:
            self._states.pop(resource_id, None)
            self._witnesses.pop(resource_id, None)

    def has_resource(self, resource_id: str) -> bool:
        with self._lock:
            return resource_id in self._states

    def list_known_resources(self) -> List[str]:
        with self._lock:
            return list(self._states.keys())


class CausalLineageTracker:
    """
    Tracks causal lineages of read operations witnessed during an execution session.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # session_id -> {resource_id -> PreStateWitness}
        self._session_witnesses: Dict[str, Dict[str, PreStateWitness]] = {}
        # session_id -> list of executed op signatures e.g. ["GET /api/v1/items/1"]
        self._session_history: Dict[str, List[str]] = {}

    def record_read(self, session_id: str, resource_id: str, witness: PreStateWitness, op_name: str) -> None:
        with self._lock:
            if session_id not in self._session_witnesses:
                self._session_witnesses[session_id] = {}
                self._session_history[session_id] = []
            self._session_witnesses[session_id][resource_id] = witness
            self._session_history[session_id].append(op_name)

    def has_read_witness(self, session_id: str, resource_id: str) -> bool:
        with self._lock:
            return (
                session_id in self._session_witnesses
                and resource_id in self._session_witnesses[session_id]
            )

    def get_witness(self, session_id: str, resource_id: str) -> Optional[PreStateWitness]:
        with self._lock:
            return self._session_witnesses.get(session_id, {}).get(resource_id)

    def get_history(self, session_id: str) -> List[str]:
        with self._lock:
            return list(self._session_history.get(session_id, []))


class StateInvariantGate:
    """
    Gatekeeper that enforces causal invariants and pre-state witness alignment.
    Rejects unverified or out-of-order mutations before they reach backend tools.
    """

    MUTATING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    MUTATING_MCP_TOOLS = {
        "approve_action", "reject_action", "dispatch_action", "delete_draft",
        "transfer", "send", "revoke", "grant", "write", "set", "drop", "insert", "mutate"
    }
    MUTATING_TOOL_PREFIXES = (
        "create_", "update_", "delete_", "approve_", "reject_",
        "modify_", "apply_", "execute_", "remove_", "cancel_", "dispatch_", "patch_",
        "transfer_", "send_", "revoke_", "grant_", "write_", "set_", "drop_", "insert_", "mutate_"
    )

    @staticmethod
    def extract_resource_id_from_body_or_query(
        target: str, payload: Optional[Any] = None
    ) -> Optional[str]:
        """Extracts resource ID candidate from target query parameters or request body."""
        if "?" in target:
            from urllib.parse import parse_qs
            query_str = target.split("?", 1)[1]
            params = parse_qs(query_str)
            for k in ("resource_id", "id", "draft_id", "item_id", "target_id", "invoice_id", "workspace_id", "user_id"):
                if k in params and params[k]:
                    return str(params[k][0])
            for k, v in params.items():
                if k.endswith("_id") and v:
                    return str(v[0])
        if isinstance(payload, dict):
            for k in ("resource_id", "id", "draft_id", "item_id", "target_id", "invoice_id", "workspace_id", "user_id"):
                if k in payload and payload[k] is not None:
                    return str(payload[k])
            for k, v in payload.items():
                if k.endswith("_id") and isinstance(v, (str, int)):
                    return str(v)
        return None

    def __init__(
        self,
        token_authority: TokenAuthority,
        registry: Optional[StateWitnessRegistry] = None,
        route_graph: Optional[OpenAPIRouteGraph] = None,
    ):
        self.token_authority = token_authority
        self.registry = registry or StateWitnessRegistry(token_authority)
        self.lineage_tracker = CausalLineageTracker()
        self.route_graph = route_graph

    def is_mutation(self, method: str, target: str) -> bool:
        """Determines if the operation is a stateful mutation."""
        method_up = method.upper()
        if method_up in self.MUTATING_HTTP_METHODS:
            return True
        target_low = target.lower()
        if target_low in self.MUTATING_MCP_TOOLS or any(
            target_low.startswith(prefix) for prefix in self.MUTATING_TOOL_PREFIXES
        ):
            return True
        method_low = method.lower()
        if method_low in self.MUTATING_MCP_TOOLS or any(
            method_low.startswith(prefix) for prefix in self.MUTATING_TOOL_PREFIXES
        ):
            return True
        return False

    def mark_permit_consumed(self, permit_id: str) -> None:
        self.registry.mark_permit_consumed(permit_id)

    def is_permit_consumed(self, permit_id: str) -> bool:
        return self.registry.is_permit_consumed(permit_id)

    def _check_route_graph_prerequisites(
        self,
        session_id: str,
        method: str,
        target: str,
    ) -> Optional[SemanticDenialEnvelope]:
        if not self.route_graph:
            return None

        clean_target = target.split("?")[0]
        matching_op = None
        for op_id, op in self.route_graph.operations.items():
            if op.method.value.upper() != method.upper():
                continue
            pattern = "^" + re.sub(r"\{[a-zA-Z0-9_-]+\}", r"([^/]+)", op.path) + "$"
            if re.match(pattern, clean_target):
                matching_op = op
                break

        if not matching_op:
            return None

        prereq_op_ids: Set[str] = set()
        for src_id, dependents in self.route_graph.adj_list.items():
            if matching_op.op_id in dependents:
                prereq_op_ids.add(src_id)

        if not prereq_op_ids:
            return None

        history = self.lineage_tracker.get_history(session_id)
        missing_prereqs = []
        for prereq_id in prereq_op_ids:
            prereq_op = self.route_graph.operations.get(prereq_id)
            if not prereq_op:
                continue
            satisfied = any(
                prereq_op.path in h or f"{prereq_op.method.value} {prereq_op.path}" in h
                for h in history
            )
            if not satisfied:
                missing_prereqs.append(f"{prereq_op.method.value} {prereq_op.path}")

        if missing_prereqs:
            logger.warn(
                "hypervisor_route_graph_prerequisite_missing",
                session_id=session_id,
                target=target,
                missing=missing_prereqs,
            )
            return DenialEnvelopeFactory.causal_lineage_violation(
                resource_id=matching_op.op_id,
                target_op=f"{method} {target}",
                prerequisite_reads=missing_prereqs,
            )

        return None

    def verify_execution_gate(
        self,
        session_id: str,
        method: str,
        target: str,
        resource_id: Optional[str],
        permit: Optional[ActionPermit],
        token: CapabilityToken,
        payload: Optional[Any] = None,
    ) -> Optional[SemanticDenialEnvelope]:
        """
        Evaluates causal dependency, hallucination checks, and pre-state drift.
        Returns None if permitted, or a structured SemanticDenialEnvelope if denied.
        """
        # Resolve resource ID from query or payload if not passed explicitly
        if resource_id is None:
            resource_id = self.extract_resource_id_from_body_or_query(target, payload)

        # Safe read operations do not require prior lineage or permits
        if not self.is_mutation(method, target):
            return None

        # Replay prevention: One-time permits cannot be reused
        if permit is not None and self.is_permit_consumed(permit.permit_id):
            logger.warn("hypervisor_permit_replay_detected", permit_id=permit.permit_id)
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.PERMIT_TAMPERED,
                violated_invariant="PermitAlreadyConsumed: ActionPermit is single-use and has already been redeemed.",
                details=f"Permit '{permit.permit_id}' cannot be replayed for subsequent mutations.",
                permitted_alternate_paths=[f"inspect_{resource_id or permit.resource_id}"],
                suggested_recovery_step=f"Re-inspect resource '{resource_id or permit.resource_id}' to produce a fresh pre-state witness and request a new ActionPermit.",
                timestamp=time.time(),
            )

        # Route graph causal prerequisite verification
        route_denial = self._check_route_graph_prerequisites(session_id, method, target)
        if route_denial is not None:
            return route_denial

        # If operation targets a specific resource
        if resource_id is not None:
            # 1. Hallucination Gate: Check if resource actually exists in backend
            if not self.registry.has_resource(resource_id):
                known = self.registry.list_known_resources()
                logger.warn("hypervisor_hallucinated_resource", resource_id=resource_id, known_count=len(known))
                return DenialEnvelopeFactory.hallucinated_resource_id(
                    resource_id=resource_id,
                    valid_candidates=known[:5],
                )

            # 2. Causal Lineage Gate: Verify prior read / inspection occurred in this session
            if not self.lineage_tracker.has_read_witness(session_id, resource_id):
                logger.warn("hypervisor_lineage_violation", session_id=session_id, resource_id=resource_id, target=target)
                prereq_paths = [
                    f"GET {target.rsplit('/', 1)[0]}/{resource_id}" if "/" in target else f"inspect_{resource_id}",
                    "list_pending_actions" if "action" in target else "list_resources",
                ]
                return DenialEnvelopeFactory.causal_lineage_violation(
                    resource_id=resource_id,
                    target_op=f"{method} {target}",
                    prerequisite_reads=prereq_paths,
                )

            # 3. Action Permit Gate: Destructive mutations must bundle a valid permit
            if permit is None:
                logger.warn("hypervisor_missing_permit", resource_id=resource_id, method=method, target=target)
                return DenialEnvelopeFactory.missing_action_permit(
                    action_method=method,
                    resource_id=resource_id,
                )

            # 4. Pre-State Drift Verification: Ensure permit pre-state witness matches current state
            current_state_hash = self.registry.get_state_hash(resource_id)
            permit_denial = self.token_authority.verify_action_permit(
                permit=permit,
                token=token,
                current_state_hash=current_state_hash,
                expected_method=method,
                expected_resource_id=resource_id,
            )
            if permit_denial is not None:
                logger.warn("hypervisor_permit_verification_failed", denial=permit_denial.denial_code, resource_id=resource_id)
                return permit_denial

        return None
