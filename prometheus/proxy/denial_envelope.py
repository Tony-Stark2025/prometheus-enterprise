"""
Semantic Denial Envelope Generator.
Constructs rich, structured denial envelopes to prevent LLM denial cascade collapse
and steer autonomous agents into valid prerequisite exploration paths.
"""

from typing import List, Optional
import time

from prometheus.proxy.models import DenialCode, ScopeBoundary, SemanticDenialEnvelope


class DenialEnvelopeFactory:
    """Factory for standard semantic denial envelopes."""

    @staticmethod
    def missing_action_token(
        details: str = "Request lacked a cryptographically valid capability token.",
        permitted_paths: Optional[List[str]] = None,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.MISSING_ACTION_TOKEN,
            violated_invariant="AmbientAuthorityForbidden: Tool invocation requires an explicit scoped CapabilityToken.",
            details=details,
            permitted_alternate_paths=permitted_paths or ["request_capability_token"],
            suggested_recovery_step="Request an attenuated capability token from the Token Authority before invoking the tool.",
            timestamp=time.time(),
        )

    @staticmethod
    def expired_action_token(
        token_id: str,
        expires_at: float,
        scope: Optional[ScopeBoundary] = None,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.EXPIRED_ACTION_TOKEN,
            violated_invariant=f"TokenTTLExceeded: CapabilityToken '{token_id}' expired at {expires_at}.",
            details=f"The capability token exceeded its maximum 60s TTL window. Current time is {time.time()}.",
            permitted_alternate_paths=["refresh_capability_token"],
            scope_boundary=scope,
            suggested_recovery_step="Obtain a refreshed capability token with fresh TTL and retry operation.",
            timestamp=time.time(),
        )

    @staticmethod
    def unauthorized_resource_scope(
        requested_resource: str,
        scope: ScopeBoundary,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.UNAUTHORIZED_RESOURCE_SCOPE,
            violated_invariant=f"ResourceConfinementViolation: Target '{requested_resource}' outside granted scope.",
            details=f"Token is confined to resources {scope.allowed_resource_ids}, but operation targeted '{requested_resource}'.",
            permitted_alternate_paths=[f"inspect_{r}" for r in scope.allowed_resource_ids],
            scope_boundary=scope,
            suggested_recovery_step="Restrict operations to resources within your assigned scope boundary.",
            timestamp=time.time(),
        )

    @staticmethod
    def unauthorized_method_scope(
        requested_method: str,
        scope: ScopeBoundary,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.UNAUTHORIZED_METHOD_SCOPE,
            violated_invariant=f"MethodCaveatViolation: Method/Tool '{requested_method}' is not in permitted capabilities.",
            details=f"Granted methods are {scope.allowed_methods}, but attempted action was '{requested_method}'.",
            permitted_alternate_paths=scope.allowed_methods,
            scope_boundary=scope,
            suggested_recovery_step=f"Use permitted methods ({', '.join(scope.allowed_methods)}) or request escalated capabilities.",
            timestamp=time.time(),
        )

    @staticmethod
    def causal_lineage_violation(
        resource_id: str,
        target_op: str,
        prerequisite_reads: List[str],
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.CAUSAL_LINEAGE_VIOLATION,
            violated_invariant=f"CausalReadPreconditionViolation: Mutation requires prior read inspection of '{resource_id}' before executing '{target_op}'.",
            details=f"Autonomous mutations require an established causal lineage. Resource '{resource_id}' was never read or inspected in this trace.",
            permitted_alternate_paths=prerequisite_reads,
            suggested_recovery_step=f"Execute an inspection read ({prerequisite_reads[0] if prerequisite_reads else 'read tool'}) on '{resource_id}' to generate a valid pre-state witness.",
            timestamp=time.time(),
        )

    @staticmethod
    def missing_action_permit(
        action_method: str,
        resource_id: str,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.MISSING_ACTION_PERMIT,
            violated_invariant=f"ActionPermitRequired: Destructive mutation '{action_method}' on '{resource_id}' requires a signed ActionPermit.",
            details="Destructive actions (POST, PUT, DELETE, or destructive MCP tools) must bundle an ActionPermit containing a pre-state witness H(S).",
            permitted_alternate_paths=[f"read_{resource_id}", f"inspect_{resource_id}"],
            suggested_recovery_step=f"Obtain a verified ActionPermit binding your pre-state witness H(S) for '{resource_id}' before executing mutation.",
            timestamp=time.time(),
        )

    @staticmethod
    def prestate_hash_mismatch(
        resource_id: str,
        expected_hash: str,
        observed_hash: str,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.PRESTATE_HASH_MISMATCH,
            violated_invariant=f"PreStateWitnessDrift: State of '{resource_id}' drifted between inspection and execution.",
            details=f"Permit pre-state hash H(S)={expected_hash[:12]}... does not match current state hash H(S')={observed_hash[:12]}.... State drifted and was modified concurrently.",
            permitted_alternate_paths=[f"re-read_{resource_id}"],
            suggested_recovery_step=f"Re-inspect '{resource_id}' to observe updated state, obtain a fresh witness hash, and re-issue the ActionPermit.",
            timestamp=time.time(),
        )

    @staticmethod
    def hallucinated_resource_id(
        resource_id: str,
        valid_candidates: List[str],
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.HALLUCINATED_RESOURCE_ID,
            violated_invariant=f"UnwitnessedResourceReference: Resource ID '{resource_id}' does not exist in observed lineage.",
            details=f"The agent attempted to operate on '{resource_id}', which has not been discovered or read in the active session.",
            permitted_alternate_paths=valid_candidates or ["list_resources", "list_pending_actions"],
            suggested_recovery_step="Query discovery or listing tools to retrieve real existing resource identifiers.",
            timestamp=time.time(),
        )

    @staticmethod
    def attenuation_violation(
        reason: str,
        parent_scope: Optional[ScopeBoundary] = None,
    ) -> SemanticDenialEnvelope:
        return SemanticDenialEnvelope(
            denied=True,
            denial_code=DenialCode.ATTENUATION_VIOLATION,
            violated_invariant="MonotonicAttenuationInvariant: Attenuated token cannot widen privileges or exceed parent TTL.",
            details=reason,
            permitted_alternate_paths=[],
            scope_boundary=parent_scope,
            suggested_recovery_step="Ensure attenuated scope parameters are a strict subset of the parent token's capabilities.",
            timestamp=time.time(),
        )
