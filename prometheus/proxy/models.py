"""
Stateful Capability Hypervisor - Domain Models.
Strict Pydantic schemas for monotonic capability tokens, action permits,
pre-state witness hashes, and semantic denial envelopes.
"""

from enum import Enum
import time
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ToolCallType(str, Enum):
    MCP = "mcp"
    HTTP = "http"


class DenialCode(str, Enum):
    MISSING_ACTION_TOKEN = "MISSING_ACTION_TOKEN"
    EXPIRED_ACTION_TOKEN = "EXPIRED_ACTION_TOKEN"
    UNAUTHORIZED_RESOURCE_SCOPE = "UNAUTHORIZED_RESOURCE_SCOPE"
    UNAUTHORIZED_METHOD_SCOPE = "UNAUTHORIZED_METHOD_SCOPE"
    CAUSAL_LINEAGE_VIOLATION = "CAUSAL_LINEAGE_VIOLATION"
    MISSING_ACTION_PERMIT = "MISSING_ACTION_PERMIT"
    PRESTATE_HASH_MISMATCH = "PRESTATE_HASH_MISMATCH"
    HALLUCINATED_RESOURCE_ID = "HALLUCINATED_RESOURCE_ID"
    PERMIT_TAMPERED = "PERMIT_TAMPERED"
    ATTENUATION_VIOLATION = "ATTENUATION_VIOLATION"


class ScopeBoundary(BaseModel):
    """Defines the strict operational boundaries of a capability."""
    allowed_methods: List[str] = Field(..., description="Permitted HTTP verbs (e.g. GET, POST) or MCP tool names")
    allowed_resource_ids: List[str] = Field(..., description="Permitted target resource IDs (or ['*'] for wildcard)")
    tenant_id: Optional[str] = Field(default=None, description="Optional discrete tenant boundary")
    max_ttl_seconds: int = Field(default=60, description="Strict TTL ceiling for the capability")
    issued_at: float = Field(default_factory=time.time, description="Unix timestamp of issue")
    expires_at: float = Field(..., description="Unix timestamp of hard expiration")


class CapabilityToken(BaseModel):
    """
    Cryptographically scoped capability token.
    Eliminates ambient service account authority by enforcing bounded caveats.
    """
    token_id: str = Field(..., description="Unique token UUID")
    subject: str = Field(..., description="Agent or principal identity")
    scope: ScopeBoundary = Field(..., description="Attenuated scope boundary")
    parent_token_id: Optional[str] = Field(default=None, description="Lineage link to parent token if attenuated")
    signature: str = Field(..., description="HMAC-SHA256 signature sealing token contents")

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.scope.expires_at

    def allows_method(self, method: str) -> bool:
        if "*" in self.scope.allowed_methods:
            return True
        method_upper = method.upper()
        return any(m.upper() == method_upper or m == method for m in self.scope.allowed_methods)

    def allows_resource(self, resource_id: Optional[str]) -> bool:
        if "*" in self.scope.allowed_resource_ids:
            return True
        if resource_id is None:
            return True
        return resource_id in self.scope.allowed_resource_ids


class PreStateWitness(BaseModel):
    """
    Cryptographic pre-state witness derived from an authorized prior read.
    Guarantees H(S) pre-condition before destructive mutations are admitted.
    """
    resource_id: str = Field(..., description="Identifier of the witnessed resource")
    state_hash: str = Field(..., description="Cryptographic SHA-256 hash of canonical pre-state H(S)")
    witnessed_at: float = Field(default_factory=time.time, description="Unix timestamp when state was witnessed")
    source_op: str = Field(..., description="Originating read tool or HTTP endpoint (e.g. 'GET /api/v1/items/1')")
    signature: str = Field(..., description="HMAC signature sealing the pre-state witness")
    raw_state_snippet: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional canonical state snippet for deterministic drift verification"
    )


class ActionPermit(BaseModel):
    """
    One-time permit required for destructive mutations (POST, PUT, DELETE).
    Binds the capability token to a verified PreStateWitness.
    """
    permit_id: str = Field(..., description="Unique permit UUID")
    token_id: str = Field(..., description="ID of the bound CapabilityToken")
    action_method: str = Field(..., description="Target mutating method or tool name")
    resource_id: str = Field(..., description="Target resource ID")
    pre_state_witness: PreStateWitness = Field(..., description="Bound cryptographic pre-state witness")
    created_at: float = Field(default_factory=time.time, description="Unix timestamp of permit minting")
    signature: str = Field(..., description="HMAC signature verifying permit authenticity")


class SemanticDenialEnvelope(BaseModel):
    """
    Structured semantic denial envelope emitted on invariant or permit failure.
    Prevents LLM denial cascade collapse and guides autonomous agent recovery.
    """
    denied: bool = Field(default=True, description="Always true for denial envelopes")
    denial_code: DenialCode = Field(..., description="Standardized hypervisor denial error code")
    violated_invariant: str = Field(..., description="Precise formal invariant that was violated")
    details: str = Field(..., description="Detailed diagnostic context for the reasoning engine")
    permitted_alternate_paths: List[str] = Field(
        default_factory=list,
        description="Valid alternative actions or prerequisite inspection paths"
    )
    scope_boundary: Optional[ScopeBoundary] = Field(
        default=None,
        description="The active or violated capability boundary"
    )
    suggested_recovery_step: str = Field(
        ...,
        description="Prescriptive action for the reasoning agent to recover valid execution"
    )
    timestamp: float = Field(default_factory=time.time, description="Timestamp of denial emission")


class ProxyToolRequest(BaseModel):
    """Standardized tool invocation request entering the capability hypervisor."""
    call_type: ToolCallType = Field(..., description="Invocation protocol: MCP or HTTP")
    method: str = Field(..., description="HTTP verb (e.g. GET, POST) or MCP method (e.g. tools/call)")
    target: str = Field(..., description="Endpoint path or MCP tool name")
    resource_id: Optional[str] = Field(default=None, description="Extracted target resource ID")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Invocation payload or tool arguments")
    token: Optional[Union[str, CapabilityToken]] = Field(default=None, description="Capability token")
    action_permit: Optional[ActionPermit] = Field(default=None, description="Action permit for destructive operations")
    headers: Dict[str, str] = Field(default_factory=dict, description="Transport headers")
    session_id: str = Field(default="default_session", description="Execution session/trace ID")
    context: Dict[str, Any] = Field(default_factory=dict, description="Metadata context")


class ProxyToolResponse(BaseModel):
    """Standardized hypervisor response."""
    success: bool = Field(..., description="True if admitted and successfully executed")
    status_code: int = Field(default=200, description="Transport status code (200, 400, 403, 404, etc.)")
    result: Optional[Any] = Field(default=None, description="Execution result payload if admitted")
    denial: Optional[SemanticDenialEnvelope] = Field(default=None, description="Semantic denial envelope if rejected")
    pre_state_witness: Optional[PreStateWitness] = Field(
        default=None,
        description="Fresh pre-state witness generated if this was an authorized read"
    )
    latency_ms: float = Field(default=0.0, description="Hypervisor gateway overhead in milliseconds")
