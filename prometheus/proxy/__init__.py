"""
Prometheus Capability Hypervisor & Stateful Execution Firewall.
Provides inline capability attenuation, state invariant verification,
pre-state witness gates H(S), and semantic denial envelopes.
"""

from prometheus.proxy.models import (
    ActionPermit,
    CapabilityToken,
    DenialCode,
    PreStateWitness,
    ProxyToolRequest,
    ProxyToolResponse,
    ScopeBoundary,
    SemanticDenialEnvelope,
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
from prometheus.proxy.denial_envelope import DenialEnvelopeFactory
from prometheus.proxy.hypervisor import ToolExecutionHypervisor

__all__ = [
    "ActionPermit",
    "AttenuationViolationError",
    "CapabilityToken",
    "CausalLineageTracker",
    "DenialCode",
    "DenialEnvelopeFactory",
    "PreStateWitness",
    "ProxyToolRequest",
    "ProxyToolResponse",
    "ScopeBoundary",
    "SemanticDenialEnvelope",
    "StateInvariantGate",
    "StateWitnessRegistry",
    "TokenAuthority",
    "ToolCallType",
    "ToolExecutionHypervisor",
]
