"""
Token Authority & Monotonic Capability Attenuation Engine.
Mints short-lived (<=60s), cryptographically signed capability tokens with bounded caveats,
enforces monotonic privilege reduction during token derivation, and issues cryptographic
Action Permits bound to pre-state witness hashes H(S).
"""

import hmac
import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from prometheus.proxy.models import (
    ActionPermit,
    CapabilityToken,
    DenialCode,
    PreStateWitness,
    ScopeBoundary,
    SemanticDenialEnvelope,
)
from prometheus.proxy.denial_envelope import DenialEnvelopeFactory


import secrets

DEFAULT_HYPERVISOR_SECRET = (
    os.getenv("HYPERVISOR_SECRET_KEY")
    or os.getenv("VAULT_MASTER_KEY")
    or secrets.token_hex(32)
)


class AttenuationViolationError(Exception):
    """Raised when an attenuated token attempts to expand authority."""
    pass


class TokenAuthority:
    """
    Cryptographic authority for minting, attenuating, and verifying
    least-privilege capability tokens and mutation permits.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self._secret = (secret_key or DEFAULT_HYPERVISOR_SECRET).encode("utf-8")

    def _sign_payload(self, canonical_str: str) -> str:
        return hmac.new(self._secret, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify_signature(self, canonical_str: str, signature: str) -> bool:
        expected = self._sign_payload(canonical_str)
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def canonical_json(data: Any) -> str:
        """Serializes data into canonical deterministic JSON format."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def compute_state_hash(state_data: Any) -> str:
        """Computes deterministic SHA-256 state witness hash H(S)."""
        canonical_bytes = TokenAuthority.canonical_json(state_data).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def mint_token(
        self,
        subject: str,
        allowed_methods: List[str],
        allowed_resource_ids: List[str],
        ttl_seconds: int = 60,
        tenant_id: Optional[str] = None,
    ) -> CapabilityToken:
        """
        Mints a root capability token with strict upper bound of 60s TTL.
        """
        bounded_ttl = min(max(ttl_seconds, 1), 60)
        now = time.time()
        expires_at = now + bounded_ttl

        token_id = f"tok_{uuid.uuid4().hex[:16]}"
        scope = ScopeBoundary(
            allowed_methods=list(allowed_methods),
            allowed_resource_ids=list(allowed_resource_ids),
            tenant_id=tenant_id,
            max_ttl_seconds=bounded_ttl,
            issued_at=now,
            expires_at=expires_at,
        )

        canonical_payload = self.canonical_json({
            "token_id": token_id,
            "subject": subject,
            "scope": scope.model_dump(),
            "parent_token_id": None,
        })
        sig = self._sign_payload(canonical_payload)

        return CapabilityToken(
            token_id=token_id,
            subject=subject,
            scope=scope,
            parent_token_id=None,
            signature=sig,
        )

    def attenuate_token(
        self,
        parent_token: CapabilityToken,
        restricted_methods: Optional[List[str]] = None,
        restricted_resources: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> CapabilityToken:
        """
        Derives an attenuated child token.
        Enforces monotonic attenuation:
        1. Child methods must be subset of parent methods.
        2. Child resources must be subset of parent resources.
        3. Child TTL cannot exceed parent's expiration time.
        4. Tenant confinement is preserved.
        """
        if not self.verify_token(parent_token):
            raise AttenuationViolationError("Cannot attenuate an invalid or tampered parent token.")

        if parent_token.is_expired():
            raise AttenuationViolationError("Cannot attenuate an expired parent token.")

        if tenant_id is not None and parent_token.scope.tenant_id is not None and tenant_id != parent_token.scope.tenant_id:
            raise AttenuationViolationError(
                f"Tenant escalation forbidden: cannot switch tenant from '{parent_token.scope.tenant_id}' to '{tenant_id}'."
            )

        parent_methods = set(parent_token.scope.allowed_methods)
        if "*" in parent_methods:
            effective_methods = restricted_methods or list(parent_methods)
        else:
            if restricted_methods is not None:
                for m in restricted_methods:
                    if m not in parent_methods and m.upper() not in [pm.upper() for pm in parent_methods]:
                        raise AttenuationViolationError(
                            f"Method escalation forbidden: '{m}' not present in parent allowed methods {list(parent_methods)}"
                        )
                effective_methods = restricted_methods
            else:
                effective_methods = list(parent_methods)

        parent_resources = set(parent_token.scope.allowed_resource_ids)
        if "*" in parent_resources:
            effective_resources = restricted_resources or list(parent_resources)
        else:
            if restricted_resources is not None:
                for r in restricted_resources:
                    if r not in parent_resources:
                        raise AttenuationViolationError(
                            f"Resource escalation forbidden: '{r}' not present in parent allowed resources {list(parent_resources)}"
                        )
                effective_resources = restricted_resources
            else:
                effective_resources = list(parent_resources)

        now = time.time()
        parent_remaining = parent_token.scope.expires_at - now
        if parent_remaining <= 0:
            raise AttenuationViolationError("Parent token has expired.")

        if ttl_seconds is not None:
            if ttl_seconds > parent_remaining:
                raise AttenuationViolationError(
                    f"TTL extension forbidden: requested {ttl_seconds}s exceeds parent remaining lifespan ({parent_remaining:.1f}s)"
                )
            child_ttl = min(ttl_seconds, 60)
        else:
            child_ttl = min(parent_remaining, 60.0)

        child_expires_at = min(now + child_ttl, parent_token.scope.expires_at)
        child_id = f"tok_{uuid.uuid4().hex[:16]}"

        effective_tenant_id = tenant_id if tenant_id is not None else parent_token.scope.tenant_id
        child_scope = ScopeBoundary(
            allowed_methods=effective_methods,
            allowed_resource_ids=effective_resources,
            tenant_id=effective_tenant_id,
            max_ttl_seconds=int(child_ttl),
            issued_at=now,
            expires_at=child_expires_at,
        )

        canonical_payload = self.canonical_json({
            "token_id": child_id,
            "subject": parent_token.subject,
            "scope": child_scope.model_dump(),
            "parent_token_id": parent_token.token_id,
        })
        sig = self._sign_payload(canonical_payload)

        return CapabilityToken(
            token_id=child_id,
            subject=parent_token.subject,
            scope=child_scope,
            parent_token_id=parent_token.token_id,
            signature=sig,
        )

    def verify_token(self, token: CapabilityToken) -> bool:
        """Verifies cryptographic signature on capability token."""
        canonical_payload = self.canonical_json({
            "token_id": token.token_id,
            "subject": token.subject,
            "scope": token.scope.model_dump(),
            "parent_token_id": token.parent_token_id,
        })
        return self._verify_signature(canonical_payload, token.signature)

    def validate_action(
        self,
        token: Optional[CapabilityToken],
        method: str,
        resource_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        current_time: Optional[float] = None,
    ) -> Optional[SemanticDenialEnvelope]:
        """
        Validates whether a token grants authority for a specific method and resource.
        Returns None if permitted, or a structured SemanticDenialEnvelope if denied.
        """
        if token is None:
            return DenialEnvelopeFactory.missing_action_token()

        if not self.verify_token(token):
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.PERMIT_TAMPERED,
                violated_invariant="CryptographicIntegrityFailure: Token signature is invalid or tampered.",
                details=f"Token '{token.token_id}' failed HMAC-SHA256 signature verification.",
                permitted_alternate_paths=["reissue_token"],
                suggested_recovery_step="Request a new signed capability token from the Token Authority.",
                timestamp=time.time(),
            )

        if token.is_expired(current_time=current_time):
            return DenialEnvelopeFactory.expired_action_token(
                token_id=token.token_id,
                expires_at=token.scope.expires_at,
                scope=token.scope,
            )

        if tenant_id is not None and token.scope.tenant_id is not None and token.scope.tenant_id != tenant_id:
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.UNAUTHORIZED_RESOURCE_SCOPE,
                violated_invariant=f"TenantConfinementViolation: Target tenant '{tenant_id}' outside granted boundary '{token.scope.tenant_id}'.",
                details=f"Token is confined to tenant '{token.scope.tenant_id}', but operation targeted '{tenant_id}'.",
                permitted_alternate_paths=[],
                scope_boundary=token.scope,
                suggested_recovery_step=f"Obtain a capability token for tenant '{tenant_id}'.",
                timestamp=time.time(),
            )

        if not token.allows_method(method):
            return DenialEnvelopeFactory.unauthorized_method_scope(
                requested_method=method,
                scope=token.scope,
            )

        if resource_id is not None and not token.allows_resource(resource_id):
            return DenialEnvelopeFactory.unauthorized_resource_scope(
                requested_resource=resource_id,
                scope=token.scope,
            )

        return None

    def create_pre_state_witness(
        self,
        resource_id: str,
        state_data: Any,
        source_op: str,
    ) -> PreStateWitness:
        """
        Produces a signed PreStateWitness derived from an authorized read operation.
        Calculates SHA-256 canonical hash H(S) and signs the tuple.
        """
        state_hash = self.compute_state_hash(state_data)
        now = time.time()
        canonical_sig_payload = f"{resource_id}:{state_hash}:{now:.6f}:{source_op}"
        sig = self._sign_payload(canonical_sig_payload)

        raw_snippet = state_data if isinstance(state_data, dict) else {"content": str(state_data)}

        return PreStateWitness(
            resource_id=resource_id,
            state_hash=state_hash,
            witnessed_at=now,
            source_op=source_op,
            signature=sig,
            raw_state_snippet=raw_snippet,
        )

    def verify_pre_state_witness(self, witness: PreStateWitness) -> bool:
        """Verifies signature on PreStateWitness."""
        canonical_sig_payload = f"{witness.resource_id}:{witness.state_hash}:{witness.witnessed_at:.6f}:{witness.source_op}"
        return self._verify_signature(canonical_sig_payload, witness.signature)

    def mint_action_permit(
        self,
        token: CapabilityToken,
        action_method: str,
        resource_id: str,
        witness: PreStateWitness,
    ) -> ActionPermit:
        """
        Mints a cryptographic Action Permit for a destructive operation.
        Binds token, method, resource, and pre-state witness together.
        """
        if not self.verify_token(token):
            raise ValueError("Cannot issue action permit for an invalid token.")
        if token.is_expired():
            raise ValueError("Cannot issue action permit for an expired token.")
        if not self.verify_pre_state_witness(witness):
            raise ValueError("PreStateWitness failed cryptographic signature verification.")
        if witness.resource_id != resource_id:
            raise ValueError(f"Witness resource mismatch: witness is for '{witness.resource_id}', permit requested for '{resource_id}'.")

        permit_id = f"per_{uuid.uuid4().hex[:16]}"
        now = time.time()
        canonical_permit_payload = f"{permit_id}:{token.token_id}:{action_method}:{resource_id}:{witness.state_hash}:{now:.6f}"
        sig = self._sign_payload(canonical_permit_payload)

        return ActionPermit(
            permit_id=permit_id,
            token_id=token.token_id,
            action_method=action_method,
            resource_id=resource_id,
            pre_state_witness=witness,
            created_at=now,
            signature=sig,
        )

    def verify_action_permit(
        self,
        permit: ActionPermit,
        token: CapabilityToken,
        current_state_hash: Optional[str] = None,
        expected_method: Optional[str] = None,
        expected_resource_id: Optional[str] = None,
        expected_tenant_id: Optional[str] = None,
        current_time: Optional[float] = None,
    ) -> Optional[SemanticDenialEnvelope]:
        """
        Verifies Action Permit validity, cryptographic signature, bound method/resource,
        expiration, and pre-state witness alignment.
        Fails closed if signature invalid, token mismatch, or pre-state drift occurs.
        """
        canonical_permit_payload = f"{permit.permit_id}:{permit.token_id}:{permit.action_method}:{permit.resource_id}:{permit.pre_state_witness.state_hash}:{permit.created_at:.6f}"
        if not self._verify_signature(canonical_permit_payload, permit.signature):
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.PERMIT_TAMPERED,
                violated_invariant="PermitSignatureFailure: ActionPermit signature verification failed.",
                details=f"Permit '{permit.permit_id}' contains an invalid HMAC signature.",
                permitted_alternate_paths=["reissue_action_permit"],
                suggested_recovery_step="Request a new signed ActionPermit.",
                timestamp=time.time(),
            )

        if permit.token_id != token.token_id:
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.PERMIT_TAMPERED,
                violated_invariant="PermitTokenBindingMismatch: ActionPermit was minted for a different token.",
                details=f"Permit bound to '{permit.token_id}', but caller presented '{token.token_id}'.",
                permitted_alternate_paths=["reissue_action_permit"],
                suggested_recovery_step="Present the capability token bound to the permit or request a new permit.",
                timestamp=time.time(),
            )

        now = current_time if current_time is not None else time.time()
        if token.is_expired(current_time=now):
            return DenialEnvelopeFactory.expired_action_token(
                token_id=token.token_id,
                expires_at=token.scope.expires_at,
                scope=token.scope,
            )

        if now - permit.created_at > 60.0 or now >= token.scope.expires_at:
            return DenialEnvelopeFactory.expired_action_token(
                token_id=permit.permit_id,
                expires_at=min(permit.created_at + 60.0, token.scope.expires_at),
                scope=token.scope,
            )

        if not self.verify_pre_state_witness(permit.pre_state_witness):
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.PERMIT_TAMPERED,
                violated_invariant="WitnessIntegrityFailure: Attached PreStateWitness is corrupted or tampered.",
                details="Pre-state witness signature failed cryptographic check.",
                permitted_alternate_paths=[f"read_{permit.resource_id}"],
                suggested_recovery_step=f"Re-inspect '{permit.resource_id}' to produce a fresh witness.",
                timestamp=time.time(),
            )

        if expected_method is not None:
            method_matches = (
                permit.action_method.upper() == expected_method.upper()
                or permit.action_method == expected_method
            )
            if not method_matches:
                return SemanticDenialEnvelope(
                    denied=True,
                    denial_code=DenialCode.UNAUTHORIZED_METHOD_SCOPE,
                    violated_invariant=f"PermitMethodMismatch: ActionPermit was minted for '{permit.action_method}', but attempted action was '{expected_method}'.",
                    details=f"Permit '{permit.permit_id}' cannot be used to execute '{expected_method}'.",
                    permitted_alternate_paths=[permit.action_method],
                    suggested_recovery_step=f"Mint an ActionPermit specifically for '{expected_method}'.",
                    timestamp=time.time(),
                )

        if expected_resource_id is not None and permit.resource_id != expected_resource_id:
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.UNAUTHORIZED_RESOURCE_SCOPE,
                violated_invariant=f"PermitResourceMismatch: ActionPermit was minted for '{permit.resource_id}', but attempted action targets '{expected_resource_id}'.",
                details=f"Permit '{permit.permit_id}' cannot be used to mutate '{expected_resource_id}'.",
                permitted_alternate_paths=[f"inspect_{expected_resource_id}"],
                suggested_recovery_step=f"Re-inspect '{expected_resource_id}' and obtain an ActionPermit for '{expected_resource_id}'.",
                timestamp=time.time(),
            )

        if expected_tenant_id is not None and token.scope.tenant_id is not None and token.scope.tenant_id != expected_tenant_id:
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.UNAUTHORIZED_RESOURCE_SCOPE,
                violated_invariant=f"TenantConfinementViolation: Token is bound to tenant '{token.scope.tenant_id}', but permit action targets tenant '{expected_tenant_id}'.",
                details=f"Tenant isolation failure on ActionPermit.",
                permitted_alternate_paths=[],
                scope_boundary=token.scope,
                suggested_recovery_step=f"Request an ActionPermit for tenant '{expected_tenant_id}'.",
                timestamp=time.time(),
            )

        # Pre-State Drift Gate: If live state hash is provided, verify against witness
        if current_state_hash is not None and current_state_hash != permit.pre_state_witness.state_hash:
            return DenialEnvelopeFactory.prestate_hash_mismatch(
                resource_id=permit.resource_id,
                expected_hash=permit.pre_state_witness.state_hash,
                observed_hash=current_state_hash,
            )

        return None
