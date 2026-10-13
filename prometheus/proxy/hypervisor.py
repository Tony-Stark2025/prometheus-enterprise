"""
Inline Tool Execution Hypervisor Proxy.
Asynchronous reverse proxy and execution interceptor for MCP (JSON-RPC) and HTTP tool calls.
Enforces monotonic capability attenuation, causal dependency gates, pre-state witness
verification H(S), and structured semantic denial envelopes.
"""

import json
import re
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional, Union
import structlog

from prometheus.proxy.models import (
    ActionPermit,
    CapabilityToken,
    DenialCode,
    PreStateWitness,
    ProxyToolRequest,
    ProxyToolResponse,
    SemanticDenialEnvelope,
    ToolCallType,
)
from prometheus.proxy.token_authority import TokenAuthority
from prometheus.proxy.state_invariants import StateInvariantGate, StateWitnessRegistry
from prometheus.proxy.denial_envelope import DenialEnvelopeFactory
from prometheus.pentest.route_graph import OpenAPIRouteGraph

logger = structlog.get_logger(__name__)


class ToolExecutionHypervisor:
    """
    Stateful Capability Hypervisor Reverse Proxy.
    Interprets, verifies, and mediates all autonomous agent tool invocations.
    """

    def __init__(
        self,
        token_authority: Optional[TokenAuthority] = None,
        registry: Optional[StateWitnessRegistry] = None,
        route_graph: Optional[OpenAPIRouteGraph] = None,
        mcp_handler: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = None,
        http_handler: Optional[Callable[[str, str, Optional[Dict[str, Any]], Dict[str, str]], Coroutine[Any, Any, Any]]] = None,
    ):
        self.token_authority = token_authority or TokenAuthority()
        self.registry = registry or StateWitnessRegistry(self.token_authority)
        self.gate = StateInvariantGate(
            token_authority=self.token_authority,
            registry=self.registry,
            route_graph=route_graph,
        )
        self.mcp_handler = mcp_handler
        self.http_handler = http_handler

    @staticmethod
    def extract_resource_id_from_path(path: str) -> Optional[str]:
        """
        Extracts candidate resource UUIDs or IDs from URL paths.
        Distinguishes resource IDs from collection names and API versioning.
        """
        clean_path = path.split("?")[0].strip("/")
        segments = [s for s in clean_path.split("/") if s]

        api_prefixes = {"api", "v1", "v2", "v3", "v1alpha", "v1beta", "v1beta1", "v1beta2"}
        system_endpoints = {
            "health", "healthz", "ready", "readyz", "metrics", "status",
            "ping", "info", "version", "analytics", "settings"
        }
        collection_names = {
            "invoices", "workspaces", "projects", "users", "items", "actions", "reports",
            "accounts", "tenants", "sessions", "drafts", "orders", "tasks", "endpoints",
            "webhooks", "roles", "policies", "documents", "files", "permissions", "resources",
            "members", "comments", "messages", "tags", "categories"
        }

        uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        hex_id_pattern = re.compile(r"^[0-9a-fA-F]{24,64}$")
        numeric_id_pattern = re.compile(r"^\d+$")
        slug_id_pattern = re.compile(r"^[a-zA-Z0-9]+[_-][a-zA-Z0-9_-]+$")

        for seg in reversed(segments):
            seg_lower = seg.lower()
            if seg_lower in api_prefixes or seg_lower in system_endpoints or seg_lower in collection_names:
                continue

            if (
                uuid_pattern.match(seg)
                or hex_id_pattern.match(seg)
                or numeric_id_pattern.match(seg)
                or slug_id_pattern.match(seg)
            ):
                return seg

        return None

    def _resolve_token(self, token_input: Optional[Union[str, CapabilityToken, Dict[str, Any]]]) -> Optional[CapabilityToken]:
        """Resolves token input string, dict, or object into CapabilityToken."""
        if token_input is None:
            return None
        if isinstance(token_input, CapabilityToken):
            return token_input
        if isinstance(token_input, dict):
            try:
                return CapabilityToken.model_validate(token_input)
            except Exception:
                logger.warn("hypervisor_token_dict_parse_failed")
                return None
        if isinstance(token_input, str):
            try:
                data = json.loads(token_input)
                return CapabilityToken.model_validate(data)
            except Exception:
                logger.warn("hypervisor_token_parse_failed", raw_token=token_input[:30])
                return None
        return None

    def _resolve_permit(self, permit_input: Optional[Union[str, ActionPermit, Dict[str, Any]]]) -> Optional[ActionPermit]:
        """Resolves permit input into ActionPermit."""
        if permit_input is None:
            return None
        if isinstance(permit_input, ActionPermit):
            return permit_input
        if isinstance(permit_input, dict):
            return ActionPermit.model_validate(permit_input)
        if isinstance(permit_input, str):
            try:
                data = json.loads(permit_input)
                return ActionPermit.model_validate(data)
            except Exception:
                logger.warn("hypervisor_permit_parse_failed", raw_permit=permit_input[:30])
                return None
        return None

    async def execute_tool(self, request: ProxyToolRequest) -> ProxyToolResponse:
        """
        Primary hypervisor gateway entrypoint for both MCP and HTTP tool requests.
        """
        start_time = time.time()
        token = self._resolve_token(request.token)
        permit = self._resolve_permit(request.action_permit)

        # Resolve target resource ID if not passed explicitly
        if request.resource_id is None:
            if request.call_type == ToolCallType.HTTP:
                request.resource_id = self.extract_resource_id_from_path(request.target)
            elif request.call_type == ToolCallType.MCP:
                args = request.payload
                res_id = args.get("resource_id") or args.get("id")
                if res_id is None:
                    for k, v in args.items():
                        if k.endswith("_id") and isinstance(v, (str, int)):
                            res_id = str(v)
                            break
                if res_id is not None:
                    request.resource_id = str(res_id)

            if request.resource_id is None:
                request.resource_id = StateInvariantGate.extract_resource_id_from_body_or_query(
                    request.target, request.payload
                )

        # 1. Capability Attenuation & Caveat Gate
        tenant_id = (
            request.context.get("tenant_id")
            or request.headers.get("x-tenant-id")
            or request.headers.get("X-Tenant-ID")
        )
        auth_denial = self.token_authority.validate_action(
            token=token,
            method=request.method,
            resource_id=request.resource_id,
            tenant_id=tenant_id,
        )
        if auth_denial is not None:
            latency = (time.time() - start_time) * 1000.0
            return ProxyToolResponse(
                success=False,
                status_code=403,
                denial=auth_denial,
                latency_ms=latency,
            )

        # 2. State Invariant & Lineage Gate
        assert token is not None  # Guaranteed by auth_denial is None
        gate_denial = self.gate.verify_execution_gate(
            session_id=request.session_id,
            method=request.method,
            target=request.target,
            resource_id=request.resource_id,
            permit=permit,
            token=token,
            payload=request.payload,
        )
        if gate_denial is not None:
            latency = (time.time() - start_time) * 1000.0
            return ProxyToolResponse(
                success=False,
                status_code=403,
                denial=gate_denial,
                latency_ms=latency,
            )

        # 3. Admitted: Forward execution to target
        try:
            result_payload = None
            if request.call_type == ToolCallType.HTTP and self.http_handler:
                result_payload = await self.http_handler(
                    request.method,
                    request.target,
                    request.payload,
                    request.headers,
                )
            elif request.call_type == ToolCallType.MCP and self.mcp_handler:
                mcp_body = {
                    "jsonrpc": "2.0",
                    "id": request.context.get("rpc_id", 1),
                    "method": "tools/call",
                    "params": {"name": request.target, "arguments": request.payload},
                }
                result_payload = await self.mcp_handler(mcp_body)
            else:
                # Default execution fallback
                result_payload = {"status": "executed", "target": request.target, "method": request.method}

            witness = None
            is_mutation = self.gate.is_mutation(request.method, request.target)

            if not is_mutation:
                # Read operation succeeded -> produce PreStateWitness and register in lineage
                res_id = request.resource_id or request.target
                witness = self.registry.register_state(
                    resource_id=res_id,
                    state_data=result_payload,
                    source_op=f"{request.method} {request.target}",
                )
                self.gate.lineage_tracker.record_read(
                    session_id=request.session_id,
                    resource_id=res_id,
                    witness=witness,
                    op_name=f"{request.method} {request.target}",
                )

                # Also automatically witness entities if payload is an array or collection dict
                items_to_register = []
                if isinstance(result_payload, list):
                    items_to_register = result_payload
                elif isinstance(result_payload, dict):
                    for k in ("items", "drafts", "invoices", "data", "results", "records", "actions", "workspaces", "projects"):
                        if isinstance(result_payload.get(k), list):
                            items_to_register.extend(result_payload[k])

                for item in items_to_register:
                    if isinstance(item, dict):
                        item_id = item.get("id") or item.get("draft_id") or item.get("resource_id") or item.get("invoice_id")
                        if not item_id:
                            for k, v in item.items():
                                if k.endswith("_id") and isinstance(v, (str, int)):
                                    item_id = str(v)
                                    break
                        if item_id:
                            item_id_str = str(item_id)
                            item_witness = self.registry.register_state(
                                resource_id=item_id_str,
                                state_data=item,
                                source_op=f"{request.method} {request.target}",
                            )
                            self.gate.lineage_tracker.record_read(
                                session_id=request.session_id,
                                resource_id=item_id_str,
                                witness=item_witness,
                                op_name=f"{request.method} {request.target}",
                            )
            else:
                # Mutation succeeded -> mark permit consumed to prevent replay attacks
                if permit:
                    self.gate.mark_permit_consumed(permit.permit_id)

                if request.method.upper() == "DELETE" or any(request.target.lower().startswith(p) for p in ("delete_", "remove_")):
                    if request.resource_id:
                        self.registry.delete_state(request.resource_id)
                else:
                    target_id = request.resource_id
                    if not target_id and isinstance(result_payload, dict):
                        target_id = result_payload.get("id") or result_payload.get("resource_id") or result_payload.get("draft_id")
                        if not target_id:
                            for k, v in result_payload.items():
                                if k.endswith("_id") and isinstance(v, (str, int)):
                                    target_id = str(v)
                                    break

                    if target_id:
                        target_id_str = str(target_id)
                        mut_witness = self.registry.update_state(
                            resource_id=target_id_str,
                            new_state_data=result_payload,
                            source_op=f"{request.method} {request.target}",
                        )
                        self.gate.lineage_tracker.record_read(
                            session_id=request.session_id,
                            resource_id=target_id_str,
                            witness=mut_witness,
                            op_name=f"{request.method} {request.target}",
                        )

            latency = (time.time() - start_time) * 1000.0
            return ProxyToolResponse(
                success=True,
                status_code=200,
                result=result_payload,
                pre_state_witness=witness,
                latency_ms=latency,
            )

        except Exception as e:
            logger.exception("hypervisor_downstream_dispatch_error", error=str(e))
            latency = (time.time() - start_time) * 1000.0
            return ProxyToolResponse(
                success=False,
                status_code=500,
                result={"error": str(e)},
                latency_ms=latency,
            )

    async def handle_mcp_jsonrpc(
        self,
        request_dict: Dict[str, Any],
        token: Optional[Union[str, CapabilityToken, Dict[str, Any]]] = None,
        permit: Optional[Union[str, ActionPermit, Dict[str, Any]]] = None,
        session_id: str = "default_session",
    ) -> Dict[str, Any]:
        """
        Intercepts and mediates standard JSON-RPC 2.0 MCP tool calls.
        """
        req_id = request_dict.get("id")
        method = request_dict.get("method", "")
        params = request_dict.get("params", {})

        # Unrestricted protocol negotiation & tool introspection
        if method in ("initialize", "tools/list", "ping"):
            if self.mcp_handler:
                return await self.mcp_handler(request_dict)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"status": "ok", "method": method},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})

            # Extract resource_id from standard argument conventions
            res_id = args.get("resource_id") or args.get("id")
            if res_id is None:
                for k, v in args.items():
                    if k.endswith("_id") and isinstance(v, (str, int)):
                        res_id = str(v)
                        break

            # Check for embedded token/permit in arguments or top-level dict
            active_token = (
                token
                or args.get("capability_token")
                or request_dict.get("capability_token")
                or request_dict.get("token")
            )
            active_permit = (
                permit
                or args.get("action_permit")
                or request_dict.get("action_permit")
                or request_dict.get("permit")
            )

            proxy_req = ProxyToolRequest(
                call_type=ToolCallType.MCP,
                method=tool_name,
                target=tool_name,
                resource_id=str(res_id) if res_id is not None else None,
                payload=args,
                token=active_token,
                action_permit=self._resolve_permit(active_permit),
                session_id=session_id,
                context={"rpc_id": req_id},
            )

            resp = await self.execute_tool(proxy_req)

            if not resp.success:
                if resp.denial:
                    denial_data = resp.denial.model_dump(mode="json")
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32003,
                            "message": f"Capability Hypervisor Denial: {resp.denial.denial_code.value}",
                            "data": denial_data,
                        },
                    }
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": "Tool execution downstream failure",
                            "data": resp.result,
                        },
                    }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": resp.result,
                "pre_state_witness": resp.pre_state_witness.model_dump() if resp.pre_state_witness else None,
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }

    async def handle_http_request(
        self,
        method: str,
        path: str,
        resource_id: Optional[str] = None,
        body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        token: Optional[Union[str, CapabilityToken, Dict[str, Any]]] = None,
        permit: Optional[Union[str, ActionPermit, Dict[str, Any]]] = None,
        session_id: str = "default_session",
    ) -> ProxyToolResponse:
        """
        Intercepts and mediates HTTP tool invocations.
        """
        hdrs = headers or {}
        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        res_id = resource_id or self.extract_resource_id_from_path(path)

        # Check for Authorization header case-insensitively if token not passed explicitly
        active_token = token
        if active_token is None:
            auth_val = hdrs_lower.get("authorization")
            if auth_val and auth_val.startswith("Bearer "):
                active_token = auth_val[7:]

        active_permit = permit
        if active_permit is None:
            active_permit = hdrs_lower.get("x-action-permit")

        req = ProxyToolRequest(
            call_type=ToolCallType.HTTP,
            method=method.upper(),
            target=path,
            resource_id=res_id,
            payload=body or {},
            token=active_token,
            action_permit=self._resolve_permit(active_permit),
            headers=hdrs,
            session_id=session_id,
        )

        return await self.execute_tool(req)
