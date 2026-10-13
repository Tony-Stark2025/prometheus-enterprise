"""
Prometheus Model Context Protocol (MCP) Server.
Exposes Prometheus multi-agent telemetry, HITL actions, and Capability Hypervisor
firewall controls as MCP tools over stdio and SSE.
"""

import os
import sys
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
from prometheus.mcp.protocol import (
    JSONRPCRequest,
    JSONRPCResponse,
    MCPToolDefinition,
    MCPToolParameter,
    MCPListToolsResponse,
)
from prometheus.security.abac_guard import UserContext
from prometheus.memory.state_store import state_store, DraftStatus
from prometheus.tools.slack_tools import SlackTools
from prometheus.proxy.hypervisor import ToolExecutionHypervisor
from prometheus.proxy.token_authority import TokenAuthority
from prometheus.proxy.state_invariants import StateWitnessRegistry

logger = logging.getLogger(__name__)


class PrometheusMCPServer:
    """
    Standard Model Context Protocol (MCP) Server for Prometheus.
    Mediated by the Stateful Execution Capability Hypervisor to enforce
    monotonic capability attenuation, causal dependency gates, and pre-state witness checks.
    """

    TOOLS: List[MCPToolDefinition] = [
        MCPToolDefinition(
            name="get_daily_digest",
            description="Triggers the multi-agent fleet to ingest telemetry and produce the daily alignment digest.",
            inputSchema=MCPToolParameter(
                properties={
                    "user_id": {"type": "string", "description": "Authenticated user ID"},
                    "username": {"type": "string", "description": "User handle"},
                    "scopes": {"type": "array", "items": {"type": "string"}, "description": "Authorized scopes"},
                    "query": {"type": "string", "description": "Investigation query"},
                },
                required=["username"],
            ),
        ),
        MCPToolDefinition(
            name="list_active_blockers",
            description="Lists all currently active delivery bottlenecks and correlated blockers.",
            inputSchema=MCPToolParameter(properties={}),
        ),
        MCPToolDefinition(
            name="list_pending_actions",
            description="Lists action drafts waiting for Human-In-The-Loop approval.",
            inputSchema=MCPToolParameter(properties={}),
        ),
        MCPToolDefinition(
            name="approve_action",
            description="Explicitly approves and dispatches an action draft to Slack/Jira.",
            inputSchema=MCPToolParameter(
                properties={
                    "draft_id": {"type": "string", "description": "ID of the action draft"},
                    "approver": {"type": "string", "description": "Username of the approver"},
                },
                required=["draft_id", "approver"],
            ),
        ),
        MCPToolDefinition(
            name="reject_action",
            description="Aborts a proposed action draft.",
            inputSchema=MCPToolParameter(
                properties={
                    "draft_id": {"type": "string", "description": "ID of the action draft"},
                    "approver": {"type": "string", "description": "Username of the rejector"},
                },
                required=["draft_id"],
            ),
        ),
        MCPToolDefinition(
            name="scan_api_security",
            description="Autonomous adversarial exploit engine probe for OWASP API Top 10 vulnerabilities (BOLA/BFLA).",
            inputSchema=MCPToolParameter(
                properties={
                    "target_url": {"type": "string", "description": "Target base URL to scan"},
                    "spec_url": {"type": "string", "description": "OpenAPI spec URL or path"},
                    "auth_header_alpha": {"type": "string", "description": "Victim tenant auth token"},
                    "auth_header_beta": {"type": "string", "description": "Attacker tenant auth token"},
                },
                required=["target_url"],
            ),
        ),
        MCPToolDefinition(
            name="mint_capability_token",
            description="Mints a short-lived, monotonic capability token with bounded execution caveats.",
            inputSchema=MCPToolParameter(
                properties={
                    "subject": {"type": "string", "description": "Sub-agent identifier"},
                    "allowed_methods": {"type": "array", "items": {"type": "string"}, "description": "Allowed methods/tools"},
                    "allowed_resources": {"type": "array", "items": {"type": "string"}, "description": "Scoped resource IDs"},
                    "ttl_seconds": {"type": "integer", "description": "TTL in seconds (max 60s)"},
                },
                required=["subject"],
            ),
        ),
        MCPToolDefinition(
            name="request_action_permit",
            description="Requests a signed Action Permit with cryptographic pre-state witness H(S) for mutating operations.",
            inputSchema=MCPToolParameter(
                properties={
                    "capability_token": {"type": "object", "description": "Signed Capability Token"},
                    "target_op": {"type": "string", "description": "Target tool or method name"},
                    "resource_id": {"type": "string", "description": "Resource identifier to mutate"},
                },
                required=["capability_token", "target_op", "resource_id"],
            ),
        ),
        MCPToolDefinition(
            name="verify_action_permit",
            description="Validates an Action Permit against current resource state prior to mutation.",
            inputSchema=MCPToolParameter(
                properties={
                    "capability_token": {"type": "object", "description": "Signed Capability Token"},
                    "action_permit": {"type": "object", "description": "Signed Action Permit"},
                    "target_op": {"type": "string", "description": "Target tool or method name"},
                    "resource_id": {"type": "string", "description": "Target resource ID"},
                },
                required=["capability_token", "action_permit", "target_op", "resource_id"],
            ),
        ),
    ]

    def __init__(
        self,
        hypervisor: Optional[ToolExecutionHypervisor] = None,
        enforce_hypervisor: bool = False,
    ):
        self.enforce_hypervisor = (
            enforce_hypervisor
            or os.getenv("PROMETHEUS_ENFORCE_HYPERVISOR", "false").lower() in ("true", "1", "yes")
        )
        if hypervisor:
            self.hypervisor = hypervisor
        else:
            token_authority = TokenAuthority()
            registry = StateWitnessRegistry(token_authority)
            self.hypervisor = ToolExecutionHypervisor(
                token_authority=token_authority,
                registry=registry,
                mcp_handler=self._execute_tool_raw,
            )

    async def _execute_tool_raw(self, request_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Bridge between Hypervisor execution and MCP tool dispatch."""
        params = request_dict.get("params", {})
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        return await self._execute_tool(tool_name, args)

    async def handle_jsonrpc(
        self,
        request_dict: Dict[str, Any],
        token: Optional[Any] = None,
        permit: Optional[Any] = None,
        session_id: str = "mcp_session",
    ) -> Dict[str, Any]:
        """Processes incoming JSON-RPC 2.0 requests according to MCP specifications."""
        req_id = request_dict.get("id")
        method = request_dict.get("method", "")
        params = request_dict.get("params", {})

        try:
            if method == "initialize":
                return JSONRPCResponse(
                    id=req_id,
                    result={
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": "prometheus-mcp-server",
                            "version": "0.1.0",
                        },
                        "capabilities": {
                            "tools": {"listChanged": True},
                        },
                    },
                ).model_dump()

            elif method == "tools/list":
                return JSONRPCResponse(
                    id=req_id,
                    result=MCPListToolsResponse(tools=self.TOOLS).model_dump(),
                ).model_dump()

            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})

                has_token_or_permit = bool(
                    token
                    or permit
                    or request_dict.get("token")
                    or request_dict.get("capability_token")
                    or request_dict.get("action_permit")
                    or request_dict.get("permit")
                    or (isinstance(args, dict) and any(k in args for k in ("token", "capability_token", "action_permit", "permit")))
                )

                if self.enforce_hypervisor or has_token_or_permit:
                    return await self.hypervisor.handle_mcp_jsonrpc(
                        request_dict=request_dict,
                        token=token,
                        permit=permit,
                        session_id=session_id,
                    )

                res = await self._execute_tool(tool_name, args)
                return JSONRPCResponse(id=req_id, result=res).model_dump()

            else:
                return JSONRPCResponse(
                    id=req_id,
                    error={"code": -32601, "message": f"Method '{method}' not found"},
                ).model_dump()

        except Exception as e:
            logger.exception("Error handling MCP request: %s", e)
            return JSONRPCResponse(
                id=req_id,
                error={"code": -32603, "message": f"Internal error: {str(e)}"},
            ).model_dump()

    async def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "get_daily_digest":
            from prometheus.workflows.prometheus_flow import PrometheusWorkflow
            user = UserContext(
                user_id=args.get("user_id", "mcp-user"),
                username=args.get("username", "alex-lead"),
                is_authenticated=True,
                org_scopes=set(args.get("scopes", ["engineering", "platform"])),
            )
            result = await PrometheusWorkflow.run(
                user=user,
                query=args.get("query", "Scan cross-squad telemetry for active sprint blockers"),
            )
            return {"content": [{"type": "text", "text": json.dumps(result.model_dump(), default=str)}]}

        elif tool_name == "list_active_blockers":
            blockers = await state_store.get_active_blockers()
            return {"content": [{"type": "text", "text": json.dumps([b.model_dump() for b in blockers], default=str)}]}

        elif tool_name == "list_pending_actions":
            drafts = await state_store.list_drafts(status=DraftStatus.PENDING)
            return {"content": [{"type": "text", "text": json.dumps([d.model_dump() for d in drafts], default=str)}]}

        elif tool_name == "approve_action":
            draft_id = args.get("draft_id")
            approver = args.get("approver", "mcp-user")
            res = await SlackTools.dispatch_approved_action(draft_id, approver)
            return {"content": [{"type": "text", "text": json.dumps(res, default=str)}]}

        elif tool_name == "reject_action":
            draft_id = args.get("draft_id")
            approver = args.get("approver", "mcp-user")
            updated = await state_store.update_draft_status(
                draft_id=draft_id,
                status=DraftStatus.REJECTED,
                approver=approver,
                result="Action rejected via MCP.",
            )
            if not updated:
                raise ValueError(f"Draft '{draft_id}' not found.")
            return {"content": [{"type": "text", "text": json.dumps({"status": "rejected", "draft_id": draft_id})}]}

        elif tool_name == "scan_api_security":
            from prometheus.pentest.service import PentestExecutionService, PentestScanRequest
            target_url = args.get("target_url")
            if not target_url:
                raise ValueError("Missing required argument: 'target_url'")
            scan_req = PentestScanRequest(
                target_url=target_url,
                spec_url=args.get("spec_url"),
                auth_header_alpha=args.get("auth_header_alpha"),
                auth_header_beta=args.get("auth_header_beta"),
            )
            scan_res = await PentestExecutionService.execute_scan(scan_req)
            return {"content": [{"type": "text", "text": json.dumps(scan_res.model_dump(), default=str)}]}

        elif tool_name == "mint_capability_token":
            subject = args.get("subject", "autonomous-agent")
            allowed_methods = args.get("allowed_methods", ["GET"])
            allowed_resources = args.get("allowed_resources", ["*"])
            ttl = args.get("ttl_seconds", 60)
            token = self.hypervisor.token_authority.mint_token(
                subject=subject,
                allowed_methods=allowed_methods,
                allowed_resource_ids=allowed_resources,
                ttl_seconds=ttl,
            )
            return {"content": [{"type": "text", "text": json.dumps(token.model_dump(), default=str)}]}

        elif tool_name == "request_action_permit":
            raw_token = args.get("capability_token")
            token = self.hypervisor._resolve_token(raw_token)
            if not token:
                raise ValueError("Invalid or missing capability token.")
            target_op = args.get("target_op")
            resource_id = str(args.get("resource_id", "*"))
            witness = self.hypervisor.registry.get_witness(resource_id)
            if witness is None:
                witness = self.hypervisor.registry.register_state(
                    resource_id=resource_id,
                    state_data={"resource_id": resource_id},
                    source_op=f"mcp_permit {target_op}",
                )
            permit = self.hypervisor.token_authority.mint_action_permit(
                token=token,
                action_method=target_op,
                resource_id=resource_id,
                witness=witness,
            )
            return {"content": [{"type": "text", "text": json.dumps(permit.model_dump(), default=str)}]}

        elif tool_name == "verify_action_permit":
            raw_token = args.get("capability_token")
            token = self.hypervisor._resolve_token(raw_token)
            raw_permit = args.get("action_permit")
            permit = self.hypervisor._resolve_permit(raw_permit)
            target_op = args.get("target_op")
            resource_id = str(args.get("resource_id", "*"))
            denial = self.hypervisor.gate.verify_execution_gate(
                session_id="mcp_verification",
                method=target_op,
                target=target_op,
                resource_id=resource_id,
                permit=permit,
                token=token,
            )
            if denial:
                return {"content": [{"type": "text", "text": json.dumps({"verified": False, "denial": denial.model_dump()}, default=str)}]}
            return {"content": [{"type": "text", "text": json.dumps({"verified": True, "permit_id": permit.permit_id if permit else None}, default=str)}]}

        else:
            raise ValueError(f"Unknown MCP tool: {tool_name}")

    async def run_stdio(self):
        """Runs the standard I/O protocol loop for desktop assistants (Antigravity, Claude Desktop)."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break
            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue
            try:
                req_json = json.loads(line_str)
                resp = await self.handle_jsonrpc(req_json)
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = JSONRPCResponse(
                    error={"code": -32700, "message": f"Parse error: {str(e)}"}
                ).model_dump()
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


mcp_server = PrometheusMCPServer()

if __name__ == "__main__":
    asyncio.run(mcp_server.run_stdio())
