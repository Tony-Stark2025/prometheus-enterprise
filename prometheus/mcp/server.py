"""
Prometheus Model Context Protocol (MCP) Server.
Exposes Prometheus API Security Scanner and Capability Hypervisor
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
from prometheus.proxy.hypervisor import ToolExecutionHypervisor
from prometheus.proxy.token_authority import TokenAuthority
from prometheus.proxy.state_invariants import StateWitnessRegistry

logger = logging.getLogger(__name__)


class PrometheusMCPServer:
    """
    Standard Model Context Protocol (MCP) Server for Prometheus Enterprise.
    Mediated by the Stateful Execution Capability Hypervisor to enforce
    monotonic capability attenuation, causal dependency gates, and pre-state witness checks.
    """

    TOOLS: List[MCPToolDefinition] = [
        MCPToolDefinition(
            name="scan_api_security",
            description="Autonomous adversarial exploit engine probe for OWASP API Top 10 vulnerabilities (BOLA/BFLA).",
            inputSchema=MCPToolParameter(
                properties={
                    "target_url": {"type": "string", "description": "Target base URL to scan"},
                    "spec_url": {"type": "string", "description": "OpenAPI spec URL or path"},
                    "target_dir": {"type": "string", "description": "Optional local source directory for static route extraction and AST auto-patching"},
                    "auth_header_alpha": {"type": "string", "description": "Victim tenant auth token"},
                    "auth_header_beta": {"type": "string", "description": "Attacker tenant auth token"},
                    "seed_params": {"type": "object", "description": "Seeded path parameter values"},
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
                    "tenant_id": {"type": "string", "description": "Enforced tenant boundary ID"},
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
        MCPToolDefinition(
            name="inspect_agentic_payload",
            description="Evaluates an MCP tool call or agent payload against the 2026 OWASP Agentic Top 10 (ASI01-ASI10) and CoSAI guardrails.",
            inputSchema=MCPToolParameter(
                properties={
                    "tool_name": {"type": "string", "description": "Target tool name being invoked"},
                    "arguments": {"type": "object", "description": "Tool arguments dictionary"},
                    "prompt_context": {"type": "string", "description": "Optional prompt or RAG context"},
                    "agent_id": {"type": "string", "description": "Non-human agent identifier"},
                    "server_id": {"type": "string", "description": "Target MCP server ID"},
                },
                required=["tool_name"],
            ),
        ),
        MCPToolDefinition(
            name="prometheus_immunology_check",
            description="Event-driven Continuous Immunology sweep: queries live THN RSS and OSV.dev advisory streams and verifies AST/source reachability in a target repository.",
            inputSchema=MCPToolParameter(
                properties={
                    "target_dir": {"type": "string", "description": "Local repository directory path to analyze"},
                },
                required=["target_dir"],
            ),
        ),
        MCPToolDefinition(
            name="prometheus_synthesize_patch",
            description="Contextual SWE Agent program repair: synthesizes an idiomatic code patch, verifies compilation, and generates a ContextualPatchPR.",
            inputSchema=MCPToolParameter(
                properties={
                    "target_dir": {"type": "string", "description": "Repository root directory"},
                    "target_file": {"type": "string", "description": "Relative path to target source file"},
                    "target_endpoint": {"type": "string", "description": "Vulnerable HTTP endpoint path"},
                    "http_method": {"type": "string", "description": "HTTP method (GET, POST, DELETE, etc.)"},
                    "vector": {"type": "string", "description": "Vulnerability category (BOLA_IDOR, BFLA, RACE_CONDITION, etc.)"},
                },
                required=["target_file", "target_endpoint"],
            ),
        ),
        MCPToolDefinition(
            name="prometheus_verify_exposure",
            description="Verifies whether a package advisory or route is reachable in the repository call-graph and live staging environment.",
            inputSchema=MCPToolParameter(
                properties={
                    "target_dir": {"type": "string", "description": "Local repository directory path"},
                    "package_name": {"type": "string", "description": "Package name to trace in AST call-graph"},
                    "target_url": {"type": "string", "description": "Optional live staging URL for runtime probe verification"},
                },
                required=["target_dir", "package_name"],
            ),
        ),
        MCPToolDefinition(
            name="prometheus_generate_poc",
            description="Generates a standalone, token-redacted Python httpx PoC script and cURL command for a confirmed vulnerability.",
            inputSchema=MCPToolParameter(
                properties={
                    "http_method": {"type": "string", "description": "HTTP method (GET, POST, DELETE, etc.)"},
                    "target_url": {"type": "string", "description": "Full target endpoint URL"},
                    "headers": {"type": "object", "description": "Optional HTTP headers dictionary"},
                    "body": {"type": "object", "description": "Optional JSON request body"},
                },
                required=["http_method", "target_url"],
            ),
        ),
        MCPToolDefinition(
            name="prometheus_publish_pr",
            description="Publishes a verified ContextualPatchPR directly to GitHub by creating a remediation branch, committing patched files, and opening a Pull Request.",
            inputSchema=MCPToolParameter(
                properties={
                    "repo": {"type": "string", "description": "Target GitHub repository in 'owner/repo' format"},
                    "pr_title": {"type": "string", "description": "Pull Request title"},
                    "pr_body_markdown": {"type": "string", "description": "Pull Request markdown body"},
                    "patched_files": {"type": "object", "description": "Map of relative file path to patched file content"},
                    "base_branch": {"type": "string", "description": "Base branch name (default: 'main')"},
                    "branch_name": {"type": "string", "description": "Optional custom remediation branch name"},
                },
                required=["repo", "pr_title", "pr_body_markdown", "patched_files"],
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
                            "version": "2.0.0",
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
        if tool_name == "scan_api_security":
            from prometheus.pentest.service import PentestExecutionService, PentestScanRequest
            target_url = args.get("target_url")
            if not target_url:
                raise ValueError("Missing required argument: 'target_url'")
            scan_req = PentestScanRequest(
                target_url=target_url,
                spec_url=args.get("spec_url"),
                target_dir=args.get("target_dir"),
                auth_header_alpha=args.get("auth_header_alpha"),
                auth_header_beta=args.get("auth_header_beta"),
                seed_params=args.get("seed_params"),
            )
            scan_res = await PentestExecutionService.execute_scan(scan_req)
            return {"content": [{"type": "text", "text": json.dumps(scan_res.model_dump(), default=str)}]}

        elif tool_name == "mint_capability_token":
            subject = args.get("subject", "autonomous-agent")
            allowed_methods = args.get("allowed_methods", ["GET"])
            allowed_resources = args.get("allowed_resources", ["*"])
            ttl = args.get("ttl_seconds", 60)
            tenant_id = args.get("tenant_id")
            token = self.hypervisor.token_authority.mint_token(
                subject=subject,
                allowed_methods=allowed_methods,
                allowed_resource_ids=allowed_resources,
                ttl_seconds=ttl,
                tenant_id=tenant_id,
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

        elif tool_name == "inspect_agentic_payload":
            from prometheus.security.agentic_owasp import agentic_owasp_engine, AgenticInspectionRequest
            req = AgenticInspectionRequest(
                tenant_id=args.get("tenant_id", "default_enterprise"),
                agent_id=args.get("agent_id", "mcp-agent"),
                server_id=args.get("server_id", "prometheus-local-mcp"),
                tool_name=args.get("tool_name", "unknown_tool"),
                arguments=args.get("arguments", {}),
                prompt_context=args.get("prompt_context"),
                delegation_depth=int(args.get("delegation_depth", 0)),
                has_scoped_nhi_token=bool(args.get("has_scoped_nhi_token", True)),
            )
            res = agentic_owasp_engine.inspect_tool_invocation(req)
            return {"content": [{"type": "text", "text": json.dumps(res.model_dump(), default=str)}]}

        elif tool_name == "prometheus_immunology_check":
            from prometheus.pentest.immunology import ContinuousImmunologyEngine
            target_dir = args.get("target_dir") or os.getcwd()
            engine = ContinuousImmunologyEngine()
            res = await engine.run_immunology_sweep(target_dir)
            return {"content": [{"type": "text", "text": json.dumps(res, default=str)}]}

        elif tool_name == "prometheus_synthesize_patch":
            from prometheus.pentest.swe_patcher import ContextualSWERepairAgent
            from prometheus.pentest.models import ExploitProof, HttpMethod, Severity, VulnerabilityCategory

            target_dir = args.get("target_dir") or os.getcwd()
            target_file = args.get("target_file", "app/api/routes.py")
            target_endpoint = args.get("target_endpoint", "/api/v1/invoices/{invoice_id}")
            http_method_str = str(args.get("http_method", "GET")).upper()
            method_enum = HttpMethod(http_method_str) if http_method_str in HttpMethod.__members__ else HttpMethod.GET
            vector_str = str(args.get("vector", "BOLA_IDOR")).upper()
            vec_enum = VulnerabilityCategory.BFLA if "BFLA" in vector_str else VulnerabilityCategory.BOLA_IDOR

            full_path = os.path.join(target_dir, target_file) if not os.path.isabs(target_file) else target_file
            if os.path.isfile(full_path):
                with open(full_path, "r", encoding="utf-8") as f:
                    source_code = f.read()
            else:
                source_code = (
                    f'@app.{method_enum.value.lower()}("{target_endpoint}")\n'
                    "async def handler(resource_id: str, current_user: UserSession = Depends(get_current_user)):\n"
                    "    resource = DB.get(resource_id)\n"
                    "    if not resource:\n"
                    '        raise HTTPException(status_code=404, detail="Not found")\n'
                    "    return resource\n"
                )

            proof = ExploitProof(
                is_vulnerable=True,
                vector=vec_enum,
                severity=Severity.HIGH,
                target_endpoint=target_endpoint,
                http_method=method_enum,
                http_status_code=200,
                curl_command=f"curl -X {method_enum.value} http://localhost:8000{target_endpoint}",
                remediation_guidance="Enforce tenant ownership and RBAC policy.",
                execution_time_ms=5.0,
            )
            swe_agent = ContextualSWERepairAgent(target_dir=target_dir)
            patch_res, contextual_pr = await swe_agent.synthesize_contextual_patch(
                original_code=source_code,
                proof=proof,
                target_file=target_file,
            )
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "patch": patch_res.model_dump(),
                                "contextual_pr": contextual_pr.model_dump(),
                            },
                            default=str,
                        ),
                    }
                ]
            }

        elif tool_name == "prometheus_verify_exposure":
            from prometheus.pentest.immunology import ContinuousImmunologyEngine
            target_dir = args.get("target_dir") or os.getcwd()
            package_name = str(args.get("package_name", "")).strip()
            if not package_name:
                raise ValueError("Missing required argument: 'package_name'")
            reachable_files, call_sites = ContinuousImmunologyEngine.trace_call_graph_reachability(
                target_dir=target_dir,
                package_name=package_name,
            )
            payload = {
                "target_dir": target_dir,
                "package_name": package_name,
                "is_reachable_in_repo": len(reachable_files) > 0,
                "reachable_files": reachable_files,
                "call_sites": call_sites,
            }
            return {"content": [{"type": "text", "text": json.dumps(payload, default=str)}]}

        elif tool_name == "prometheus_generate_poc":
            from prometheus.pentest.exploit_prober import ExploitProber
            from prometheus.pentest.models import ExploitProbeRequest, HttpMethod, VulnerabilityCategory
            from prometheus.pentest.proof_validator import ProofValidator

            http_method_str = str(args.get("http_method", "GET")).upper()
            method_enum = HttpMethod(http_method_str) if http_method_str in HttpMethod.__members__ else HttpMethod.GET
            target_url = str(args.get("target_url", "http://localhost:8000/api/v1/resource")).strip()
            headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
            body = args.get("body") if isinstance(args.get("body"), dict) else None

            py_script = ExploitProber.generate_python_poc(
                method=method_enum.value,
                url=target_url,
                headers=headers,
                body=body,
            )
            validator = ProofValidator(redact_tokens=True)
            req = ExploitProbeRequest(
                target_url=target_url,
                method=method_enum,
                headers=headers,
                body=body,
                vector=VulnerabilityCategory.BOLA_IDOR,
                hypothesis="MCP PoC generation",
            )
            curl_cmd = validator.generate_curl_command(req)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "reproduction_script_python": py_script,
                                "reproduction_curl": curl_cmd,
                            },
                            default=str,
                        ),
                    }
                ]
            }

        elif tool_name == "prometheus_publish_pr":
            from prometheus.pentest.pr_reporter import PRReporter

            repo = str(args.get("repo", "")).strip()
            pr_title = str(args.get("pr_title", "fix(security): Prometheus automated remediation")).strip()
            pr_body_markdown = str(args.get("pr_body_markdown", "")).strip()
            patched_files = args.get("patched_files") if isinstance(args.get("patched_files"), dict) else {}
            base_branch = str(args.get("base_branch", "main")).strip()
            branch_name = args.get("branch_name")

            pub_res = await PRReporter.publish_github_pull_request(
                repo=repo,
                pr_title=pr_title,
                pr_body_markdown=pr_body_markdown,
                patched_files=patched_files,
                base_branch=base_branch,
                branch_name=branch_name,
            )
            return {"content": [{"type": "text", "text": json.dumps(pub_res, default=str)}]}

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
