"""
Tier 1 Unit Tests: Model Context Protocol (MCP) JSON-RPC 2.0 Schemas & Server
Validates protocol serialization, schemas, tool definitions, and error handling.
"""

import pytest
import json
from prometheus.mcp.protocol import (
    JSONRPCRequest,
    JSONRPCResponse,
    MCPToolParameter,
    MCPToolDefinition,
    MCPListToolsResponse,
)
from prometheus.mcp.server import PrometheusMCPServer


@pytest.fixture
def mcp_server():
    return PrometheusMCPServer()


@pytest.mark.unit
class TestMCPProtocol:
    def test_jsonrpc_request_schema_serialization(self):
        """Validates standard JSON-RPC 2.0 Request structure."""
        req = JSONRPCRequest(
            id="req-123",
            method="tools/call",
            params={"name": "scan_api_security", "arguments": {"target_url": "http://test"}},
        )
        data = req.model_dump()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == "req-123"
        assert data["method"] == "tools/call"
        assert data["params"]["name"] == "scan_api_security"

    def test_jsonrpc_response_schema_serialization(self):
        """Validates JSON-RPC 2.0 Response with result or error."""
        res_success = JSONRPCResponse(id="req-123", result={"status": "ok"})
        assert res_success.model_dump()["result"] == {"status": "ok"}
        assert res_success.model_dump()["error"] is None

        res_err = JSONRPCResponse(id="req-456", error={"code": -32601, "message": "Method not found"})
        assert res_err.model_dump()["error"]["code"] == -32601

    def test_tool_definition_and_list_response_schema(self):
        """Validates MCP Tool definitions and schema models."""
        param = MCPToolParameter(
            properties={"target_url": {"type": "string"}},
            required=["target_url"],
        )
        tool = MCPToolDefinition(
            name="test_tool",
            description="A test tool description",
            inputSchema=param,
        )
        list_resp = MCPListToolsResponse(tools=[tool])
        assert len(list_resp.tools) == 1
        assert list_resp.tools[0].name == "test_tool"
        assert "target_url" in list_resp.tools[0].inputSchema.properties

    @pytest.mark.asyncio
    async def test_mcp_initialize_method(self, mcp_server):
        """Validates MCP initialize handshake message."""
        payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        resp = await mcp_server.handle_jsonrpc(payload)
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert "result" in resp
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert result["serverInfo"]["name"] == "prometheus-mcp-server"
        assert "tools" in result["capabilities"]

    @pytest.mark.asyncio
    async def test_mcp_tools_list_contains_all_security_tools(self, mcp_server):
        """Validates MCP tools/list exposes all required tools."""
        payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        resp = await mcp_server.handle_jsonrpc(payload)
        assert resp["id"] == 2
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        expected_tools = [
            "scan_api_security",
            "mint_capability_token",
            "request_action_permit",
            "verify_action_permit",
        ]
        for expected in expected_tools:
            assert expected in tool_names

    @pytest.mark.asyncio
    async def test_mcp_unknown_method_error_code(self, mcp_server):
        """Validates JSON-RPC -32601 error on unregistered method."""
        payload = {"jsonrpc": "2.0", "id": 99, "method": "unsupported_mcp_call", "params": {}}
        resp = await mcp_server.handle_jsonrpc(payload)
        assert "error" in resp
        assert resp["error"]["code"] == -32601
        assert "Method 'unsupported_mcp_call' not found" in resp["error"]["message"]

    @pytest.mark.asyncio
    async def test_mcp_call_tool_mint_capability_token(self, mcp_server):
        """Validates MCP tools/call for mint_capability_token."""
        payload = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "mint_capability_token",
                "arguments": {"subject": "agent-worker", "ttl_seconds": 60},
            },
        }
        resp = await mcp_server.handle_jsonrpc(payload)
        assert "result" in resp
        assert "content" in resp["result"]
        assert len(resp["result"]["content"]) > 0
        assert resp["result"]["content"][0]["type"] == "text"
        token_data = json.loads(resp["result"]["content"][0]["text"])
        assert token_data["subject"] == "agent-worker"

    @pytest.mark.asyncio
    async def test_mcp_call_tool_request_action_permit(self, mcp_server):
        """Validates MCP tools/call for request_action_permit."""
        token = mcp_server.hypervisor.token_authority.mint_token(
            subject="agent-worker",
            allowed_methods=["tools/call", "PUT", "request_action_permit"],
            allowed_resource_ids=["*"],
            ttl_seconds=60,
        )
        payload = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "request_action_permit",
                "arguments": {
                    "capability_token": token.model_dump(),
                    "target_op": "PUT",
                    "resource_id": "res-invoice-123",
                },
            },
        }
        resp = await mcp_server.handle_jsonrpc(payload)
        assert "result" in resp
        assert "content" in resp["result"]
        permit_data = json.loads(resp["result"]["content"][0]["text"])
        assert permit_data["action_method"] == "PUT"

    @pytest.mark.asyncio
    async def test_mcp_call_unregistered_tool(self, mcp_server):
        """Validates tools/call with unknown tool name returns internal error code -32603."""
        payload = {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "unregistered_tool_xyz", "arguments": {}},
        }
        resp = await mcp_server.handle_jsonrpc(payload)
        assert "error" in resp
        assert resp["error"]["code"] == -32603
        assert "Unknown MCP tool" in resp["error"]["message"]
