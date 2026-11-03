"""
Model Context Protocol (MCP) Ecosystem for Prometheus.
Exposes Prometheus API Security Scanner and Capability Hypervisor firewall controls as MCP tools.
"""

from prometheus.mcp.protocol import (
    JSONRPCRequest,
    JSONRPCResponse,
    MCPToolDefinition,
    MCPCallToolRequest,
    MCPListToolsResponse,
)
from prometheus.mcp.server import PrometheusMCPServer, mcp_server

__all__ = [
    "JSONRPCRequest",
    "JSONRPCResponse",
    "MCPToolDefinition",
    "MCPCallToolRequest",
    "MCPListToolsResponse",
    "PrometheusMCPServer",
    "mcp_server",
]
