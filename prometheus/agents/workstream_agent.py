"""
Workstream Ingestion Agent for Prometheus.
Synthesizes public workstream chatter (Slack/Teams) to uncover informal blocker mentions.
"""

from typing import List, Dict, Any, Optional
from prometheus.config import settings
from prometheus.tools.slack_tools import SlackTools
from prometheus.security.abac_guard import ABACGuard, UserContext
from prometheus.mcp.client import mcp_client


class WorkstreamAgent:
    """
    Sub-agent 4: Workstream Ingestion Agent
    Captures unstructured team conversation artifacts within authorized channel scopes.
    """

    name: str = "WorkstreamIngestionAgent"
    role: str = "Public Communication & Chat Signal Ingestion"

    @classmethod
    async def collect_telemetry(
        cls,
        user: UserContext,
    ) -> Dict[str, Any]:
        """
        Gathers recent channel discussions filtered by ABAC scope.
        """
        if settings.mcp_enabled:
            all_messages = await mcp_client.fetch_slack_telemetry()
        else:
            all_messages = await SlackTools.get_recent_channel_messages()
        scoped_messages = ABACGuard.filter_resources(user, all_messages)

        return {
            "agent": cls.name,
            "total_messages": len(scoped_messages),
            "messages": scoped_messages,
        }
