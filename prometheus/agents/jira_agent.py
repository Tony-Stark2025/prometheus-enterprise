"""
Project Tracker Agent for Prometheus.
Tracks issue status changes, epic progress, blocked states, and sprint burndown deviations.
"""

from typing import List, Dict, Any, Optional
from prometheus.config import settings
from prometheus.tools.jira_tools import JiraTools
from prometheus.security.abac_guard import ABACGuard, UserContext
from prometheus.mcp.client import mcp_client


class JiraAgent:
    """
    Sub-agent 3: Project Tracker Agent
    Monitors work tracking systems (Jira / Linear) for blocked epics and cross-squad dependencies.
    """

    name: str = "ProjectTrackerAgent"
    role: str = "Issue Status & Dependency Ingestion"

    @classmethod
    async def collect_telemetry(
        cls,
        user: UserContext,
    ) -> Dict[str, Any]:
        """
        Fetches sprint tickets and blocker dependencies filtered by ABAC scope.
        """
        if settings.mcp_enabled:
            all_issues = await mcp_client.fetch_jira_telemetry()
        else:
            all_issues = await JiraTools.get_sprint_issues()
        scoped_issues = ABACGuard.filter_resources(user, all_issues)

        blocked_issues = [
            issue for issue in scoped_issues
            if issue.get("status") == "BLOCKED" or len(issue.get("blocked_by", [])) > 0
        ]

        return {
            "agent": cls.name,
            "total_issues": len(scoped_issues),
            "blocked_issues": blocked_issues,
            "all_issues": scoped_issues,
        }
