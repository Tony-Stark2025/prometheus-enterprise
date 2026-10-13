"""
Git & CI/CD Ingestion Agent for Prometheus.
Scans PR review latency, stale branches (>48h unreviewed), and build failures across GitHub/GitLab.
"""

from typing import List, Dict, Any, Optional
from prometheus.config import settings
from prometheus.tools.github_tools import GitHubTools
from prometheus.security.abac_guard import ABACGuard, UserContext
from prometheus.mcp.client import mcp_client


class GitAgent:
    """
    Sub-agent 2: Git & CI/CD Ingestion Agent
    Collects objective code delivery artifacts, PR wait times, and CI health metrics.
    """

    name: str = "GitAndCIngestionAgent"
    role: str = "Code Telemetry & Pipeline Health Ingestion"

    @classmethod
    async def collect_telemetry(
        cls,
        user: UserContext,
        stale_threshold_hours: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Gathers PRs and CI status filtered by user org scope.
        """
        threshold = stale_threshold_hours if stale_threshold_hours is not None else float(settings.stale_pr_hours_threshold)
        if settings.mcp_enabled:
            all_prs = await mcp_client.fetch_github_telemetry()
        else:
            all_prs = await GitHubTools.get_open_pull_requests()
        # Enforce ABAC scope pre-filtering
        scoped_prs = ABACGuard.filter_resources(user, all_prs)

        # Identify stale PRs
        stale_prs = [
            pr for pr in scoped_prs
            if pr.get("review_latency_hours", 0) >= threshold
            and pr.get("review_status") == "WAITING_REVIEW"
        ]

        all_ci_failures = await GitHubTools.get_ci_pipeline_failures()
        scoped_ci_failures = ABACGuard.filter_resources(user, all_ci_failures)

        return {
            "agent": cls.name,
            "total_open_prs": len(scoped_prs),
            "stale_prs": stale_prs,
            "ci_failures": scoped_ci_failures,
            "all_prs": scoped_prs,
        }
