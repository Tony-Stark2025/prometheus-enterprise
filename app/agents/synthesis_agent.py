"""
Synthesis & Blocker Agent for Prometheus.
Correlates multi-source operational telemetry to identify root-cause delivery bottlenecks.
Uses Gemini 3.7 Flash Reasoning Engine on Vertex AI with deterministic heuristic fallback.
"""

from typing import List, Dict, Any, Optional
import json
import logging
from prometheus.config import settings
from prometheus.memory.state_store import state_store, BlockerRecord
from prometheus.llm.gemini_pool import gemini_engine, gemini_pool

logger = logging.getLogger(__name__)


class SynthesisAgent:
    """
    Sub-agent 5: Synthesis & Blocker Agent
    Correlates Git PR latency, Jira dependency graphs, and Slack discussions to pinpoint delivery blockers.
    """

    name: str = "SynthesisAndBlockerAgent"
    role: str = "Multi-Domain Telemetry Correlation & Root Cause Analysis"

    @classmethod
    async def synthesize(
        cls,
        git_telemetry: Dict[str, Any],
        jira_telemetry: Dict[str, Any],
        slack_telemetry: Dict[str, Any],
    ) -> List[BlockerRecord]:
        """
        Synthesizes telemetry across sub-agents and generates persistent blocker records.
        """
        blockers: List[BlockerRecord] = []

        stale_prs = git_telemetry.get("stale_prs", [])
        ci_failures = git_telemetry.get("ci_failures", [])
        blocked_issues = jira_telemetry.get("blocked_issues", [])
        messages = slack_telemetry.get("messages", [])

        # Construct normalized telemetry payload
        telemetry_payload = {
            "stale_prs": stale_prs,
            "ci_failures": ci_failures,
            "blocked_issues": blocked_issues,
            "messages": messages,
        }
        cache_key = json.dumps(telemetry_payload, sort_keys=True, default=str)

        prompt = f"""
You are the Prometheus Synthesis & Blocker Agent.
Analyze the following multi-domain engineering telemetry and identify root-cause delivery bottlenecks:

Git Telemetry:
Stale PRs: {json.dumps(stale_prs, default=str)}
CI Failures: {json.dumps(ci_failures, default=str)}

Jira Telemetry:
Blocked Issues: {json.dumps(blocked_issues, default=str)}

Slack Telemetry:
Messages: {json.dumps(messages, default=str)}

Return a JSON array of objects with the following schema:
[
  {{
    "blocker_id": "BLK-01",
    "title": "Concise summary of bottleneck",
    "description": "In-depth root cause and correlation details across Git, Jira, and Slack",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "source_artifacts": ["PR-402", "PROJ-108", "MSG-901"],
    "impacted_squads": ["engineering", "platform"]
  }}
]
"""

        # Invocate Gemini 3.7 Flash on Vertex AI / Agent Platform
        pool_result = await gemini_engine.generate_structured_synthesis(
            prompt=prompt,
            cache_key=cache_key,
        )

        if pool_result and isinstance(pool_result, list):
            for item in pool_result:
                rec = BlockerRecord(
                    blocker_id=item.get("blocker_id", f"BLK-{len(blockers)+1:02d}"),
                    title=item.get("title", "Detected Blocker"),
                    description=item.get("description", ""),
                    severity=item.get("severity", "HIGH"),
                    source_artifacts=item.get("source_artifacts", []),
                    impacted_squads=item.get("impacted_squads", ["engineering"]),
                    metadata={"engine": "gemini_37_vertex"},
                )
                await state_store.save_blocker(rec)
                blockers.append(rec)
            return blockers

        # Deterministic Heuristic Correlation Engine (Zero-dependency & offline reliable)
        logger.info("⚡ [SynthesisAgent] Executing deterministic heuristic correlation engine...")
        for pr in stale_prs:
            pr_id = pr.get("id")
            blocking = pr.get("blocking_downstream", [])

            related_jira = [
                issue for issue in blocked_issues
                if pr_id in issue.get("blocked_by", []) or issue.get("key") in blocking
            ]

            pr_num = pr_id.replace("PR-", "")
            related_slack = [
                m for m in messages
                if pr_id in m.get("text", "")
                or f"#{pr_num}" in m.get("text", "")
                or f"PR #{pr_num}" in m.get("text", "")
                or any(j["key"] in m.get("text", "") for j in related_jira)
            ]

            artifacts = [pr_id] + [j["key"] for j in related_jira] + [s["id"] for s in related_slack]

            description = (
                f"PR {pr_id} ('{pr.get('title')}') has been waiting for review for {pr.get('review_latency_hours')} hours "
                f"from reviewer(s) {', '.join(pr.get('reviewers', []))}. "
            )
            if related_jira:
                description += f"It is directly blocking high-priority Jira Epic(s): {', '.join([j['key'] for j in related_jira])}. "
            if ci_failures:
                description += f"Downstream CI pipeline is also failing due to interface mismatch with unmerged changes."

            blocker = BlockerRecord(
                blocker_id=f"BLK-{len(blockers)+1:02d}",
                title=f"Stale PR {pr_id} blocking Epic {related_jira[0]['key'] if related_jira else 'Delivery'}",
                description=description,
                severity="CRITICAL" if related_jira else "HIGH",
                source_artifacts=artifacts,
                impacted_squads=pr.get("scopes", ["engineering"]),
                metadata={"engine": "heuristic_correlation"},
            )
            await state_store.save_blocker(blocker)
            blockers.append(blocker)

        return blockers
