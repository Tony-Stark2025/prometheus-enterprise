"""
Synthesis & Blocker Agent for Prometheus.
Correlates multi-source operational telemetry to identify root-cause delivery bottlenecks.
Uses Gemini 3.7 Flash Reasoning Engine on Vertex AI with deterministic heuristic fallback.
"""

from typing import List, Dict, Any, Optional
import hashlib
import json
import logging
from prometheus.config import settings
from prometheus.memory.state_store import state_store, BlockerRecord
from prometheus.llm.gemini_pool import gemini_engine, gemini_pool
from prometheus.security.guardrails import GuardrailService

logger = logging.getLogger(__name__)


class SynthesisAgent:
    """
    Sub-agent 5: Synthesis & Blocker Agent
    Correlates Git PR latency, Jira dependency graphs, and Slack discussions to pinpoint delivery blockers.
    """

    name: str = "SynthesisAndBlockerAgent"
    role: str = "Multi-Domain Telemetry Correlation & Root Cause Analysis"

    @staticmethod
    def _sanitize_telemetry_items(items: List[Dict[str, Any]], text_fields: List[str]) -> List[Dict[str, Any]]:
        sanitized_list: List[Dict[str, Any]] = []
        for item in items:
            clean_item = dict(item)
            for field in text_fields:
                val = clean_item.get(field)
                if isinstance(val, str) and val:
                    res = GuardrailService.sanitize(val)
                    clean_item[field] = res.sanitized_text if res.is_safe else "[REDACTED_UNSAFE_TELEMETRY]"
            sanitized_list.append(clean_item)
        return sanitized_list

    @staticmethod
    def _deterministic_blocker_id(artifacts: List[str], fallback_idx: int) -> str:
        if not artifacts:
            return f"BLK-{fallback_idx:02d}"
        digest = hashlib.sha256("|".join(sorted(set(artifacts))).encode("utf-8")).hexdigest()[:8].upper()
        return f"BLK-{digest}"

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

        stale_prs = cls._sanitize_telemetry_items(
            git_telemetry.get("stale_prs", []), ["title", "body"]
        )
        ci_failures = cls._sanitize_telemetry_items(
            git_telemetry.get("ci_failures", []), ["error_summary", "failed_step"]
        )
        blocked_issues = cls._sanitize_telemetry_items(
            jira_telemetry.get("blocked_issues", []), ["summary", "blocker_reason"]
        )
        messages = cls._sanitize_telemetry_items(
            slack_telemetry.get("messages", []), ["text", "content"]
        )

        if not stale_prs and not ci_failures and not blocked_issues:
            return []

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

        # Invoke Gemini on Vertex AI / Agent Platform
        pool_result = await gemini_engine.generate_structured_synthesis(
            prompt=prompt,
            cache_key=cache_key,
        )

        raw_items = None
        if isinstance(pool_result, list):
            raw_items = pool_result
        elif isinstance(pool_result, dict):
            raw_items = pool_result.get("items") or pool_result.get("blockers")

        if raw_items and isinstance(raw_items, list):
            for item in raw_items:
                artifacts = item.get("source_artifacts", [])
                rec = BlockerRecord(
                    blocker_id=item.get("blocker_id") or cls._deterministic_blocker_id(artifacts, len(blockers) + 1),
                    title=item.get("title", "Detected Blocker"),
                    description=item.get("description", ""),
                    severity=item.get("severity", "HIGH"),
                    source_artifacts=artifacts,
                    impacted_squads=item.get("impacted_squads", ["engineering"]),
                    metadata={"engine": "gemini_vertex"},
                )
                await state_store.save_blocker(rec)
                blockers.append(rec)
            return blockers

        # Deterministic Graph Correlation Engine over actual ingested telemetry
        logger.info("⚡ [SynthesisAgent] Executing deterministic graph correlation engine...")
        correlated_jira_keys = set()

        for pr in stale_prs:
            pr_id = pr.get("id", "PR-UNKNOWN")
            blocking = pr.get("blocking_downstream", [])
            reviewers = pr.get("reviewers", [])

            related_jira = [
                issue for issue in blocked_issues
                if pr_id in issue.get("blocked_by", []) or issue.get("key") in blocking
            ]
            for j in related_jira:
                correlated_jira_keys.add(j.get("key"))

            pr_num = pr_id.replace("PR-", "")
            related_slack = [
                m for m in messages
                if pr_id in m.get("text", "")
                or f"#{pr_num}" in m.get("text", "")
                or f"PR #{pr_num}" in m.get("text", "")
                or any(j.get("key", "") in m.get("text", "") for j in related_jira)
            ]

            artifacts = [pr_id] + [j["key"] for j in related_jira] + [s["id"] for s in related_slack]
            description = (
                f"PR {pr_id} ('{pr.get('title')}') has been waiting for review for {pr.get('review_latency_hours')} hours "
                f"from reviewer(s) {', '.join(reviewers)}. "
            )
            if related_jira:
                description += f"It is directly blocking high-priority Jira Epic(s): {', '.join([j['key'] for j in related_jira])}. "
            if ci_failures:
                description += "Downstream CI pipeline is also failing due to interface mismatch with unmerged changes."

            blocker = BlockerRecord(
                blocker_id=cls._deterministic_blocker_id(artifacts, len(blockers) + 1),
                title=f"Stale PR {pr_id} blocking Epic {related_jira[0]['key'] if related_jira else 'Delivery'}",
                description=description,
                severity="CRITICAL" if related_jira else "HIGH",
                source_artifacts=artifacts,
                impacted_squads=pr.get("scopes", ["engineering"]),
                metadata={
                    "engine": "deterministic_graph_correlation",
                    "reviewers": reviewers,
                    "pr_id": pr_id,
                    "channel": related_slack[0].get("channel") if related_slack else None,
                },
            )
            await state_store.save_blocker(blocker)
            blockers.append(blocker)

        for issue in blocked_issues:
            key = issue.get("key")
            if key in correlated_jira_keys:
                continue
            artifacts = [key] + issue.get("blocked_by", [])
            blocker = BlockerRecord(
                blocker_id=cls._deterministic_blocker_id(artifacts, len(blockers) + 1),
                title=f"Blocked Issue {key}: {issue.get('summary', '')}",
                description=issue.get("blocker_reason") or f"Issue {key} is blocked by {', '.join(issue.get('blocked_by', []))}.",
                severity="CRITICAL" if issue.get("priority") in ("Highest", "Critical") else "HIGH",
                source_artifacts=artifacts,
                impacted_squads=issue.get("scopes", ["engineering"]),
                metadata={
                    "engine": "deterministic_graph_correlation",
                    "assignee": issue.get("assignee"),
                },
            )
            await state_store.save_blocker(blocker)
            blockers.append(blocker)

        return blockers
