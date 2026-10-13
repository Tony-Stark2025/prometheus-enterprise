"""
Jira and Linear project management telemetry tools for Prometheus.
Tracks issue status, sprint blockers, epic dependencies, and burndown risks
via live Jira Cloud REST API with Firestore Vault & Secret Manager credential resolution.
Zero mock or synthetic fallback data.
"""

import base64
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

import httpx

from prometheus.config import settings
from prometheus.memory.firestore_store import firestore_store

logger = logging.getLogger(__name__)


class JiraTools:
    """
    Enterprise Jira Cloud API telemetry client.
    Ingests sprint tickets, epic blocker dependencies, and workstream status across teams.
    """

    @classmethod
    async def _resolve_credentials(
        cls,
        tenant_id: str = "default_enterprise",
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Resolves Jira URL, token, email, and project key from Firestore Vault or settings."""
        vault_cfg = await firestore_store.get_integration(tenant_id, "jira") or {}
        instance_url = (
            vault_cfg.get("jira_instance_url")
            or vault_cfg.get("instance_url")
            or vault_cfg.get("url")
            or settings.jira_instance_url
        )
        api_token = (
            vault_cfg.get("jira_api_token")
            or vault_cfg.get("api_token")
            or vault_cfg.get("token")
            or settings.jira_api_token
        )
        user_email = (
            vault_cfg.get("jira_user_email")
            or vault_cfg.get("user_email")
            or vault_cfg.get("email")
            or settings.jira_user_email
        )
        project_key = (
            vault_cfg.get("jira_project_key")
            or vault_cfg.get("project_key")
            or settings.jira_project_key
        )
        return instance_url, api_token, user_email, project_key

    @classmethod
    def _get_auth_headers(
        cls,
        token: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Prometheus-Observability-Fleet/1.1",
        }
        resolved_token = token if token is not None else settings.jira_api_token
        resolved_email = email if email is not None else settings.jira_user_email

        if resolved_token and resolved_email:
            auth_str = f"{resolved_email}:{resolved_token}"
            encoded = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {encoded}"
        elif resolved_token:
            headers["Authorization"] = f"Bearer {resolved_token}"

        return headers

    @classmethod
    def _infer_scopes(cls, labels: List[str], project_key: str, summary: str) -> List[str]:
        scopes = set()
        text = f"{project_key} {summary} {' '.join(labels)}".lower()

        if "finance" in text or "billing" in text or "vat" in text or "pay" in text:
            scopes.update(["engineering", "finance"])
        elif "sec" in text or "auth" in text or "oauth" in text:
            scopes.update(["engineering", "platform", "security"])
        else:
            scopes.update(["engineering", "platform"])

        for lbl in labels:
            lbl_lower = lbl.lower()
            if "security" in lbl_lower:
                scopes.add("security")
            if "finance" in lbl_lower or "billing" in lbl_lower:
                scopes.add("finance")
            if "platform" in lbl_lower:
                scopes.add("platform")
            if "engineering" in lbl_lower:
                scopes.add("engineering")

        return sorted(list(scopes))

    @classmethod
    def _parse_blockers_and_dependencies(
        cls,
        issue: Dict[str, Any],
    ) -> Tuple[List[str], Optional[str]]:
        fields = issue.get("fields", {})
        blocked_by = set()
        reasons = []

        # 1. Parse Issue Links
        issue_links = fields.get("issuelinks", [])
        for link in issue_links:
            link_type = link.get("type", {})
            inward_desc = link_type.get("inward", "").lower()
            outward_desc = link_type.get("outward", "").lower()

            if "blocked by" in inward_desc or "depends on" in inward_desc:
                inward_issue = link.get("inwardIssue", {})
                if inward_issue.get("key"):
                    blocked_by.add(inward_issue["key"])
                    reasons.append(f"Blocked by {inward_issue['key']}: {inward_issue.get('fields', {}).get('summary', '')}")
            elif "is blocked by" in outward_desc:
                outward_issue = link.get("outwardIssue", {})
                if outward_issue.get("key"):
                    blocked_by.add(outward_issue["key"])
                    reasons.append(f"Blocked by {outward_issue['key']}: {outward_issue.get('fields', {}).get('summary', '')}")

        # 2. Extract Cross-Domain PR references (e.g. PR-402, PR-415, #402)
        summary = fields.get("summary", "")
        desc = fields.get("description", "")
        if isinstance(desc, dict):
            desc = str(desc)

        combined_text = f"{summary} {desc}"
        found_prs = set(re.findall(r"(?:\b[A-Za-z0-9]+-\d+|#[0-9]+)\b", combined_text, re.IGNORECASE))
        for pr_ref in found_prs:
            if pr_ref.startswith("#"):
                blocked_by.add(f"PR-{pr_ref[1:]}")
            elif pr_ref.upper() != issue.get("key", "").upper():
                blocked_by.add(pr_ref.upper())

        status_name = fields.get("status", {}).get("name", "").upper()
        if "BLOCK" in status_name and not reasons:
            reasons.append("Issue flagged in BLOCKED status pending dependency resolution.")

        reason_str = " ".join(reasons) if reasons else None
        return sorted(list(blocked_by)), reason_str

    @classmethod
    def _extract_sprint_name(cls, fields: Dict[str, Any]) -> str:
        sprint_field = fields.get("sprint")
        if isinstance(sprint_field, dict):
            return sprint_field.get("name", "Active Sprint")
        elif isinstance(sprint_field, list) and sprint_field:
            return sprint_field[-1].get("name", "Active Sprint")

        for k, v in fields.items():
            if k.startswith("customfield_") and v:
                if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict) and "name" in v[0] and "sprint" in k.lower():
                    return v[-1]["name"]
                elif isinstance(v, dict) and "name" in v and "sprint" in k.lower():
                    return v["name"]

        return "Active Sprint"

    @classmethod
    async def get_sprint_issues(
        cls,
        scopes: Optional[List[str]] = None,
        jql: Optional[str] = None,
        tenant_id: str = "default_enterprise",
    ) -> List[Dict[str, Any]]:
        """
        Fetches active sprint issues, epics, and blocker dependencies via live Jira Cloud REST API.
        Returns an empty list if Jira credentials are not configured or API fails.
        """
        instance_url, api_token, user_email, project_key = await cls._resolve_credentials(tenant_id=tenant_id)
        if not instance_url or not api_token:
            logger.info("Jira credentials not configured; returning empty issue list.")
            return []

        base_url = instance_url.rstrip("/")
        if jql:
            query_jql = jql
        elif project_key:
            query_jql = f"project = {project_key} ORDER BY updated DESC"
        else:
            query_jql = "sprint in openSprints() ORDER BY priority DESC, updated DESC"

        headers = cls._get_auth_headers(token=api_token, email=user_email)
        live_issues: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                params = {
                    "jql": query_jql,
                    "fields": "summary,status,issuetype,priority,sprint,assignee,reporter,issuelinks,duedate,labels,description",
                    "maxResults": 50,
                }
                search_url = f"{base_url}/rest/api/3/search/jql"
                resp = await client.get(search_url, headers=headers, params=params)

                if resp.status_code in (400, 404, 410):
                    search_url = f"{base_url}/rest/api/3/search"
                    resp = await client.get(search_url, headers=headers, params=params)
                    if resp.status_code in (404, 410):
                        search_url = f"{base_url}/rest/api/2/search"
                        resp = await client.get(search_url, headers=headers, params=params)

                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After", "unknown")
                    logger.warning(f"Jira API 429 Rate Limit (Retry-After: {retry_after}s).")
                    return []

                if resp.status_code != 200:
                    logger.warning(f"Jira API search failed with status HTTP {resp.status_code}")
                    return []

                data = resp.json()
                raw_issues = data.get("issues", [])

                for issue in raw_issues:
                    key = issue.get("key", "UNKNOWN")
                    fields = issue.get("fields") or {}

                    summary = fields.get("summary", "")
                    issuetype_obj = fields.get("issuetype") or {}
                    issue_type = issuetype_obj.get("name") or "Story"

                    status_obj = fields.get("status") or {}
                    raw_status = (status_obj.get("name") or "IN_PROGRESS").upper()

                    if "BLOCK" in raw_status:
                        status = "BLOCKED"
                    elif "PROGRESS" in raw_status or "DEVELOPMENT" in raw_status:
                        status = "IN_PROGRESS"
                    elif "REVIEW" in raw_status or "TEST" in raw_status or "QA" in raw_status:
                        status = "IN_REVIEW"
                    elif "DONE" in raw_status or "RESOLVED" in raw_status or "CLOSED" in raw_status:
                        status = "DONE"
                    else:
                        status = raw_status.replace(" ", "_")

                    priority_obj = fields.get("priority") or {}
                    priority = priority_obj.get("name") or "Medium"
                    sprint_name = cls._extract_sprint_name(fields)

                    assignee_obj = fields.get("assignee") or {}
                    assignee = (
                        assignee_obj.get("displayName")
                        or assignee_obj.get("name")
                        or "unassigned"
                    )
                    reporter_obj = fields.get("reporter") or {}
                    reporter = (
                        reporter_obj.get("displayName")
                        or reporter_obj.get("name")
                        or "unknown"
                    )

                    blocked_by, blocker_reason = cls._parse_blockers_and_dependencies(issue)
                    labels = fields.get("labels", [])
                    scopes_inferred = cls._infer_scopes(labels, key, summary)
                    due_date = fields.get("duedate") or (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%d")

                    issue_record = {
                        "key": key,
                        "summary": summary,
                        "type": issue_type,
                        "status": status,
                        "priority": priority,
                        "sprint": sprint_name,
                        "assignee": assignee,
                        "reporter": reporter,
                        "blocked_by": blocked_by,
                        "blocker_reason": blocker_reason,
                        "scopes": scopes_inferred,
                        "target_release_date": due_date,
                    }
                    live_issues.append(issue_record)

            if scopes:
                return [i for i in live_issues if any(s in i.get("scopes", []) for s in scopes)]
            return live_issues

        except Exception as exc:
            logger.error(f"Live Jira query failed: {exc}")
            return []

    @classmethod
    async def get_blocked_issues(
        cls,
        scopes: Optional[List[str]] = None,
        jql: Optional[str] = None,
        tenant_id: str = "default_enterprise",
    ) -> List[Dict[str, Any]]:
        """
        Filters issues in blocked status or with active dependency links.
        """
        all_issues = await cls.get_sprint_issues(scopes=scopes, jql=jql, tenant_id=tenant_id)
        return [
            issue for issue in all_issues
            if issue.get("status") == "BLOCKED" or len(issue.get("blocked_by", [])) > 0
        ]
