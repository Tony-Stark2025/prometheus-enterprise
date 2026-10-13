"""
Tier 2 Integration Tests: Jira Cloud Live REST API Client & Blocker Telemetry Ingestion
Validates sprint issue queries, epic dependency graphs, blocker parsing, rate limiting, and auth handling.
"""

import pytest
import base64
from unittest.mock import patch, AsyncMock
import httpx
from prometheus.tools.jira_tools import JiraTools
from prometheus.config import settings


@pytest.mark.integration
class TestJiraClient:
    @pytest.mark.asyncio
    async def test_jira_get_sprint_issues_structure(self):
        """Validates normalized dictionary schema for Jira sprint issues."""
        issues = await JiraTools.get_sprint_issues()
        assert isinstance(issues, list)
        assert len(issues) > 0

        for issue in issues:
            assert "key" in issue
            assert "summary" in issue
            assert "type" in issue
            assert "status" in issue
            assert "priority" in issue
            assert "sprint" in issue
            assert "assignee" in issue
            assert "reporter" in issue
            assert "blocked_by" in issue
            assert isinstance(issue["blocked_by"], list)
            assert "scopes" in issue
            assert isinstance(issue["scopes"], list)
            assert "target_release_date" in issue

    @pytest.mark.asyncio
    async def test_jira_scope_filtering(self):
        """Validates organizational scope filtering on Jira issues."""
        eng_issues = await JiraTools.get_sprint_issues(scopes=["engineering"])
        assert len(eng_issues) > 0
        assert all(any(s in issue.get("scopes", []) for s in ["engineering"]) for issue in eng_issues)

        finance_issues = await JiraTools.get_sprint_issues(scopes=["finance"])
        assert len(finance_issues) > 0
        assert all("finance" in issue.get("scopes", []) for issue in finance_issues)

        unmatched = await JiraTools.get_sprint_issues(scopes=["nonexistent_department"])
        assert len(unmatched) == 0

    @pytest.mark.asyncio
    async def test_jira_blocked_issues_filtering(self):
        """Validates filtering of blocked issues and dependency chain extraction."""
        blocked = await JiraTools.get_blocked_issues()
        assert isinstance(blocked, list)
        assert len(blocked) >= 1

        for issue in blocked:
            assert issue["status"] == "BLOCKED" or len(issue["blocked_by"]) > 0

        proj_108 = next((i for i in blocked if i["key"] == "PROJ-108"), None)
        assert proj_108 is not None
        assert "PR-402" in proj_108["blocked_by"]
        assert proj_108["priority"] == "Highest"

    def test_jira_parse_blockers_and_dependencies_with_issuelinks(self):
        """Validates parsing of Jira issuelinks (blocked by, depends on) and cross-domain PR references."""
        issue_data = {
            "key": "PROJ-200",
            "fields": {
                "summary": "Gateway Auth v2.1 Rollout blocked by PR-402 and #415",
                "description": "Waiting on auth-service PR-402 and database migration PROJ-101",
                "status": {"name": "BLOCKED"},
                "issuelinks": [
                    {
                        "type": {"inward": "is blocked by", "outward": "blocks"},
                        "inwardIssue": {
                            "key": "SEC-55",
                            "fields": {"summary": "Security Audit Approval"},
                        },
                    },
                    {
                        "type": {"inward": "depends on", "outward": "is depended on by"},
                        "inwardIssue": {
                            "key": "INFRA-88",
                            "fields": {"summary": "Redis Cluster Provisioning"},
                        },
                    },
                ],
            },
        }
        blocked_by, reason = JiraTools._parse_blockers_and_dependencies(issue_data)
        assert "SEC-55" in blocked_by
        assert "INFRA-88" in blocked_by
        assert "PR-402" in blocked_by
        assert "PR-415" in blocked_by
        assert "PROJ-101" in blocked_by
        assert reason is not None
        assert "SEC-55" in reason

    def test_jira_parse_adf_description(self):
        """Validates extraction of text and PR references from Atlassian Document Format (ADF) description dict."""
        issue_data = {
            "key": "PROJ-300",
            "fields": {
                "summary": "ADF Description Test",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "This task is blocked by PR-999 and PROJ-888."}
                            ],
                        }
                    ],
                },
                "status": {"name": "In Progress"},
                "issuelinks": [],
            },
        }
        blocked_by, _ = JiraTools._parse_blockers_and_dependencies(issue_data)
        assert "PR-999" in blocked_by
        assert "PROJ-888" in blocked_by

    def test_jira_auth_headers_generation(self):
        """Validates Basic auth header generation with email and API token."""
        with patch.object(settings, "jira_user_email", "lead@company.com"), \
             patch.object(settings, "jira_api_token", "secret-token-123"):
            headers = JiraTools._get_auth_headers()
            assert "Authorization" in headers
            expected_b64 = base64.b64encode(b"lead@company.com:secret-token-123").decode("utf-8")
            assert headers["Authorization"] == f"Basic {expected_b64}"

    def test_jira_scope_inference(self):
        """Validates scope inference based on labels, project key, and summary."""
        scopes_sec = JiraTools._infer_scopes(["security-review"], "SEC-10", "OAuth token leak")
        assert "security" in scopes_sec

        scopes_fin = JiraTools._infer_scopes(["billing"], "BILL-01", "VAT rounding bug")
        assert "finance" in scopes_fin

        scopes_plat = JiraTools._infer_scopes([], "PROJ-01", "Kubernetes cluster upgrade")
        assert "platform" in scopes_plat

    @pytest.mark.asyncio
    async def test_jira_live_api_mock_response_parsing(self):
        """Tests live API parsing when Jira returns valid search results via mock client."""
        mock_jira_payload = {
            "total": 1,
            "issues": [
                {
                    "key": "LIVE-101",
                    "fields": {
                        "summary": "Live Jira Test Blocker",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "BLOCKED"},
                        "priority": {"name": "Highest"},
                        "sprint": {"name": "Sprint 42"},
                        "assignee": {"displayName": "Sarah Connor"},
                        "reporter": {"displayName": "John Connor"},
                        "issuelinks": [],
                        "duedate": "2026-09-01",
                        "labels": ["platform"],
                        "description": "Waiting on PR-1001 to resolve build failure",
                    },
                }
            ],
        }

        mock_resp = httpx.Response(
            status_code=200,
            json=mock_jira_payload,
            request=httpx.Request("GET", "https://mock-jira.atlassian.net/rest/api/3/search"),
        )

        with patch.object(settings, "jira_instance_url", "https://mock-jira.atlassian.net"), \
             patch.object(settings, "jira_api_token", "mock-token"), \
             patch.object(settings, "jira_user_email", "user@test.com"), \
             patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
            issues = await JiraTools.get_sprint_issues()
            assert len(issues) == 1
            assert issues[0]["key"] == "LIVE-101"
            assert issues[0]["status"] == "BLOCKED"
            assert "PR-1001" in issues[0]["blocked_by"]
            assert issues[0]["assignee"] == "Sarah Connor"

    @pytest.mark.asyncio
    async def test_jira_rate_limit_429_handling(self):
        """Tests rate limit (HTTP 429) handling returns an empty list cleanly without crashing."""
        mock_resp = httpx.Response(
            status_code=429,
            headers={"Retry-After": "30"},
            request=httpx.Request("GET", "https://mock-jira.atlassian.net/rest/api/3/search"),
        )

        with patch.object(settings, "jira_instance_url", "https://mock-jira.atlassian.net"), \
             patch.object(settings, "jira_api_token", "mock-token"), \
             patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
            issues = await JiraTools.get_sprint_issues()
            assert issues == []
