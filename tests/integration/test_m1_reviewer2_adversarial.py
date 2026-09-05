"""
Adversarial & Stress Verification Suite by Reviewer 2 for Milestone M1.
Tests deep edge cases:
- Missing/invalid/empty tokens in config
- Rate limiting (429, retry-after, 403 secondary limits, ratelimited error strings)
- Network errors & timeouts
- Live parsing simulations across GitHub, Jira, and Slack
- ADF description parsing in Jira
- HITL draft and idempotent approval lifecycle
- Namespace parity between prometheus.* and app.*
"""

import asyncio
import pytest
import httpx
from unittest.mock import patch, MagicMock

from prometheus.config import Settings
from prometheus.tools.github_tools import GitHubTools
from prometheus.tools.jira_tools import JiraTools
from prometheus.tools.slack_tools import SlackTools
from prometheus.memory.state_store import state_store, DraftStatus, ActionDraftRecord

from app.tools.github_tools import GitHubTools as AppGH
from app.tools.jira_tools import JiraTools as AppJira
from app.tools.slack_tools import SlackTools as AppSlack


@pytest.mark.asyncio
async def test_config_resilient_parsing_and_normalization():
    """Verify config handles whitespace, JSON strings, and empty strings safely."""
    s = Settings(
        github_repos="org/repo1, org/repo2",
        slack_channels='["general", "alerts"]',
        github_token="   ",
        jira_api_token="",
        jira_instance_url="   ",
        jira_user_email="   ",
        slack_bot_token="",
    )
    assert s.github_repos == ["org/repo1", "org/repo2"]
    assert s.slack_channels == ["general", "alerts"]
    assert s.github_token is None
    assert s.jira_api_token is None
    assert s.jira_instance_url is None
    assert s.jira_user_email is None
    assert s.slack_bot_token is None


@pytest.mark.asyncio
async def test_github_adversarial_matrix():
    """Adversarially test GitHub tool under token states, rate limits, network errors, and live responses."""
    # 1. Unauthenticated fallback
    with patch("prometheus.config.settings.github_token", None):
        prs = await GitHubTools.get_open_pull_requests()
        assert len(prs) == len(GitHubTools.MOCK_PRS)
        ci = await GitHubTools.get_ci_pipeline_failures()
        assert len(ci) == 1

    # 2. HTTP 429 Rate limit
    with patch("prometheus.config.settings.github_token", "mock_token"):
        with patch("httpx.AsyncClient.get", return_value=httpx.Response(429, headers={"Retry-After": "60"})):
            prs = await GitHubTools.get_open_pull_requests()
            assert len(prs) == len(GitHubTools.MOCK_PRS)
            ci = await GitHubTools.get_ci_pipeline_failures()
            assert len(ci) == 1

    # 3. Secondary Rate limit 403 / remaining == 0
    with patch("prometheus.config.settings.github_token", "mock_token"):
        with patch("httpx.AsyncClient.get", return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "0"})):
            prs = await GitHubTools.get_open_pull_requests()
            assert len(prs) == len(GitHubTools.MOCK_PRS)

    # 4. Network exception / timeout
    with patch("prometheus.config.settings.github_token", "mock_token"):
        with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectTimeout("Connection timeout")):
            prs = await GitHubTools.get_open_pull_requests()
            assert len(prs) == len(GitHubTools.MOCK_PRS)
            ci = await GitHubTools.get_ci_pipeline_failures()
            assert len(ci) == 1

    # 5. Live parsing simulation with standard PR-### and PROJ-### tags
    mock_live_pulls = [
        {
            "number": 101,
            "title": "refactor: update auth schema PR-402",
            "user": {"login": "dev-bob"},
            "created_at": "2026-08-25T12:00:00Z",
            "updated_at": "2026-08-26T12:00:00Z",
            "requested_reviewers": [{"login": "dev-alice"}],
            "head": {"sha": "abcdef123456"},
            "labels": [{"name": "security"}],
            "body": "Fixes PROJ-108 and blocks PR-415",
        }
    ]
    with patch("prometheus.config.settings.github_token", "valid_token"):
        with patch("httpx.AsyncClient.get") as mock_get:
            def side_effect_func(url, **kwargs):
                url_str = str(url)
                if "pulls?state=open" in url_str:
                    return httpx.Response(200, json=mock_live_pulls)
                elif "reviews" in url_str:
                    return httpx.Response(200, json=[{"user": {"login": "dev-alice"}, "state": "CHANGES_REQUESTED"}])
                elif "check-runs" in url_str:
                    return httpx.Response(200, json={"check_runs": [{"conclusion": "failure"}]})
                return httpx.Response(404)

            mock_get.side_effect = side_effect_func
            live_prs = await GitHubTools.get_open_pull_requests(repos=["myorg/auth-service"])
            assert len(live_prs) == 1
            assert live_prs[0]["id"] == "PR-101"
            assert live_prs[0]["review_status"] == "CHANGES_REQUESTED"
            assert live_prs[0]["ci_status"] == "FAILED"
            assert "PR-402" in live_prs[0]["blocking_downstream"]
            assert "PROJ-108" in live_prs[0]["blocking_downstream"]
            assert "PR-415" in live_prs[0]["blocking_downstream"]
            assert "security" in live_prs[0]["scopes"]


@pytest.mark.asyncio
async def test_jira_adversarial_matrix():
    """Adversarially test Jira tool under missing creds, 429s, ADF doc formats, and link types."""
    # 1. Unauthenticated fallback
    with patch("prometheus.config.settings.jira_instance_url", None):
        issues = await JiraTools.get_sprint_issues()
        assert len(issues) == len(JiraTools.MOCK_ISSUES)
        blocked = await JiraTools.get_blocked_issues()
        assert len(blocked) >= 1

    # 2. Basic Auth vs Bearer header generation
    with patch("prometheus.config.settings.jira_instance_url", "https://jira.acme.com"):
        with patch("prometheus.config.settings.jira_user_email", "user@acme.com"):
            with patch("prometheus.config.settings.jira_api_token", "secret_token"):
                headers = JiraTools._get_auth_headers()
                assert "Authorization" in headers
                assert headers["Authorization"].startswith("Basic ")

        with patch("prometheus.config.settings.jira_user_email", None):
            with patch("prometheus.config.settings.jira_api_token", "bearer_token"):
                headers2 = JiraTools._get_auth_headers()
                assert headers2["Authorization"] == "Bearer bearer_token"

    # 3. HTTP 429 Rate Limit
    with patch("prometheus.config.settings.jira_instance_url", "https://jira.acme.com"):
        with patch("prometheus.config.settings.jira_api_token", "secret_token"):
            with patch("httpx.AsyncClient.get", return_value=httpx.Response(429, headers={"Retry-After": "30"})):
                issues = await JiraTools.get_sprint_issues()
                assert len(issues) == len(JiraTools.MOCK_ISSUES)

    # 4. Live parsing simulation with ADF description and issue links
    mock_jira_issues = {
        "issues": [
            {
                "key": "PROJ-500",
                "fields": {
                    "summary": "Migrate OAuth token service",
                    "issuetype": {"name": "Epic"},
                    "status": {"name": "Blocked on Review"},
                    "priority": {"name": "Highest"},
                    "sprint": {"name": "Sprint 30 - Auth"},
                    "assignee": {"displayName": "Alice Lead"},
                    "reporter": {"displayName": "Bob Product"},
                    "description": {"type": "doc", "content": [{"text": "Waiting on PR-101 and PR-102"}]},
                    "issuelinks": [
                        {
                            "type": {"inward": "is blocked by", "outward": "blocks"},
                            "inwardIssue": {"key": "PROJ-499", "fields": {"summary": "Base DB Migration"}},
                        }
                    ],
                    "labels": ["security", "finance"],
                    "duedate": "2026-09-01",
                },
            }
        ]
    }
    with patch("prometheus.config.settings.jira_instance_url", "https://jira.acme.com"):
        with patch("prometheus.config.settings.jira_api_token", "secret_token"):
            with patch("httpx.AsyncClient.get", return_value=httpx.Response(200, json=mock_jira_issues)):
                live_issues = await JiraTools.get_sprint_issues()
                assert len(live_issues) == 1
                assert live_issues[0]["key"] == "PROJ-500"
                assert live_issues[0]["status"] == "BLOCKED"
                assert "PROJ-499" in live_issues[0]["blocked_by"]
                assert "PR-101" in live_issues[0]["blocked_by"]
                assert "PR-102" in live_issues[0]["blocked_by"]
                assert "security" in live_issues[0]["scopes"]
                assert "finance" in live_issues[0]["scopes"]


@pytest.mark.asyncio
async def test_slack_adversarial_matrix():
    """Adversarially test Slack tool under token absence, rate limits, user resolution, and action dispatch."""
    await state_store.init_db()

    # 1. Unauthenticated fallback
    with patch("prometheus.config.settings.slack_bot_token", None):
        msgs = await SlackTools.get_recent_channel_messages()
        assert len(msgs) == len(SlackTools.MOCK_MESSAGES)

    # 2. Rate limit fallback
    with patch("prometheus.config.settings.slack_bot_token", "xox" + "b-token"):
        with patch("httpx.AsyncClient.get", return_value=httpx.Response(429)):
            msgs = await SlackTools.get_recent_channel_messages()
            assert len(msgs) == len(SlackTools.MOCK_MESSAGES)
        with patch("httpx.AsyncClient.get", return_value=httpx.Response(200, json={"ok": False, "error": "ratelimited"})):
            msgs = await SlackTools.get_recent_channel_messages()
            assert len(msgs) == len(SlackTools.MOCK_MESSAGES)

    # 3. Action Drafting & Idempotent Approval
    draft = await SlackTools.draft_action_card(
        target="@alex-lead",
        action_type="slack_dm",
        content="Please review PR #402",
        context_blocker_id="BLK-01",
    )
    assert draft.status == DraftStatus.PENDING

    with patch("prometheus.config.settings.slack_bot_token", None):
        res1 = await SlackTools.dispatch_approved_action(draft.draft_id, "admin-user")
        assert res1["status"] == "success"
        res2 = await SlackTools.dispatch_approved_action(draft.draft_id, "admin-user")
        assert res2["status"] == "already_executed"

    # 4. Live Slack dispatch with Block Kit & channel resolution
    draft_live = await SlackTools.draft_action_card(
        target="#platform-engineering",
        action_type="slack_channel_alert",
        content="Alert for platform team",
    )
    with patch("prometheus.config.settings.slack_bot_token", "xox" + "b-test"):
        with patch("httpx.AsyncClient.get", return_value=httpx.Response(200, json={"ok": True, "channels": [{"name": "platform-engineering", "id": "C12345"}]})):
            with patch("httpx.AsyncClient.post", return_value=httpx.Response(200, json={"ok": True, "ts": "1690000000.1234"})):
                live_dispatch = await SlackTools.dispatch_approved_action(draft_live.draft_id, "approver")
                assert live_dispatch["status"] == "success"


@pytest.mark.asyncio
async def test_app_and_prometheus_namespace_parity():
    """Verify both app.tools and prometheus.tools operate identically without circular import issues."""
    with patch("app.config.settings.github_token", None), patch("prometheus.config.settings.github_token", None):
        app_prs = await AppGH.get_open_pull_requests()
        prom_prs = await GitHubTools.get_open_pull_requests()
        assert len(app_prs) == len(prom_prs)
        assert len(app_prs) >= 3

    with patch("app.config.settings.jira_instance_url", None), patch("prometheus.config.settings.jira_instance_url", None):
        app_issues = await AppJira.get_sprint_issues()
        prom_issues = await JiraTools.get_sprint_issues()
        assert len(app_issues) == len(prom_issues)
        assert len(app_issues) >= 3

    with patch("app.config.settings.slack_bot_token", None), patch("prometheus.config.settings.slack_bot_token", None):
        app_msgs = await AppSlack.get_recent_channel_messages()
        prom_msgs = await SlackTools.get_recent_channel_messages()
        assert len(app_msgs) == len(prom_msgs)
        assert len(app_msgs) >= 3
