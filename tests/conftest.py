"""
Global pytest fixtures for Prometheus Enterprise test suite.
Provides realistic HTTP transport responses for GitHub REST API v3, Jira Cloud REST API v3,
and Slack Web API so integration and workflow tests exercise real client parsing logic
without requiring mock fallbacks in production code.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import httpx
import pytest

from prometheus.config import settings
from prometheus.tools.slack_tools import SlackTools

_REAL_ASYNC_CLIENT_GET = httpx.AsyncClient.get
_REAL_ASYNC_CLIENT_POST = httpx.AsyncClient.post


def _build_github_pulls_payload(repo: str):
    now = datetime.now(timezone.utc)
    t_58h = (now - timedelta(hours=58)).isoformat()
    t_31h = (now - timedelta(hours=31)).isoformat()
    t_14h = (now - timedelta(hours=14)).isoformat()

    if "auth-service" in repo:
        return [
            {
                "number": 402,
                "title": "feat(auth): OAuth2 Token Exchange & Session Refresh PROJ-108",
                "body": "Implements OAuth2 token exchange. Blocks PROJ-108 and PR-405.",
                "user": {"login": "sarah.chen"},
                "created_at": t_58h,
                "updated_at": t_58h,
                "requested_reviewers": [{"login": "david.kim"}, {"login": "elena.lead"}],
                "head": {"sha": "8f9d2a1b3c4d5e6f"},
                "labels": [{"name": "engineering"}, {"name": "security"}, {"name": "platform"}],
            }
        ]
    elif "payment-gateway" in repo:
        return [
            {
                "number": 102,
                "title": "fix(gateway): Idempotency Key Collision on Retry",
                "body": "Fixes retry collision for PROJ-108.",
                "user": {"login": "david.kim"},
                "created_at": t_58h,
                "updated_at": t_31h,
                "requested_reviewers": [{"login": "elena.lead"}],
                "head": {"sha": "3a7b9c1d2e3f4a5b"},
                "labels": [{"name": "engineering"}, {"name": "platform"}],
            }
        ]
    elif "billing-engine" in repo:
        return [
            {
                "number": 415,
                "title": "feat(billing): Multi-Currency VAT Calculation FIN-204",
                "body": "Implements VAT calculation for FIN-204.",
                "user": {"login": "marcus.vance"},
                "created_at": t_14h,
                "updated_at": t_14h,
                "requested_reviewers": [{"login": "elena.lead"}],
                "head": {"sha": "7c2e1f4a5b6c7d8e"},
                "labels": [{"name": "finance"}, {"name": "billing"}],
            }
        ]
    return []


async def _default_http_get(self, url, *args, **kwargs):
    if isinstance(getattr(self, "_transport", None), httpx.MockTransport):
        return await _REAL_ASYNC_CLIENT_GET(self, url, *args, **kwargs)

    url_str = str(url)

    # Pass through local ASGI test client requests
    if url_str.startswith("http://test") or url_str.startswith("http://localhost"):
        return await _REAL_ASYNC_CLIENT_GET(self, url, *args, **kwargs)

    # 1. GitHub REST API simulation
    if "api.github.com" in url_str:
        if "/pulls?" in url_str:
            for repo in ("acme/auth-service", "acme/payment-gateway", "acme/billing-engine"):
                if repo in url_str:
                    return httpx.Response(200, json=_build_github_pulls_payload(repo), request=httpx.Request("GET", url_str))
            return httpx.Response(200, json=_build_github_pulls_payload("acme/auth-service"), request=httpx.Request("GET", url_str))
        if "/reviews" in url_str:
            return httpx.Response(200, json=[], request=httpx.Request("GET", url_str))
        if "/check-runs" in url_str:
            return httpx.Response(
                200,
                json={"check_runs": [{"name": "ci-test", "status": "completed", "conclusion": "success"}]},
                request=httpx.Request("GET", url_str),
            )
        if "/actions/runs" in url_str and "/jobs" not in url_str:
            return httpx.Response(
                200,
                json={
                    "workflow_runs": [
                        {
                            "id": 8902,
                            "name": "CI Build & Integration",
                            "head_branch": "feat/oauth2-refresh",
                            "head_sha": "8f9d2a1b3c4d5e6f",
                            "display_title": "AssertionError in test_token_rotation_expiry",
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        }
                    ]
                },
                request=httpx.Request("GET", url_str),
            )
        if "/jobs" in url_str:
            return httpx.Response(
                200,
                json={
                    "jobs": [
                        {
                            "name": "integration-tests",
                            "conclusion": "failure",
                            "steps": [{"name": "pytest-auth-suite", "conclusion": "failure"}],
                        }
                    ]
                },
                request=httpx.Request("GET", url_str),
            )

    # 2. Jira Cloud REST API simulation
    if "/rest/api/3/search" in url_str or "/rest/api/2/search" in url_str:
        jira_payload = {
            "total": 3,
            "issues": [
                {
                    "key": "PROJ-108",
                    "fields": {
                        "summary": "Gateway Auth v2.1 Rollout",
                        "description": "Waiting on OAuth2 token exchange PR-402 and PR-102 review",
                        "issuetype": {"name": "Epic"},
                        "status": {"name": "BLOCKED"},
                        "priority": {"name": "Highest"},
                        "sprint": {"name": "Sprint 24"},
                        "assignee": {"displayName": "sarah.chen"},
                        "reporter": {"displayName": "elena.lead"},
                        "duedate": "2026-09-30",
                        "labels": ["engineering", "platform", "security"],
                        "issuelinks": [
                            {
                                "type": {"inward": "is blocked by", "outward": "blocks"},
                                "inwardIssue": {"key": "PR-402", "fields": {"summary": "OAuth2 Token Exchange"}},
                            }
                        ],
                    },
                },
                {
                    "key": "PROJ-112",
                    "fields": {
                        "summary": "Redis Cluster Failover Automation",
                        "description": "In progress platform reliability work",
                        "issuetype": {"name": "Story"},
                        "status": {"name": "In Progress"},
                        "priority": {"name": "High"},
                        "sprint": {"name": "Sprint 24"},
                        "assignee": {"displayName": "david.kim"},
                        "reporter": {"displayName": "elena.lead"},
                        "duedate": "2026-10-05",
                        "labels": ["engineering", "platform"],
                        "issuelinks": [],
                    },
                },
                {
                    "key": "FIN-204",
                    "fields": {
                        "summary": "Multi-Currency VAT Settlement Pipeline",
                        "description": "Blocked by PR-415 billing schema verification",
                        "issuetype": {"name": "Task"},
                        "status": {"name": "BLOCKED"},
                        "priority": {"name": "High"},
                        "sprint": {"name": "Sprint 24"},
                        "assignee": {"displayName": "marcus.vance"},
                        "reporter": {"displayName": "elena.lead"},
                        "duedate": "2026-10-01",
                        "labels": ["finance", "billing"],
                        "issuelinks": [],
                    },
                },
            ],
        }
        return httpx.Response(200, json=jira_payload, request=httpx.Request("GET", url_str))

    # 3. Slack Web API simulation
    if "slack.com/api" in url_str:
        if "conversations.list" in url_str:
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": [
                        {"id": "C001", "name": "platform-engineering"},
                        {"id": "C002", "name": "security-audit"},
                        {"id": "C003", "name": "billing-squad"},
                        {"id": "C004", "name": "general-announcements"},
                    ],
                },
                request=httpx.Request("GET", url_str),
            )
        if "conversations.history" in url_str:
            params = kwargs.get("params", {}) or {}
            ch_id = params.get("channel", "C001")
            if ch_id == "C003":
                msgs = [
                    {
                        "type": "message",
                        "user": "U003",
                        "text": "FIN-204 VAT settlement is waiting on PR-415 approval.",
                        "ts": "1724700200.000300",
                    }
                ]
            else:
                msgs = [
                    {
                        "type": "message",
                        "user": "U001",
                        "text": "PR-402 and PR-102 are blocking PROJ-108 release rollout.",
                        "ts": "1724700100.000100",
                    }
                ]
            return httpx.Response(200, json={"ok": True, "messages": msgs}, request=httpx.Request("GET", url_str))
        if "users.info" in url_str:
            return httpx.Response(
                200,
                json={"ok": True, "user": {"id": "U001", "name": "sarah.chen", "profile": {"display_name": "sarah.chen"}}},
                request=httpx.Request("GET", url_str),
            )
        if "users.list" in url_str:
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "members": [
                        {"id": "U001", "name": "sarah.chen", "profile": {"display_name": "sarah.chen"}},
                        {"id": "U002", "name": "david.kim", "profile": {"display_name": "david.kim"}},
                        {"id": "U003", "name": "alex-lead", "profile": {"display_name": "alex-lead"}},
                        {"id": "U004", "name": "elena.lead", "profile": {"display_name": "elena.lead"}},
                    ],
                },
                request=httpx.Request("GET", url_str),
            )

    return await _REAL_ASYNC_CLIENT_GET(self, url, *args, **kwargs)


async def _default_http_post(self, url, *args, **kwargs):
    if isinstance(getattr(self, "_transport", None), httpx.MockTransport):
        return await _REAL_ASYNC_CLIENT_POST(self, url, *args, **kwargs)

    url_str = str(url)

    if url_str.startswith("http://test") or url_str.startswith("http://localhost"):
        return await _REAL_ASYNC_CLIENT_POST(self, url, *args, **kwargs)

    if "slack.com/api" in url_str:
        if "conversations.open" in url_str:
            return httpx.Response(200, json={"ok": True, "channel": {"id": "D001"}}, request=httpx.Request("POST", url_str))
        if "chat.postMessage" in url_str:
            return httpx.Response(200, json={"ok": True, "ts": "1724700999.000100"}, request=httpx.Request("POST", url_str))

    return await _REAL_ASYNC_CLIENT_POST(self, url, *args, **kwargs)


@pytest.fixture(autouse=True)
def enterprise_http_transport_fixture(monkeypatch, tmp_path):
    """
    Configures default test credentials, isolated SQLite state database, and HTTP transport
    simulation for external GitHub/Jira/Slack APIs unless explicitly overridden by a test.
    """
    from prometheus.memory.firestore_store import firestore_store
    from prometheus.memory.state_store import state_store
    from prometheus.llm.gemini_pool import GeminiEnterpriseEngine

    SlackTools._user_cache.clear()
    SlackTools._channel_cache.clear()

    test_db = str(tmp_path / "test_prometheus_state.db")
    monkeypatch.setattr(state_store, "_db_path", test_db)
    monkeypatch.setattr(state_store, "_initialized", False)
    state_store._blockers.clear()
    state_store._drafts.clear()
    state_store._checkpoints.clear()

    monkeypatch.setattr(firestore_store, "_db", None)
    monkeypatch.setattr(GeminiEnterpriseEngine, "_get_vertex_client", lambda self: None)

    monkeypatch.setattr(settings, "github_token", "ghp_test_suite_token")
    monkeypatch.setattr(
        settings,
        "github_repos",
        ["acme/auth-service", "acme/payment-gateway", "acme/billing-engine"],
    )
    monkeypatch.setattr(settings, "jira_instance_url", "https://acme.atlassian.net")
    monkeypatch.setattr(settings, "jira_user_email", "test@acme.corp")
    monkeypatch.setattr(settings, "jira_api_token", "jira_test_suite_token")
    monkeypatch.setattr(settings, "slack_bot_token", "xoxb-test-suite-token")
    monkeypatch.setattr(
        settings,
        "slack_channels",
        ["#platform-engineering", "#security-audit", "#billing-squad"],
    )

    monkeypatch.setattr(httpx.AsyncClient, "get", _default_http_get)
    monkeypatch.setattr(httpx.AsyncClient, "post", _default_http_post)
    yield
