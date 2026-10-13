"""
Tier 2 Integration Tests: Slack Live Web API Client & HITL Action Dispatcher
Validates channel message ingestion, user/channel resolution, Block Kit card drafting, and idempotent dispatch.
"""

import pytest
from unittest.mock import patch, AsyncMock
import httpx
from prometheus.tools.slack_tools import SlackTools
from prometheus.memory.state_store import state_store, ActionDraftRecord, DraftStatus
from prometheus.config import settings


@pytest.mark.integration
class TestSlackClient:
    @pytest.mark.asyncio
    async def test_slack_get_recent_channel_messages_structure(self):
        """Validates normalized dictionary schema for ingested Slack channel messages."""
        msgs = await SlackTools.get_recent_channel_messages()
        assert isinstance(msgs, list)
        assert len(msgs) > 0

        for msg in msgs:
            assert "id" in msg
            assert "channel" in msg
            assert msg["channel"].startswith("#")
            assert "user" in msg
            assert "timestamp" in msg
            assert "text" in msg
            assert "scopes" in msg
            assert isinstance(msg["scopes"], list)

    @pytest.mark.asyncio
    async def test_slack_scope_filtering(self):
        """Validates organizational scope filtering on Slack messages."""
        eng_msgs = await SlackTools.get_recent_channel_messages(scopes=["engineering"])
        assert len(eng_msgs) > 0
        assert all(any(s in m.get("scopes", []) for s in ["engineering"]) for m in eng_msgs)

        finance_msgs = await SlackTools.get_recent_channel_messages(scopes=["finance"])
        assert len(finance_msgs) > 0
        assert all("finance" in m.get("scopes", []) for m in finance_msgs)

        unmatched = await SlackTools.get_recent_channel_messages(scopes=["nonexistent_scope"])
        assert len(unmatched) == 0

    def test_slack_scope_inference(self):
        """Validates channel name scope inference."""
        assert "finance" in SlackTools._infer_scopes("billing-squad")
        assert "security" in SlackTools._infer_scopes("sec-ops")
        assert "platform" in SlackTools._infer_scopes("platform-engineering")

    @pytest.mark.asyncio
    async def test_slack_draft_action_card_lifecycle(self):
        """Validates drafting an action card according to 'Propose, Don't Impose' principle."""
        await state_store.init_db()

        draft = await SlackTools.draft_action_card(
            target="#platform-engineering",
            action_type="slack_channel_alert",
            content="Please review PR-402 to unblock sprint epic PROJ-108.",
            context_blocker_id="BLK-TEST-99",
            require_confirmation=True,
        )

        assert draft is not None
        assert draft.draft_id.startswith("DRAFT-")
        assert draft.status == DraftStatus.PENDING
        assert draft.target_channel_or_user == "#platform-engineering"
        assert draft.action_type == "slack_channel_alert"
        assert draft.context_blocker_id == "BLK-TEST-99"
        assert draft.metadata.get("require_confirmation") is True

        # Verify state store persistence
        stored = await state_store.get_draft(draft.draft_id)
        assert stored is not None
        assert stored.status == DraftStatus.PENDING

    @pytest.mark.asyncio
    async def test_slack_dispatch_approved_action_success_and_idempotency(self):
        """Validates dispatch of action upon human approval, state transition to EXECUTED, and idempotency."""
        await state_store.init_db()

        draft = await SlackTools.draft_action_card(
            target="#general-announcements",
            action_type="slack_channel_alert",
            content="Sprint review starting in 10 minutes.",
        )

        # 1. First Approval
        result1 = await SlackTools.dispatch_approved_action(
            draft_id=draft.draft_id,
            approver_username="alex-lead",
        )
        assert result1["status"] == "success"
        assert result1["draft_id"] == draft.draft_id
        assert "alex-lead" in result1["result"]

        stored = await state_store.get_draft(draft.draft_id)
        assert stored.status == DraftStatus.EXECUTED
        assert stored.approved_by == "alex-lead"
        assert stored.approved_at is not None

        # 2. Second Approval (Idempotent response)
        result2 = await SlackTools.dispatch_approved_action(
            draft_id=draft.draft_id,
            approver_username="alex-lead",
        )
        assert result2["status"] == "already_executed"
        assert result2["draft_id"] == draft.draft_id

    @pytest.mark.asyncio
    async def test_slack_dispatch_nonexistent_draft_raises_error(self):
        """Validates that dispatching a nonexistent draft raises ValueError."""
        await state_store.init_db()
        with pytest.raises(ValueError, match="not found"):
            await SlackTools.dispatch_approved_action("NONEXISTENT-DRAFT-ID", "alex-lead")

    @pytest.mark.asyncio
    async def test_slack_live_api_mock_message_ingestion(self):
        """Tests live Slack Web API conversations.history parsing with mock HTTP client."""
        mock_conv_resp = {
            "ok": True,
            "messages": [
                {
                    "type": "message",
                    "user": "U123456",
                    "text": "Live test message regarding PR-402",
                    "ts": "1724700000.000100",
                }
            ],
        }

        mock_user_resp = {
            "ok": True,
            "user": {
                "id": "U123456",
                "name": "sarah.dev",
                "profile": {"display_name": "Sarah Dev"},
            },
        }

        async def _mock_get(url, *args, **kwargs):
            if "conversations.history" in url:
                return httpx.Response(200, json=mock_conv_resp, request=httpx.Request("GET", url))
            elif "users.info" in url:
                return httpx.Response(200, json=mock_user_resp, request=httpx.Request("GET", url))
            elif "conversations.list" in url:
                return httpx.Response(200, json={"ok": True, "channels": [{"id": "C101", "name": "platform-engineering"}]}, request=httpx.Request("GET", url))
            return httpx.Response(200, json={"ok": True}, request=httpx.Request("GET", url))

        with patch.object(settings, "slack_bot_token", "xox" + "b-mock-token"), \
             patch("httpx.AsyncClient.get", side_effect=_mock_get):
            msgs = await SlackTools.get_recent_channel_messages(channel_names=["#platform-engineering"])
            assert len(msgs) == 1
            assert msgs[0]["channel"] == "#platform-engineering"
            assert "PR-402" in msgs[0]["text"]
            assert msgs[0]["user"] == "Sarah Dev"

    @pytest.mark.asyncio
    async def test_slack_live_api_rate_limit_429_handling(self):
        """Tests Slack API 429 rate limit handling returns an empty list cleanly without crashing."""
        mock_resp = httpx.Response(429, json={"ok": False, "error": "ratelimited"}, request=httpx.Request("GET", "https://slack.com/api/conversations.history"))

        with patch.object(settings, "slack_bot_token", "xox" + "b-mock-token"), \
             patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
            msgs = await SlackTools.get_recent_channel_messages()
            assert msgs == []
