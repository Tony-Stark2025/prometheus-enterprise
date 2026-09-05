"""
Prometheus Native Reasoning Engine Application for Google Cloud Vertex AI Agent Engine.
"""

import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional

from prometheus.config import settings
from prometheus.workflows.prometheus_flow import PrometheusWorkflow
from prometheus.security.abac_guard import UserContext
from prometheus.memory.state_store import state_store, DraftStatus
from prometheus.tools.slack_tools import SlackTools
from prometheus.registry.agent_registry import agent_registry


def run_async(coro):
    """
    Safely executes an async coroutine across sync/async event loops.
    Compatible with standalone scripts, running event loops, and Vertex AI runtime.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


class PrometheusAgentEngineApp:
    """
    Native Agent Application packaged for Google Cloud Vertex AI Agent Engine (Reasoning Engine).
    Unified on Gemini 3.7 Flash with cross-squad blocker telemetry correlation and HITL action drafting.
    """

    def __init__(self, model: str = "gemini-3.7-flash"):
        self.model = model
        self.agent_name = "prometheus-chief-of-staff"

    def set_up(self):
        """Initializes state store and tools on Agent Engine startup."""
        run_async(state_store.init_db())

    def query(
        self,
        prompt: str = "Scan cross-squad telemetry for active sprint blockers",
        user_id: str = "elena.lead",
        username: str = "elena.lead",
        org_scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Main query entrypoint for Gemini Enterprise Agent Platform.
        Executes asynchronous multi-agent telemetry correlation and action drafting.
        """
        if org_scopes is None:
            org_scopes = ["engineering", "platform"]

        async def _execute():
            await state_store.init_db()
            user = UserContext(
                user_id=user_id,
                username=username,
                is_authenticated=True,
                org_scopes=set(org_scopes),
            )
            result = await PrometheusWorkflow.run(user=user, query=prompt)
            digest_val = result.daily_digest if isinstance(result.daily_digest, dict) else (result.daily_digest.model_dump() if result.daily_digest else {})
            return {
                "session_id": result.session_id,
                "status": result.status,
                "summary": result.summary,
                "blockers": result.blockers,
                "action_drafts": result.action_drafts,
                "daily_digest": digest_val,
                "briefing": digest_val,
            }

        return run_async(_execute())

    def list_agents(self) -> List[Dict[str, Any]]:
        """Returns the Fortified Enterprise Fleet registry of all 6 sub-agents."""
        return [a.model_dump() for a in agent_registry.list_agents()]

    def approve_action(self, draft_id: str, approver_username: str = "elena.lead") -> Dict[str, Any]:
        """Human-in-the-loop action approval endpoint."""
        async def _execute():
            await state_store.init_db()
            try:
                return await SlackTools.dispatch_approved_action(draft_id, approver_username)
            except ValueError as e:
                return {"status": "error", "error": str(e), "draft_id": draft_id}

        return run_async(_execute())

    def reject_action(self, draft_id: str, approver_username: str = "alex-lead") -> Dict[str, Any]:
        """Human-in-the-loop action rejection endpoint."""
        async def _execute():
            await state_store.init_db()
            draft = await state_store.get_draft(draft_id)
            if not draft:
                return {"status": "error", "error": f"Draft '{draft_id}' not found.", "draft_id": draft_id}
            if draft.status == DraftStatus.EXECUTED:
                return {"status": "already_executed", "draft_id": draft_id}
            await state_store.update_draft_status(
                draft_id=draft_id,
                status=DraftStatus.REJECTED,
                approver=approver_username,
                result="Action rejected by user.",
            )
            return {"status": "rejected", "draft_id": draft_id}

        return run_async(_execute())

    def register_operations(self) -> Dict[str, List[str]]:
        """Registers callable operations for Vertex AI Reasoning Engine."""
        return {
            "": ["query", "list_agents", "approve_action", "reject_action"],
        }
