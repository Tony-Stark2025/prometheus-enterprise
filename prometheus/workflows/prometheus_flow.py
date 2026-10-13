"""
Prometheus Multi-Agent Asynchronous Orchestration Workflow.
Coordinates the fleet of 6 specialized sub-agents with state checkpointing and HITL pauses.
"""

import asyncio
import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from prometheus.security.abac_guard import UserContext
from prometheus.memory.state_store import state_store, BlockerRecord, ActionDraftRecord
from prometheus.agents.router_agent import RouterAgent
from prometheus.agents.git_agent import GitAgent
from prometheus.agents.jira_agent import JiraAgent
from prometheus.agents.workstream_agent import WorkstreamAgent
from prometheus.agents.synthesis_agent import SynthesisAgent
from prometheus.agents.action_agent import ActionAgent


class WorkflowExecutionResult(BaseModel):
    session_id: str
    status: str  # "COMPLETED", "REJECTED_SECURITY", "UNAUTHORIZED"
    summary: str
    router_envelope: Dict[str, Any]
    blockers: List[Dict[str, Any]]
    action_drafts: List[Dict[str, Any]]
    daily_digest: Optional[Dict[str, Any]] = None
    raw_telemetry: Dict[str, Any] = Field(default_factory=dict)


class PrometheusWorkflow:
    """
    Asynchronous DAG orchestrating the Prometheus sub-agent fleet.
    """

    @classmethod
    async def run(
        cls,
        user: UserContext,
        query: str = "Generate daily alignment briefing and identify delivery blockers",
    ) -> WorkflowExecutionResult:
        session_id = f"sess_{uuid.uuid4().hex[:12]}"

        # Step 1: Perimeter Router & Security Guardrails
        router_res = await RouterAgent.process_request(user=user, raw_query=query)
        if router_res["status"] != "authorized":
            status_val = "REJECTED_SECURITY" if router_res["status"] in ("rejected", "rejected_security") else router_res["status"].upper()
            return WorkflowExecutionResult(
                session_id=session_id,
                status=status_val,
                summary=f"Execution halted: {router_res.get('reason', 'Security Policy')}",
                router_envelope=router_res,
                blockers=[],
                action_drafts=[],
                raw_telemetry={},
            )

        sanitized_query = router_res.get("sanitized_query", query)

        # Step 2: Concurrent Ingestion Fan-Out (Git, Jira, Workstream)
        git_task = GitAgent.collect_telemetry(user)
        jira_task = JiraAgent.collect_telemetry(user)
        workstream_task = WorkstreamAgent.collect_telemetry(user)

        git_data, jira_data, workstream_data = await asyncio.gather(
            git_task, jira_task, workstream_task
        )

        # Step 3: Synthesis & Blocker Correlation Engine
        blockers: List[BlockerRecord] = await SynthesisAgent.synthesize(
            git_telemetry=git_data,
            jira_telemetry=jira_data,
            slack_telemetry=workstream_data,
        )

        # Step 4: Action Drafting ("Propose, Don't Impose")
        action_drafts: List[ActionDraftRecord] = await ActionAgent.create_action_drafts_for_blockers(
            blockers=blockers
        )

        # Step 5: Executive Digest Generation
        digest = await ActionAgent.generate_alignment_digest(blockers, action_drafts)

        # Step 6: Durable State Checkpointing
        await state_store.save_checkpoint(
            session_id=session_id,
            state_data={
                "user": user.model_dump(),
                "query": sanitized_query,
                "blockers": [b.model_dump() for b in blockers],
                "draft_ids": [d.draft_id for d in action_drafts],
                "digest": digest,
            },
        )

        return WorkflowExecutionResult(
            session_id=session_id,
            status="COMPLETED",
            summary=digest.get("summary_statement", "Summary available"),
            router_envelope=router_res,
            blockers=[b.model_dump() for b in blockers],
            action_drafts=[d.model_dump() for d in action_drafts],
            daily_digest=digest,
            raw_telemetry={
                "git": git_data,
                "jira": jira_data,
                "slack": workstream_data,
                "agent_run_metadata": {
                    "agents_executed": 6,
                    "agents": [
                        "RouterAndGuardrailAgent",
                        "GitIngestionAgent",
                        "ProjectTrackerAgent",
                        "WorkstreamIngestionAgent",
                        "SynthesisAndBlockerAgent",
                        "ActionDrafterAgent",
                    ],
                },
            },
        )
