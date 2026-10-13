"""
Action & Drafting Agent for Prometheus.
Adheres strictly to the 'Propose, Don't Impose' principle.
Prepares scheduled alignment digests and interactive Slack Block Kit action cards with require_confirmation=True.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from prometheus.memory.state_store import state_store, ActionDraftRecord, BlockerRecord, DraftStatus
from prometheus.tools.slack_tools import SlackTools


class ActionAgent:
    """
    Sub-agent 6: Action & Drafting Agent
    Drafts contextual remediation actions and scheduled leadership briefings for human sign-off.
    """

    name: str = "ActionAndDraftingAgent"
    role: str = "Human-in-the-Loop Action Drafting"

    @classmethod
    async def create_action_drafts_for_blockers(
        cls,
        blockers: List[BlockerRecord],
    ) -> List[ActionDraftRecord]:
        """
        Translates root-cause blockers into concrete human-reviewable action proposals.
        Deduplicates against existing pending action drafts to avoid unbounded growth.
        """
        drafts: List[ActionDraftRecord] = []
        existing_pending = await state_store.list_drafts(status=DraftStatus.PENDING)
        pending_map = {
            (d.context_blocker_id, d.action_type): d
            for d in existing_pending
            if d.context_blocker_id
        }

        for blocker in blockers:
            # 1. Stale PR / reviewer ping proposal
            pr_art = (
                blocker.metadata.get("pr_id")
                or next((a for a in blocker.source_artifacts if a.startswith("PR-") or "#" in a), None)
            )
            if pr_art or blocker.severity in ("CRITICAL", "HIGH"):
                existing = pending_map.get((blocker.blocker_id, "slack_direct_message"))
                if existing:
                    drafts.append(existing)
                else:
                    pr_label = pr_art or (blocker.source_artifacts[0] if blocker.source_artifacts else blocker.blocker_id)
                    reviewers_meta = blocker.metadata.get("reviewers", [])
                    if reviewers_meta and reviewers_meta[0] != "unassigned":
                        reviewer_target = f"@{reviewers_meta[0].lstrip('@')}"
                    elif blocker.metadata.get("assignee") and blocker.metadata["assignee"] != "unassigned":
                        reviewer_target = f"@{str(blocker.metadata['assignee']).lstrip('@')}"
                    else:
                        reviewer_target = "@engineering-oncall"
                        if "reviewer(s)" in blocker.description:
                            try:
                                parts = blocker.description.split("reviewer(s)")
                                if len(parts) > 1:
                                    r_name = parts[1].split(".")[0].strip().split()[0].strip(",")
                                    if r_name and not r_name.startswith("http"):
                                        reviewer_target = f"@{r_name}"
                            except Exception:
                                pass

                    ping_content = (
                        f"Hi {reviewer_target}! 👋 {pr_label} is awaiting review and is currently stalling delivery "
                        f"({blocker.title}). Could you please complete the review today to unblock the milestone? 🚀"
                    )
                    draft = await SlackTools.draft_action_card(
                        target=reviewer_target,
                        action_type="slack_direct_message",
                        content=ping_content,
                        context_blocker_id=blocker.blocker_id,
                        require_confirmation=True,
                    )
                    # Enrich with Slack Block Kit JSON representation
                    draft.metadata["slack_blocks"] = [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"🔔 *Prometheus Suggested Action: Review Request*"},
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": ping_content},
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Approve & Send"},
                                    "style": "primary",
                                    "value": draft.draft_id,
                                    "action_id": "approve_action",
                                },
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Discard"},
                                    "style": "danger",
                                    "value": draft.draft_id,
                                    "action_id": "reject_action",
                                },
                            ],
                        },
                    ]
                    await state_store.save_draft(draft)
                    pending_map[(blocker.blocker_id, "slack_direct_message")] = draft
                    drafts.append(draft)

            # 2. Squad-wide delivery alert proposal
            if blocker.severity in ("CRITICAL", "HIGH"):
                existing_alert = pending_map.get((blocker.blocker_id, "slack_channel_alert"))
                if existing_alert:
                    drafts.append(existing_alert)
                else:
                    channel_alert = (
                        f"⚠️ *Prometheus Blocker Alert [{blocker.blocker_id}]*:\n"
                        f"{blocker.title}\n"
                        f"Impact: Squads {', '.join(blocker.impacted_squads)}\n"
                        f"Summary: {blocker.description}"
                    )
                    channel_draft = await SlackTools.draft_action_card(
                        target="#platform-engineering",
                        action_type="slack_channel_alert",
                        content=channel_alert,
                        context_blocker_id=blocker.blocker_id,
                        require_confirmation=True,
                    )
                    channel_draft.metadata["slack_blocks"] = [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": f"🚨 Critical Delivery Bottleneck [{blocker.blocker_id}]"},
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": channel_alert},
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Broadcast to Channel"},
                                    "style": "primary",
                                    "value": channel_draft.draft_id,
                                    "action_id": "approve_action",
                                },
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Mute Alert"},
                                    "value": channel_draft.draft_id,
                                    "action_id": "reject_action",
                                },
                            ],
                        },
                    ]
                    await state_store.save_draft(channel_draft)
                    pending_map[(blocker.blocker_id, "slack_channel_alert")] = channel_draft
                    drafts.append(channel_draft)

        return drafts

    @classmethod
    async def generate_alignment_digest(
        cls,
        blockers: List[BlockerRecord],
        drafts: List[ActionDraftRecord],
    ) -> Dict[str, Any]:
        """
        Generates the formatted 08:00 AM Daily Alignment Briefing.
        """
        crit_count = len([b for b in blockers if b.severity == "CRITICAL"])
        return {
            "digest_title": "Daily Executive Workstream Alignment Digest",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "critical_blocker_count": crit_count,
            "critical_blockers_count": crit_count,
            "total_active_blockers": len(blockers),
            "pending_action_proposals": len([d for d in drafts if d.status == DraftStatus.PENDING]),
            "blockers": [b.model_dump() for b in blockers],
            "action_drafts": [d.model_dump() for d in drafts],
            "summary_statement": (
                f"Prometheus identified {len(blockers)} high-priority delivery bottleneck(s). "
                f"{len(drafts)} contextual action draft(s) are ready for human approval."
            ),
        }
