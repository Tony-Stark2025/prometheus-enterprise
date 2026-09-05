"""
Enterprise Firestore Sandbox Seeder for Prometheus.
Seeds isolated mock telemetry collections for sandbox/demo tenants in Firestore,
ensuring zero static PII or mock fixtures are hardcoded in application source code.
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from prometheus.memory.firestore_store import firestore_store

logger = logging.getLogger("prometheus.tools.seed_sandbox")


async def seed_tenant_sandbox(tenant_id: str = "default_enterprise"):
    """
    Seeds standard enterprise telemetry collections into Firestore.
    """
    now = datetime.now(timezone.utc)

    # 1. Pull Requests
    sandbox_prs = [
        {
            "id": "PR-102",
            "repo": "acme-corp/auth-platform",
            "title": "feat(auth): Migrate core auth service to OAuth 2.1 token exchange",
            "author": "elena.lead",
            "created_at": (now - timedelta(hours=58)).isoformat(),
            "updated_at": (now - timedelta(hours=52)).isoformat(),
            "review_latency_hours": 58.0,
            "status": "OPEN",
            "reviewers": ["david.kim"],
            "review_status": "WAITING_REVIEW",
            "ci_status": "PASSED",
            "scopes": ["engineering", "platform", "security"],
            "blocking_downstream": ["ACME-104"],
        },
        {
            "id": "PR-108",
            "repo": "acme-corp/web-gateway",
            "title": "fix(gateway): Adapt downstream session headers for OAuth v2.1",
            "author": "sarah.chen",
            "created_at": (now - timedelta(hours=18)).isoformat(),
            "updated_at": (now - timedelta(hours=2)).isoformat(),
            "review_latency_hours": 18.0,
            "status": "OPEN",
            "reviewers": ["david.kim"],
            "review_status": "IN_REVIEW",
            "ci_status": "PASSED",
            "scopes": ["engineering", "platform"],
            "blocking_downstream": ["ACME-104"],
        },
        {
            "id": "PR-115",
            "repo": "acme-corp/billing-service",
            "title": "chore: Upgrade Stripe webhook validator",
            "author": "marcus.vance",
            "created_at": (now - timedelta(hours=8)).isoformat(),
            "updated_at": (now - timedelta(hours=1)).isoformat(),
            "review_latency_hours": 8.0,
            "status": "OPEN",
            "reviewers": ["elena.lead"],
            "review_status": "APPROVED",
            "ci_status": "PASSED",
            "scopes": ["engineering", "platform"],
            "blocking_downstream": [],
        },
    ]

    # 2. Jira Issues
    sandbox_issues = [
        {
            "key": "ACME-104",
            "summary": "Migrate auth gateway to OAuth 2.1 token exchange",
            "type": "Epic",
            "status": "BLOCKED",
            "priority": "Highest",
            "sprint": "Sprint 24 - Core Platform",
            "assignee": "elena.lead",
            "reporter": "marcus.vance",
            "blocked_by": ["PR-102"],
            "blocker_reason": "Waiting on PR-102 review from @david.kim before gateway cutover.",
            "scopes": ["engineering", "platform"],
            "target_release_date": "2026-09-01",
        },
        {
            "key": "ACME-108",
            "summary": "Frontend M3 Expressive design overhaul",
            "type": "Story",
            "status": "IN_PROGRESS",
            "priority": "Medium",
            "sprint": "Sprint 24 - Core Platform",
            "assignee": "sarah.chen",
            "reporter": "elena.lead",
            "blocked_by": [],
            "blocker_reason": None,
            "scopes": ["engineering", "platform"],
            "target_release_date": "2026-09-03",
        },
        {
            "key": "ACME-112",
            "summary": "Enterprise ABAC Policy Engine & Firestore audit vault",
            "type": "Task",
            "status": "READY_FOR_QA",
            "priority": "High",
            "sprint": "Sprint 24 - Core Platform",
            "assignee": "elena.lead",
            "reporter": "marcus.vance",
            "blocked_by": [],
            "blocker_reason": None,
            "scopes": ["engineering", "platform"],
            "target_release_date": "2026-09-05",
        },
    ]

    # 3. Slack Messages
    sandbox_messages = [
        {
            "id": "MSG-901",
            "channel": "#platform-engineering",
            "user": "elena.lead",
            "timestamp": (now - timedelta(hours=36)).isoformat(),
            "text": "Hey @david.kim, PR-102 (OAuth 2.1) has been waiting for review. It is blocking the ACME-104 gateway integration.",
            "scopes": ["engineering", "platform"],
        },
        {
            "id": "MSG-905",
            "channel": "#platform-engineering",
            "user": "david.kim",
            "timestamp": (now - timedelta(hours=3)).isoformat(),
            "text": "Reviewing PR-102 now. Running security audit and test suite validation.",
            "scopes": ["engineering", "platform"],
        },
        {
            "id": "MSG-912",
            "channel": "#general",
            "user": "sarah.chen",
            "timestamp": (now - timedelta(hours=2)).isoformat(),
            "text": "Frontend M3 Expressive design overhaul is on track for Sprint 24 demo.",
            "scopes": ["engineering", "platform"],
        },
        {
            "id": "MSG-920",
            "channel": "#finance-billing",
            "user": "marcus.vance",
            "timestamp": (now - timedelta(hours=1)).isoformat(),
            "text": "Quarterly Billing Reconciliation Service FIN-201 scheduled for cutover.",
            "scopes": ["finance", "engineering"],
        },
    ]

    # Seed to in-memory store and Firestore collection if connected
    firestore_store._memory_cache[f"{tenant_id}:sandbox_prs"] = sandbox_prs
    firestore_store._memory_cache[f"{tenant_id}:sandbox_issues"] = sandbox_issues
    firestore_store._memory_cache[f"{tenant_id}:sandbox_messages"] = sandbox_messages

    if firestore_store._db:
        try:
            batch = firestore_store._db.batch()
            tenant_ref = firestore_store._db.collection("tenants").document(tenant_id)

            for pr in sandbox_prs:
                ref = tenant_ref.collection("sandbox_prs").document(pr["id"])
                batch.set(ref, pr)

            for issue in sandbox_issues:
                ref = tenant_ref.collection("sandbox_issues").document(issue["key"])
                batch.set(ref, issue)

            for msg in sandbox_messages:
                ref = tenant_ref.collection("sandbox_messages").document(msg["id"])
                batch.set(ref, msg)

            await batch.commit()
            logger.info(f"Successfully seeded Firestore sandbox collections for tenant '{tenant_id}'.")
        except Exception as e:
            logger.warning(f"Failed to batch commit sandbox data to Firestore: {e}")

    print(f"✓ Seeded sandbox collections for tenant '{tenant_id}'.")


if __name__ == "__main__":
    import asyncio
    asyncio.run(seed_tenant_sandbox())

