"""
Durable session checkpointing and state memory for Prometheus multi-agent workflows.
Tracks blocker lifecycles and human approval states across sessions with durable SQLite storage.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager
import asyncio
import json
import logging
import aiosqlite
from pydantic import BaseModel, Field
from prometheus.config import settings

logger = logging.getLogger(__name__)


class DraftStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


class ActionDraftRecord(BaseModel):
    draft_id: str
    target_channel_or_user: str
    action_type: str  # "slack_dm", "slack_channel_alert", "jira_comment", "reassign_pr"
    content: str
    context_blocker_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: DraftStatus = DraftStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    execution_result: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BlockerRecord(BaseModel):
    blocker_id: str
    title: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    source_artifacts: List[str] = Field(default_factory=list)
    impacted_squads: List[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StateStore:
    """
    Persistent state manager supporting durable SQLite storage,
    session checkpointing, and HITL action audit logs.
    """

    def __init__(self):
        self._db_path = settings.get_sqlite_db_path()
        self._blockers: Dict[str, BlockerRecord] = {}
        self._drafts: Dict[str, ActionDraftRecord] = {}
        self._checkpoints: Dict[str, Dict[str, Any]] = {}
        self._lock_obj: Optional[asyncio.Lock] = None
        self._lock_loop: Optional[asyncio.AbstractEventLoop] = None
        self._initialized = False

    @property
    def _lock(self) -> asyncio.Lock:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.Lock()
        if self._lock_obj is None or self._lock_loop != loop:
            self._lock_obj = asyncio.Lock()
            self._lock_loop = loop
        return self._lock_obj

    @asynccontextmanager
    async def _get_db(self):
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA busy_timeout=5000;")
            yield db

    async def init_db(self):
        """Creates the required tables in SQLite if they don't exist."""
        if self._initialized:
            return
        async with self._lock:
            if self._initialized:
                return
            try:
                async with self._get_db() as db:
                    await db.execute("PRAGMA journal_mode=WAL;")
                    await db.execute("""
                        CREATE TABLE IF NOT EXISTS blockers (
                            blocker_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            description TEXT,
                            severity TEXT,
                            source_artifacts TEXT,
                            impacted_squads TEXT,
                            detected_at TEXT,
                            resolved_at TEXT,
                            is_active INTEGER,
                            metadata TEXT
                        )
                    """)
                    await db.execute("""
                        CREATE TABLE IF NOT EXISTS action_drafts (
                            draft_id TEXT PRIMARY KEY,
                            target_channel_or_user TEXT NOT NULL,
                            action_type TEXT NOT NULL,
                            content TEXT,
                            context_blocker_id TEXT,
                            created_at TEXT,
                            status TEXT,
                            approved_by TEXT,
                            approved_at TEXT,
                            execution_result TEXT,
                            metadata TEXT
                        )
                    """)
                    await db.execute("""
                        CREATE TABLE IF NOT EXISTS checkpoints (
                            session_id TEXT PRIMARY KEY,
                            timestamp TEXT NOT NULL,
                            state_data TEXT NOT NULL
                        )
                    """)
                    await db.commit()
                self._initialized = True
                logger.info(f"🗄️ [StateStore] Persistent SQLite store initialized at '{self._db_path}'.")
            except Exception as e:
                logger.warning(f"⚠️ [StateStore] SQLite init warning ({e}); operating with in-memory store.")

    async def save_blocker(self, blocker: BlockerRecord) -> BlockerRecord:
        async with self._lock:
            self._blockers[blocker.blocker_id] = blocker
        try:
            async with self._get_db() as db:
                await db.execute("""
                    INSERT OR REPLACE INTO blockers (
                        blocker_id, title, description, severity, source_artifacts,
                        impacted_squads, detected_at, resolved_at, is_active, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    blocker.blocker_id,
                    blocker.title,
                    blocker.description,
                    blocker.severity,
                    json.dumps(blocker.source_artifacts),
                    json.dumps(blocker.impacted_squads),
                    blocker.detected_at.isoformat(),
                    blocker.resolved_at.isoformat() if blocker.resolved_at else None,
                    1 if blocker.is_active else 0,
                    json.dumps(blocker.metadata),
                ))
                await db.commit()
        except Exception as e:
            logger.debug(f"[StateStore] DB write blocker fallback ({e})")
        return blocker

    async def get_active_blockers(self, scopes: Optional[List[str]] = None) -> List[BlockerRecord]:
        results: List[BlockerRecord] = []
        try:
            async with self._get_db() as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM blockers WHERE is_active = 1") as cursor:
                    rows = await cursor.fetchall()
                    for row in rows:
                        results.append(BlockerRecord(
                            blocker_id=row["blocker_id"],
                            title=row["title"],
                            description=row["description"] or "",
                            severity=row["severity"] or "HIGH",
                            source_artifacts=json.loads(row["source_artifacts"] or "[]"),
                            impacted_squads=json.loads(row["impacted_squads"] or "[]"),
                            detected_at=datetime.fromisoformat(row["detected_at"]),
                            resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
                            is_active=bool(row["is_active"]),
                            metadata=json.loads(row["metadata"] or "{}"),
                        ))
        except Exception as e:
            logger.debug(f"[StateStore] DB read active blockers fallback ({e})")
            async with self._lock:
                results = [b for b in self._blockers.values() if b.is_active]

        if scopes:
            scope_set = set(scopes)
            return [b for b in results if set(b.impacted_squads) & scope_set]
        return results

    async def save_draft(self, draft: ActionDraftRecord) -> ActionDraftRecord:
        async with self._lock:
            self._drafts[draft.draft_id] = draft
        try:
            async with self._get_db() as db:
                await db.execute("""
                    INSERT OR REPLACE INTO action_drafts (
                        draft_id, target_channel_or_user, action_type, content,
                        context_blocker_id, created_at, status, approved_by,
                        approved_at, execution_result, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    draft.draft_id,
                    draft.target_channel_or_user,
                    draft.action_type,
                    draft.content,
                    draft.context_blocker_id,
                    draft.created_at.isoformat(),
                    draft.status.value,
                    draft.approved_by,
                    draft.approved_at.isoformat() if draft.approved_at else None,
                    draft.execution_result,
                    json.dumps(draft.metadata),
                ))
                await db.commit()
        except Exception as e:
            logger.debug(f"[StateStore] DB write draft fallback ({e})")
        return draft

    async def get_draft(self, draft_id: str) -> Optional[ActionDraftRecord]:
        try:
            async with self._get_db() as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM action_drafts WHERE draft_id = ?", (draft_id,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return ActionDraftRecord(
                            draft_id=row["draft_id"],
                            target_channel_or_user=row["target_channel_or_user"],
                            action_type=row["action_type"],
                            content=row["content"] or "",
                            context_blocker_id=row["context_blocker_id"],
                            created_at=datetime.fromisoformat(row["created_at"]),
                            status=DraftStatus(row["status"]),
                            approved_by=row["approved_by"],
                            approved_at=datetime.fromisoformat(row["approved_at"]) if row["approved_at"] else None,
                            execution_result=row["execution_result"],
                            metadata=json.loads(row["metadata"] or "{}"),
                        )
                    return None
        except Exception as e:
            logger.debug(f"[StateStore] DB read draft fallback ({e})")
        async with self._lock:
            return self._drafts.get(draft_id)

    async def list_drafts(
        self,
        status: Optional[DraftStatus] = None,
        scopes: Optional[List[str]] = None,
    ) -> List[ActionDraftRecord]:
        try:
            async with self._get_db() as db:
                db.row_factory = aiosqlite.Row
                query = "SELECT * FROM action_drafts"
                params = ()
                if status:
                    query += " WHERE status = ?"
                    params = (status.value,)
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    results = []
                    for row in rows:
                        results.append(ActionDraftRecord(
                            draft_id=row["draft_id"],
                            target_channel_or_user=row["target_channel_or_user"],
                            action_type=row["action_type"],
                            content=row["content"] or "",
                            context_blocker_id=row["context_blocker_id"],
                            created_at=datetime.fromisoformat(row["created_at"]),
                            status=DraftStatus(row["status"]),
                            approved_by=row["approved_by"],
                            approved_at=datetime.fromisoformat(row["approved_at"]) if row["approved_at"] else None,
                            execution_result=row["execution_result"],
                            metadata=json.loads(row["metadata"] or "{}"),
                        ))
                    if scopes:
                        scope_set = set(scopes)
                        filtered_results = []
                        for d in results:
                            d_scopes = set(d.metadata.get("scopes", []))
                            if not d_scopes and d.context_blocker_id:
                                async with self._lock:
                                    b = self._blockers.get(d.context_blocker_id)
                                if b:
                                    d_scopes = set(b.impacted_squads)
                            if not d_scopes or (d_scopes & scope_set):
                                filtered_results.append(d)
                        return filtered_results
                    return results
        except Exception as e:
            logger.debug(f"[StateStore] DB list drafts fallback ({e})")
        async with self._lock:
            res = [d for d in self._drafts.values() if d.status == status] if status else list(self._drafts.values())
        if scopes:
            scope_set = set(scopes)
            res = [d for d in res if not d.metadata.get("scopes") or (set(d.metadata.get("scopes", [])) & scope_set)]
        return res

    async def update_draft_status(
        self, draft_id: str, status: DraftStatus, approver: Optional[str] = None, result: Optional[str] = None
    ) -> Optional[ActionDraftRecord]:
        draft = await self.get_draft(draft_id)
        if not draft:
            return None
        draft.status = status
        if approver:
            draft.approved_by = approver
            draft.approved_at = datetime.now(timezone.utc)
        if result:
            draft.execution_result = result
        await self.save_draft(draft)
        return draft

    async def update_draft_content(
        self, draft_id: str, content: str, target: Optional[str] = None
    ) -> Optional[ActionDraftRecord]:
        draft = await self.get_draft(draft_id)
        if not draft:
            return None
        draft.content = content
        if target:
            draft.target_channel_or_user = target
        if draft.metadata and "slack_blocks" in draft.metadata:
            for block in draft.metadata.get("slack_blocks", []):
                if block.get("type") == "section" and "text" in block and block["text"].get("type") == "mrkdwn":
                    if not block["text"].get("text", "").startswith("🔔"):
                        block["text"]["text"] = content
        await self.save_draft(draft)
        return draft

    async def save_checkpoint(self, session_id: str, state_data: Dict[str, Any]) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        async with self._lock:
            self._checkpoints[session_id] = {
                "session_id": session_id,
                "timestamp": ts,
                "data": state_data,
            }
        try:
            async with self._get_db() as db:
                await db.execute("""
                    INSERT OR REPLACE INTO checkpoints (session_id, timestamp, state_data)
                    VALUES (?, ?, ?)
                """, (session_id, ts, json.dumps(state_data, default=str)))
                await db.commit()
        except Exception as e:
            logger.debug(f"[StateStore] DB save checkpoint fallback ({e})")

    async def get_checkpoint(self, session_id: str) -> Optional[Dict[str, Any]]:
        try:
            async with self._get_db() as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM checkpoints WHERE session_id = ?", (session_id,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return {
                            "session_id": row["session_id"],
                            "timestamp": row["timestamp"],
                            "data": json.loads(row["state_data"]),
                        }
        except Exception as e:
            logger.debug(f"[StateStore] DB get checkpoint fallback ({e})")
        async with self._lock:
            return self._checkpoints.get(session_id)


# Global singleton instance
state_store = StateStore()
