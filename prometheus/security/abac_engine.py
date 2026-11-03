"""
Enterprise Attribute-Based Access Control (ABAC) Database Policy Engine.
Provides persistent storage, dynamic attribute evaluation, clearance level checking, and audit trails.

Mathematical Access Rule:
  P(U, R) = IsAuthenticated(U) 
            AND NOT IsRestricted(R) 
            AND (IsAdmin(U) OR (
                DepartmentMatches(U.dept, R.dept) 
                AND ClearanceHierarchy(U.clearance) >= R.min_clearance 
                AND SquadOverlap(U.squads, R.required_squad)
            ))
"""

import uuid
import os
import time
import json
import sqlite3
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from pydantic import BaseModel, Field

logger = logging.getLogger("prometheus.security.abac_engine")

DB_PATH = os.getenv("ABAC_DB_PATH", os.path.join(os.path.dirname(__file__), "abac_policies.db"))

CLEARANCE_HIERARCHY = {
    "L1": 1,  # Public / Guest
    "L2": 2,  # Associate Engineer
    "L3": 3,  # Senior Engineer / PM
    "L4": 4,  # Staff / Principal / Architect
    "L5": 5,  # Executive / VP / CISO
}


class ABACUserRecord(BaseModel):
    user_id: str
    username: str
    email: str
    department: str = "engineering"
    clearance_level: str = "L3"
    assigned_squads: List[str] = Field(default_factory=lambda: ["auth", "platform"])
    roles: List[str] = Field(default_factory=lambda: ["developer"])
    is_admin: bool = False


class ABACResourceRecord(BaseModel):
    resource_id: str
    name: str
    resource_type: str  # "github_pr", "jira_issue", "slack_message", "security_audit", "vault"
    required_department: str = "engineering"
    min_clearance_level: str = "L2"
    required_squad: str = "auth"
    sensitivity: str = "INTERNAL"  # "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"
    is_restricted: bool = False


class ABACEvaluationResult(BaseModel):
    evaluation_id: str
    timestamp: str
    user_id: str
    resource_id: str
    decision: str  # "ALLOW" or "DENY"
    reason: str
    clearance_met: bool
    department_matched: bool
    squad_matched: bool
    latency_ms: float


class ABACPolicyEngine:
    """
    Database-backed enterprise ABAC evaluation engine with immutable audit logging.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._mem_conn = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS abac_users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                department TEXT NOT NULL,
                clearance_level TEXT NOT NULL,
                assigned_squads TEXT NOT NULL,
                roles TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS abac_resources (
                resource_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                required_department TEXT NOT NULL,
                min_clearance_level TEXT NOT NULL,
                required_squad TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                is_restricted INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS abac_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                rule_expression TEXT NOT NULL,
                effect TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 100
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS abac_audit_logs (
                evaluation_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                clearance_met INTEGER NOT NULL,
                department_matched INTEGER NOT NULL,
                squad_matched INTEGER NOT NULL,
                latency_ms REAL NOT NULL
            )
        """)
        conn.commit()

    def register_user(self, u: ABACUserRecord) -> ABACUserRecord:
        """Registers or updates an enterprise user in the ABAC catalog."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO abac_users 
                (user_id, username, email, department, clearance_level, assigned_squads, roles, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                u.user_id, u.username, u.email, u.department, u.clearance_level,
                json.dumps(u.assigned_squads), json.dumps(u.roles), 1 if u.is_admin else 0
            ))
            conn.commit()
        return u

    def register_resource(self, r: ABACResourceRecord) -> ABACResourceRecord:
        """Registers or updates a protected target resource in the ABAC catalog."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO abac_resources 
                (resource_id, name, resource_type, required_department, min_clearance_level, required_squad, sensitivity, is_restricted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.resource_id, r.name, r.resource_type, r.required_department,
                r.min_clearance_level, r.required_squad, r.sensitivity, 1 if r.is_restricted else 0
            ))
            conn.commit()
        return r

    def get_user(self, user_id: str) -> Optional[ABACUserRecord]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM abac_users WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
            if not row:
                return None
            return ABACUserRecord(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                department=row["department"],
                clearance_level=row["clearance_level"],
                assigned_squads=json.loads(row["assigned_squads"]),
                roles=json.loads(row["roles"]),
                is_admin=bool(row["is_admin"]),
            )

    def get_resource(self, resource_id: str) -> Optional[ABACResourceRecord]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM abac_resources WHERE resource_id = ?", (resource_id,))
            row = cur.fetchone()
            if not row:
                return None
            return ABACResourceRecord(
                resource_id=row["resource_id"],
                name=row["name"],
                resource_type=row["resource_type"],
                required_department=row["required_department"],
                min_clearance_level=row["min_clearance_level"],
                required_squad=row["required_squad"],
                sensitivity=row["sensitivity"],
                is_restricted=bool(row["is_restricted"]),
            )

    def evaluate_access(self, user_id: str, resource_id: str) -> ABACEvaluationResult:
        """
        Evaluates dynamic access control according to the enterprise ABAC policy.
        """
        start_time = time.perf_counter()
        eval_id = f"EVAL-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        user = self.get_user(user_id)
        resource = self.get_resource(resource_id)

        if not user:
            res = ABACEvaluationResult(
                evaluation_id=eval_id,
                timestamp=timestamp,
                user_id=user_id,
                resource_id=resource_id,
                decision="DENY",
                reason=f"User '{user_id}' not found in enterprise identity catalog.",
                clearance_met=False,
                department_matched=False,
                squad_matched=False,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )
            self._log_evaluation(res)
            return res

        if not resource:
            res = ABACEvaluationResult(
                evaluation_id=eval_id,
                timestamp=timestamp,
                user_id=user_id,
                resource_id=resource_id,
                decision="DENY",
                reason=f"Target resource '{resource_id}' not found in registry.",
                clearance_met=False,
                department_matched=False,
                squad_matched=False,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )
            self._log_evaluation(res)
            return res

        # 1. Check Restricted Status
        if resource.is_restricted and not user.is_admin:
            res = ABACEvaluationResult(
                evaluation_id=eval_id,
                timestamp=timestamp,
                user_id=user_id,
                resource_id=resource_id,
                decision="DENY",
                reason=f"Resource '{resource.name}' is marked RESTRICTED (Isolated Perimeter).",
                clearance_met=False,
                department_matched=False,
                squad_matched=False,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )
            self._log_evaluation(res)
            return res

        # 2. Check Admin Override
        if user.is_admin:
            res = ABACEvaluationResult(
                evaluation_id=eval_id,
                timestamp=timestamp,
                user_id=user_id,
                resource_id=resource_id,
                decision="ALLOW",
                reason=f"Admin access granted for {user.username} ({user.email}).",
                clearance_met=True,
                department_matched=True,
                squad_matched=True,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )
            self._log_evaluation(res)
            return res

        # 3. Clearance Level Validation
        user_clearance_rank = CLEARANCE_HIERARCHY.get(user.clearance_level, 0)
        req_clearance_rank = CLEARANCE_HIERARCHY.get(resource.min_clearance_level, 5)
        clearance_met = user_clearance_rank >= req_clearance_rank

        # 4. Department Match
        department_matched = (user.department.lower() == resource.required_department.lower())

        # 5. Squad Overlap
        squad_matched = (resource.required_squad in user.assigned_squads)

        if clearance_met and department_matched and squad_matched:
            decision = "ALLOW"
            reason = f"Verified: Clearance ({user.clearance_level} >= {resource.min_clearance_level}), Dept ({user.department}), and Squad ({resource.required_squad}) match."
        else:
            decision = "DENY"
            reasons = []
            if not clearance_met:
                reasons.append(f"Insufficient clearance ({user.clearance_level} < {resource.min_clearance_level})")
            if not department_matched:
                reasons.append(f"Department mismatch ({user.department} != {resource.required_department})")
            if not squad_matched:
                reasons.append(f"User not member of required squad '{resource.required_squad}'")
            reason = "Denied: " + ", ".join(reasons)

        res = ABACEvaluationResult(
            evaluation_id=eval_id,
            timestamp=timestamp,
            user_id=user_id,
            resource_id=resource_id,
            decision=decision,
            reason=reason,
            clearance_met=clearance_met,
            department_matched=department_matched,
            squad_matched=squad_matched,
            latency_ms=(time.perf_counter() - start_time) * 1000,
        )
        self._log_evaluation(res)
        return res

    def _log_evaluation(self, res: ABACEvaluationResult):
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO abac_audit_logs 
                (evaluation_id, timestamp, user_id, resource_id, decision, reason, clearance_met, department_matched, squad_matched, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                res.evaluation_id, res.timestamp, res.user_id, res.resource_id,
                res.decision, res.reason, 1 if res.clearance_met else 0,
                1 if res.department_matched else 0, 1 if res.squad_matched else 0,
                res.latency_ms
            ))
            conn.commit()

    def list_users(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM abac_users ORDER BY is_admin DESC, username ASC")
            rows = cur.fetchall()
            return [
                {
                    "user_id": r["user_id"],
                    "username": r["username"],
                    "email": r["email"],
                    "department": r["department"],
                    "clearance_level": r["clearance_level"],
                    "assigned_squads": json.loads(r["assigned_squads"]),
                    "roles": json.loads(r["roles"]),
                    "is_admin": bool(r["is_admin"]),
                }
                for r in rows
            ]

    def list_resources(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM abac_resources ORDER BY resource_id ASC")
            rows = cur.fetchall()
            return [
                {
                    "resource_id": r["resource_id"],
                    "name": r["name"],
                    "resource_type": r["resource_type"],
                    "required_department": r["required_department"],
                    "min_clearance_level": r["min_clearance_level"],
                    "required_squad": r["required_squad"],
                    "sensitivity": r["sensitivity"],
                    "is_restricted": bool(r["is_restricted"]),
                }
                for r in rows
            ]

    def list_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM abac_audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]


abac_engine = ABACPolicyEngine()

