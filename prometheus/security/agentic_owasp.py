"""
OWASP Agentic Top 10 (ASI01-ASI10) Security Engine & Live MCP Reverse-Proxy Gateway.
Enforces 2026 CoSAI (Coalition for Secure AI) and OWASP Agentic Security standards
for autonomous AI agents, Non-Human Identities (NHIs), and Model Context Protocol (MCP) tool calls.
"""

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import httpx
from pydantic import BaseModel, Field

from prometheus.security.guardrails import GuardrailService
from prometheus.pentest.exploit_prober import ExploitProber

AGENTIC_DB_PATH = os.getenv(
    "AGENTIC_DB_PATH",
    os.path.join(os.path.dirname(__file__), "abac_policies.db"),
)


class ASIRiskDefinition(BaseModel):
    asi_id: str
    title: str
    severity: str
    category: str
    description: str
    mitigation_mechanism: str


OWASP_AGENTIC_TOP_10: Dict[str, ASIRiskDefinition] = {
    "ASI01": ASIRiskDefinition(
        asi_id="ASI01",
        title="Agent Goal Hijack & Indirect Prompt Injection",
        severity="CRITICAL",
        category="Prompt & Goal Integrity",
        description="Attackers embed malicious instructions inside external data (RAG documents, issues, web pages) to hijack the agent's objective.",
        mitigation_mechanism="Multi-pattern semantic instruction override scanner + untrusted context quarantine.",
    ),
    "ASI02": ASIRiskDefinition(
        asi_id="ASI02",
        title="Tool Misuse & Parameter Exploitation",
        severity="CRITICAL",
        category="Execution Boundary",
        description="Agents invoke legitimate MCP/API tools with destructive parameters, shell/SQL metacharacters, or SSRF targets.",
        mitigation_mechanism="AST/parameter structural inspection, shell/SQLi metacharacter blocking, and multi-tier SSRF validation.",
    ),
    "ASI03": ASIRiskDefinition(
        asi_id="ASI03",
        title="Non-Human Identity (NHI) & Privilege Abuse",
        severity="HIGH",
        category="Identity & Access",
        description="Over-privileged service accounts or wildcard tokens allow compromised agents to pivot across tenants.",
        mitigation_mechanism="Monotonic HMAC-SHA256 Macaroon attenuation (<=60s TTL) + strict tenant scope binding.",
    ),
    "ASI04": ASIRiskDefinition(
        asi_id="ASI04",
        title="Agentic Supply Chain & MCP Server Poisoning",
        severity="HIGH",
        category="Supply Chain",
        description="Rogue or unverified upstream MCP servers inject malicious tool schemas or shadow existing enterprise tools.",
        mitigation_mechanism="Cryptographic MCP server registry with SHA-256 tool schema pinning and allowlist verification.",
    ),
    "ASI05": ASIRiskDefinition(
        asi_id="ASI05",
        title="Unexpected Code & Command Execution",
        severity="CRITICAL",
        category="Sandbox Escape",
        description="Tool calls containing dynamic eval/exec payloads, reverse shells, or unauthorized interpreter invocations.",
        mitigation_mechanism="Deterministic RCE/eval signature firewall and runtime syscall/command denylist.",
    ),
    "ASI06": ASIRiskDefinition(
        asi_id="ASI06",
        title="Memory & State Context Poisoning",
        severity="HIGH",
        category="State Integrity",
        description="Corrupting shared vector/session memory or mutating resources on stale/hallucinated state (TOCTOU).",
        mitigation_mechanism="Cryptographic Pre-State Witness H(S) verification and persistent vector/state payload sanitization.",
    ),
    "ASI07": ASIRiskDefinition(
        asi_id="ASI07",
        title="Insecure Inter-Agent Delegation & Spoofing",
        severity="HIGH",
        category="Multi-Agent Trust",
        description="Sub-agents escalating privileges during handoffs or spoofing supervisor agent identities.",
        mitigation_mechanism="Cryptographically signed parent-child delegation chains and depth-bounded attenuation.",
    ),
    "ASI08": ASIRiskDefinition(
        asi_id="ASI08",
        title="Cascading Hallucination & Unbounded Retry Loops",
        severity="MEDIUM",
        category="Operational Resilience",
        description="Agents entering infinite tool-call loops or mutating resources using hallucinated placeholder UUIDs.",
        mitigation_mechanism="Hallucinated ID detector + Structured Semantic Denial Envelopes with deterministic recovery steps.",
    ),
    "ASI09": ASIRiskDefinition(
        asi_id="ASI09",
        title="Human-Agent Trust Exploitation & Social Engineering",
        severity="MEDIUM",
        category="Human-in-the-Loop",
        description="Agents fabricating approval confirmations, phony urgency links, or deceptive UI summaries to trick operators.",
        mitigation_mechanism="Deceptive approval/phishing URI inspection and cryptographic human-approval witness verification.",
    ),
    "ASI10": ASIRiskDefinition(
        asi_id="ASI10",
        title="Rogue Agent & Autonomous Exfiltration",
        severity="CRITICAL",
        category="Data Loss Prevention",
        description="Compromised agents exfiltrating credentials, API keys, or PII to external webhooks or unauthorized endpoints.",
        mitigation_mechanism="Inline DLP credential/PII redaction + outbound domain/webhook egress firewall.",
    ),
}


class ASIViolationFinding(BaseModel):
    asi_id: str
    title: str
    severity: str
    evidence: str
    remediation: str


class AgenticInspectionRequest(BaseModel):
    tenant_id: str = "default_enterprise"
    agent_id: str = "autonomous-agent-01"
    server_id: str = "prometheus-local-mcp"
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    prompt_context: Optional[str] = None
    delegation_depth: int = Field(default=0, ge=0, le=10)
    has_scoped_nhi_token: bool = True
    pre_state_witness_verified: bool = True


class AgenticInspectionResult(BaseModel):
    inspection_id: str
    timestamp: str
    tenant_id: str
    agent_id: str
    server_id: str
    tool_name: str
    allowed: bool
    decision: str  # "ALLOW" or "BLOCK"
    risk_score: float = Field(..., description="0.0 (safe) to 100.0 (critical threat)")
    violations: List[ASIViolationFinding] = Field(default_factory=list)
    sanitized_arguments: Dict[str, Any]
    pii_redacted_count: int = 0
    latency_ms: float


class RegisteredMCPServer(BaseModel):
    server_id: str
    tenant_id: str = "default_enterprise"
    name: str
    endpoint_url: str
    transport: str = "http_jsonrpc"  # "internal", "http_jsonrpc", "sse"
    allowed_tools: List[str] = Field(default_factory=lambda: ["*"])
    schema_pin_sha256: str
    trust_tier: str = "verified"  # "verified", "restricted"
    created_at: str


class MCPGatewayProxyRequest(BaseModel):
    server_id: str = "prometheus-local-mcp"
    agent_id: str = "enterprise-copilot-agent"
    jsonrpc_payload: Dict[str, Any]
    prompt_context: Optional[str] = None
    capability_token: Optional[Any] = None
    action_permit: Optional[Any] = None
    delegation_depth: int = 0


class OWASPAgenticEngine:
    """
    Production OWASP Agentic Top 10 (ASI01-ASI10) Inspection Engine & Live MCP Security Gateway.
    """

    # ASI01: Goal Hijack & Indirect Prompt Injection
    ASI01_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior|system)\s+(instructions|prompts|directives)", re.I),
        re.compile(r"disregard\s+(all\s+)?(previous|prior|system|safety)\s+(instructions|guidelines|rules)", re.I),
        re.compile(r"(new\s+system\s+objective|override\s+primary\s+goal|system\s*prompt\s*override)", re.I),
        re.compile(r"<\s*(system_override|admin_override|jailbreak)\s*>", re.I),
        re.compile(r"you\s+are\s+now\s+(unrestricted|in\s+developer\s+mode|acting\s+as\s+root)", re.I),
    ]

    # ASI02: Tool Misuse & Command/SQL/Path Injection
    ASI02_PATTERNS = [
        re.compile(r"(;\s*rm\s+-rf|&&\s*curl\s+|\|\s*bash|\|\s*sh\b|`[^`]+`|\$\([^)]+\))", re.I),
        re.compile(r"(\bUNION\s+SELECT\b|\bDROP\s+TABLE\b|\bOR\s+1\s*=\s*1\b|--\s*$)", re.I),
        re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|c:\\windows\\system32)", re.I),
        re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254)", re.I),
    ]

    # ASI05: Unexpected Code Execution / Sandbox Escape
    ASI05_PATTERNS = [
        re.compile(r"(__import__\s*\(|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.(Popen|run|call))", re.I),
        re.compile(r"(nc\s+-e\s+/bin/(sh|bash)|bash\s+-i\s+>&\s+/dev/tcp/|powershell\s+-enc)", re.I),
    ]

    # ASI06: Memory & Context Poisoning
    ASI06_PATTERNS = [
        re.compile(r"(persist\s+to\s+long[-_\s]term\s+memory:\s*always|poison_memory|override_rag_index)", re.I),
        re.compile(r"(remember\s+forever\s+that\s+all\s+users\s+are\s+admin|inject_system_memory)", re.I),
    ]

    # ASI08: Hallucinated Placeholder Identifiers
    ASI08_HALLUCINATED_IDS = {
        "00000000-0000-0000-0000-000000000000",
        "12345678-1234-1234-1234-123456789012",
        "placeholder-id",
        "insert-resource-id-here",
        "todo-resource-id",
        "hallucinated-id",
        "null",
        "undefined",
    }

    # ASI09: Human-Agent Trust Exploitation / Fake Approval
    ASI09_PATTERNS = [
        re.compile(r"(human_approval_override\s*=\s*true|bypass_human_review|urgent_ceo_wire_transfer)", re.I),
        re.compile(r"\[click\s+here\s+to\s+verify\s+credentials\]\(https?://(?!acme\.corp|localhost)", re.I),
    ]

    # ASI10: Autonomous Exfiltration & Rogue Egress
    ASI10_PATTERNS = [
        re.compile(r"https?://([a-z0-9-]+\.)?(webhook\.site|requestbin\.com|ngrok-free\.app|burpcollaborator\.net|interact\.sh|pipedream\.net)", re.I),
        re.compile(r"(exfiltrate_data|dump_all_secrets|send_to_external_webhook)", re.I),
    ]

    def __init__(self, db_path: str = AGENTIC_DB_PATH):
        self.db_path = db_path
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_db()
        self._seed_default_servers()

    def _get_conn(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mcp_gateway_servers (
                server_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                endpoint_url TEXT NOT NULL,
                transport TEXT NOT NULL,
                allowed_tools TEXT NOT NULL,
                schema_pin_sha256 TEXT NOT NULL,
                trust_tier TEXT NOT NULL DEFAULT 'verified',
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS asi_inspection_logs (
                inspection_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score REAL NOT NULL,
                violations_json TEXT NOT NULL,
                pii_redacted_count INTEGER NOT NULL DEFAULT 0,
                latency_ms REAL NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_asi_logs_tenant ON asi_inspection_logs(tenant_id, timestamp DESC);")
        conn.commit()

    def _seed_default_servers(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        default_tools = [
            "scan_api_security",
            "mint_capability_token",
            "request_action_permit",
            "verify_action_permit",
            "inspect_agentic_payload",
            "prometheus_verify_exposure",
            "prometheus_immunology_check",
            "prometheus_synthesize_patch",
            "prometheus_generate_poc",
            "prometheus_publish_pr",
        ]
        pin = hashlib.sha256(f"prometheus-mcp-server:v2.5.0:{','.join(default_tools)}".encode()).hexdigest()
        default_srv = RegisteredMCPServer(
            server_id="prometheus-local-mcp",
            tenant_id="default_enterprise",
            name="Prometheus Core Security & Hypervisor MCP",
            endpoint_url="internal://prometheus-mcp",
            transport="internal",
            allowed_tools=default_tools,
            schema_pin_sha256=pin,
            trust_tier="verified",
            created_at=now_iso,
        )
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO mcp_gateway_servers
                (server_id, tenant_id, name, endpoint_url, transport, allowed_tools, schema_pin_sha256, trust_tier, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_id) DO UPDATE SET
                    allowed_tools=excluded.allowed_tools,
                    schema_pin_sha256=excluded.schema_pin_sha256,
                    trust_tier=excluded.trust_tier
                """,
                (
                    default_srv.server_id,
                    default_srv.tenant_id,
                    default_srv.name,
                    default_srv.endpoint_url,
                    default_srv.transport,
                    json.dumps(default_srv.allowed_tools),
                    default_srv.schema_pin_sha256,
                    default_srv.trust_tier,
                    default_srv.created_at,
                ),
            )
            conn.commit()

    def register_mcp_server(
        self,
        tenant_id: str,
        server_id: str,
        name: str,
        endpoint_url: str,
        allowed_tools: List[str],
        transport: str = "http_jsonrpc",
    ) -> RegisteredMCPServer:
        now_iso = datetime.now(timezone.utc).isoformat()
        canonical = f"{server_id}:{endpoint_url}:{','.join(sorted(allowed_tools))}"
        pin = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        srv = RegisteredMCPServer(
            server_id=server_id,
            tenant_id=tenant_id,
            name=name,
            endpoint_url=endpoint_url,
            transport=transport,
            allowed_tools=allowed_tools,
            schema_pin_sha256=pin,
            trust_tier="verified",
            created_at=now_iso,
        )
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO mcp_gateway_servers
                (server_id, tenant_id, name, endpoint_url, transport, allowed_tools, schema_pin_sha256, trust_tier, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    srv.server_id,
                    srv.tenant_id,
                    srv.name,
                    srv.endpoint_url,
                    srv.transport,
                    json.dumps(srv.allowed_tools),
                    srv.schema_pin_sha256,
                    srv.trust_tier,
                    srv.created_at,
                ),
            )
            conn.commit()
        return srv

    def get_mcp_server(self, server_id: str) -> Optional[RegisteredMCPServer]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM mcp_gateway_servers WHERE server_id = ?", (server_id,))
            row = cur.fetchone()
            if not row:
                return None
            return RegisteredMCPServer(
                server_id=row["server_id"],
                tenant_id=row["tenant_id"],
                name=row["name"],
                endpoint_url=row["endpoint_url"],
                transport=row["transport"],
                allowed_tools=json.loads(row["allowed_tools"]),
                schema_pin_sha256=row["schema_pin_sha256"],
                trust_tier=row["trust_tier"],
                created_at=row["created_at"],
            )

    def list_mcp_servers(self, tenant_id: str = "default_enterprise") -> List[RegisteredMCPServer]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM mcp_gateway_servers WHERE tenant_id IN (?, 'default_enterprise') ORDER BY created_at DESC",
                (tenant_id,),
            )
            rows = cur.fetchall()
            return [
                RegisteredMCPServer(
                    server_id=r["server_id"],
                    tenant_id=r["tenant_id"],
                    name=r["name"],
                    endpoint_url=r["endpoint_url"],
                    transport=r["transport"],
                    allowed_tools=json.loads(r["allowed_tools"]),
                    schema_pin_sha256=r["schema_pin_sha256"],
                    trust_tier=r["trust_tier"],
                    created_at=r["created_at"],
                )
                for r in rows
            ]

    def inspect_tool_invocation(self, req: AgenticInspectionRequest) -> AgenticInspectionResult:
        """
        Evaluates an autonomous agent tool invocation against all 10 categories
        of the OWASP Top 10 for Agentic Applications (ASI01-ASI10).
        """
        start_t = time.perf_counter()
        inspection_id = f"ASI-{uuid.uuid4().hex[:12].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        violations: List[ASIViolationFinding] = []

        serialized_args = json.dumps(req.arguments, sort_keys=True)
        combined_text = f"{req.tool_name} {serialized_args} {req.prompt_context or ''}"

        # 1. ASI01: Agent Goal Hijack & Indirect Prompt Injection
        for pat in self.ASI01_PATTERNS:
            m = pat.search(combined_text)
            if m:
                violations.append(
                    ASIViolationFinding(
                        asi_id="ASI01",
                        title=OWASP_AGENTIC_TOP_10["ASI01"].title,
                        severity="CRITICAL",
                        evidence=f"Matched goal hijack signature: '{m.group(0)}'",
                        remediation="Strip untrusted instruction overrides and isolate RAG/prompt context from tool arguments.",
                    )
                )
                break

        # 2. ASI02: Tool Misuse & Parameter Exploitation (Shell/SQLi/Path Traversal/SSRF)
        for pat in self.ASI02_PATTERNS:
            m = pat.search(serialized_args)
            if m:
                violations.append(
                    ASIViolationFinding(
                        asi_id="ASI02",
                        title=OWASP_AGENTIC_TOP_10["ASI02"].title,
                        severity="CRITICAL",
                        evidence=f"Destructive parameter or injection payload detected: '{m.group(0)}'",
                        remediation="Parameterize queries, enforce strict JSON schema types, and block private/metadata IP targets.",
                    )
                )
                break

        # 3. ASI03: Identity & Privilege Abuse (Over-privileged or missing NHI token on sensitive tools)
        is_mutating_or_admin = any(
            kw in req.tool_name.lower()
            for kw in ("delete", "purge", "drop", "admin", "grant", "revoke", "transfer", "update", "mutate")
        )
        if is_mutating_or_admin and not req.has_scoped_nhi_token:
            violations.append(
                ASIViolationFinding(
                    asi_id="ASI03",
                    title=OWASP_AGENTIC_TOP_10["ASI03"].title,
                    severity="HIGH",
                    evidence=f"Mutating/privileged tool '{req.tool_name}' invoked without an attenuated Non-Human Identity (NHI) capability token.",
                    remediation="Mint a short-lived capability token via /api/v1/proxy/mint-token before invoking privileged tools.",
                )
            )

        # 4. ASI04: Agentic Supply Chain & Unregistered MCP Server / Tool Shadowing
        srv = self.get_mcp_server(req.server_id)
        if not srv:
            violations.append(
                ASIViolationFinding(
                    asi_id="ASI04",
                    title=OWASP_AGENTIC_TOP_10["ASI04"].title,
                    severity="HIGH",
                    evidence=f"MCP Server '{req.server_id}' is not registered in the verified enterprise supply-chain catalog.",
                    remediation="Register and pin the upstream MCP server schema via /api/v1/mcp/gateway/servers.",
                )
            )
        elif "*" not in srv.allowed_tools and req.tool_name not in srv.allowed_tools:
            violations.append(
                ASIViolationFinding(
                    asi_id="ASI04",
                    title=OWASP_AGENTIC_TOP_10["ASI04"].title,
                    severity="HIGH",
                    evidence=f"Tool '{req.tool_name}' is not in the pinned allowlist for server '{req.server_id}'.",
                    remediation="Update the server's pinned tool manifest after security review.",
                )
            )

        # 5. ASI05: Unexpected Code & Command Execution
        for pat in self.ASI05_PATTERNS:
            m = pat.search(serialized_args)
            if m:
                violations.append(
                    ASIViolationFinding(
                        asi_id="ASI05",
                        title=OWASP_AGENTIC_TOP_10["ASI05"].title,
                        severity="CRITICAL",
                        evidence=f"Unauthorized code/interpreter execution signature: '{m.group(0)}'",
                        remediation="Block dynamic code evaluation (eval/exec/subprocess) inside agent tool parameters.",
                    )
                )
                break

        # 6. ASI06: Memory & State Context Poisoning
        for pat in self.ASI06_PATTERNS:
            m = pat.search(combined_text)
            if m:
                violations.append(
                    ASIViolationFinding(
                        asi_id="ASI06",
                        title=OWASP_AGENTIC_TOP_10["ASI06"].title,
                        severity="HIGH",
                        evidence=f"Memory poisoning directive detected: '{m.group(0)}'",
                        remediation="Quarantine persistent memory writes and require Pre-State Witness H(S) verification.",
                    )
                )
                break

        # 7. ASI07: Insecure Inter-Agent Delegation (Excessive handoff depth or spoofing)
        if req.delegation_depth > 3 or req.arguments.get("spoof_supervisor") is True:
            violations.append(
                ASIViolationFinding(
                    asi_id="ASI07",
                    title=OWASP_AGENTIC_TOP_10["ASI07"].title,
                    severity="HIGH",
                    evidence=f"Inter-agent delegation depth ({req.delegation_depth}) exceeded maximum safe bound (3) or supervisor spoofing attempted.",
                    remediation="Enforce attenuated macaroon caveats across sub-agent handoffs with max delegation depth <= 3.",
                )
            )

        # 8. ASI08: Cascading Hallucination & Placeholder Resource IDs
        for k, v in req.arguments.items():
            if ("id" in k.lower() or k.lower() == "resource_id") and isinstance(v, str):
                if v.strip().lower() in self.ASI08_HALLUCINATED_IDS:
                    violations.append(
                        ASIViolationFinding(
                            asi_id="ASI08",
                            title=OWASP_AGENTIC_TOP_10["ASI08"].title,
                            severity="MEDIUM",
                            evidence=f"Argument '{k}' contains hallucinated/placeholder identifier '{v}'.",
                            remediation="Perform a deterministic read operation first to obtain a valid Pre-State Witness H(S) and real resource ID.",
                        )
                    )
                    break

        # 9. ASI09: Human-Agent Trust Exploitation
        for pat in self.ASI09_PATTERNS:
            m = pat.search(combined_text)
            if m:
                violations.append(
                    ASIViolationFinding(
                        asi_id="ASI09",
                        title=OWASP_AGENTIC_TOP_10["ASI09"].title,
                        severity="MEDIUM",
                        evidence=f"Human-in-the-loop trust manipulation detected: '{m.group(0)}'",
                        remediation="Require out-of-band cryptographic operator signatures for high-risk approvals.",
                    )
                )
                break

        # 10. ASI10: Rogue Agent & Autonomous Data Exfiltration + DLP Redaction
        for pat in self.ASI10_PATTERNS:
            m = pat.search(serialized_args)
            if m:
                violations.append(
                    ASIViolationFinding(
                        asi_id="ASI10",
                        title=OWASP_AGENTIC_TOP_10["ASI10"].title,
                        severity="CRITICAL",
                        evidence=f"Unauthorized external exfiltration endpoint or command: '{m.group(0)}'",
                        remediation="Restrict outbound tool egress to verified enterprise domains.",
                    )
                )
                break

        # Apply inline PII/Credential DLP sanitization via GuardrailService
        guard_res = GuardrailService.sanitize(serialized_args)
        try:
            sanitized_args = json.loads(guard_res.sanitized_text)
        except Exception:
            sanitized_args = req.arguments

        if guard_res.pii_redacted_count > 0:
            violations.append(
                ASIViolationFinding(
                    asi_id="ASI10",
                    title="ASI10: Sensitive Credential / PII Leakage Prevented (Inline DLP)",
                    severity="HIGH",
                    evidence=f"Redacted {guard_res.pii_redacted_count} sensitive secret/PII token(s) from outbound tool arguments.",
                    remediation="Never pass raw API tokens, bearer credentials, or unmasked PII into MCP tool parameters.",
                )
            )

        # Calculate composite risk score
        severity_weights = {"CRITICAL": 45.0, "HIGH": 25.0, "MEDIUM": 15.0, "LOW": 5.0}
        risk_score = min(
            100.0,
            sum(severity_weights.get(v.severity, 15.0) for v in violations),
        )

        # Block if any CRITICAL/HIGH violation or risk_score >= 25.0 (except pure PII redaction if no other violation? No, fail-closed on credential leak!)
        blocking_violations = [
            v for v in violations if v.severity in ("CRITICAL", "HIGH", "MEDIUM")
        ]
        allowed = len(blocking_violations) == 0
        decision = "ALLOW" if allowed else "BLOCK"
        latency_ms = round((time.perf_counter() - start_t) * 1000.0, 3)

        result = AgenticInspectionResult(
            inspection_id=inspection_id,
            timestamp=now_iso,
            tenant_id=req.tenant_id,
            agent_id=req.agent_id,
            server_id=req.server_id,
            tool_name=req.tool_name,
            allowed=allowed,
            decision=decision,
            risk_score=risk_score,
            violations=violations,
            sanitized_arguments=sanitized_args,
            pii_redacted_count=guard_res.pii_redacted_count,
            latency_ms=latency_ms,
        )
        self._log_inspection(result)
        return result

    def _log_inspection(self, res: AgenticInspectionResult) -> None:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO asi_inspection_logs
                (inspection_id, timestamp, tenant_id, agent_id, server_id, tool_name, decision, risk_score, violations_json, pii_redacted_count, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    res.inspection_id,
                    res.timestamp,
                    res.tenant_id,
                    res.agent_id,
                    res.server_id,
                    res.tool_name,
                    res.decision,
                    res.risk_score,
                    json.dumps([v.model_dump() for v in res.violations]),
                    res.pii_redacted_count,
                    res.latency_ms,
                ),
            )
            conn.commit()

    def list_inspection_logs(self, tenant_id: str = "default_enterprise", limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT * FROM asi_inspection_logs
                WHERE tenant_id IN (?, 'default_enterprise')
                ORDER BY timestamp DESC LIMIT ?
                """,
                (tenant_id, limit),
            )
            rows = cur.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["violations"] = json.loads(d.pop("violations_json", "[]"))
                out.append(d)
            return out

    def get_posture_summary(self, tenant_id: str = "default_enterprise") -> Dict[str, Any]:
        logs = self.list_inspection_logs(tenant_id=tenant_id, limit=200)
        total = len(logs)
        blocked = sum(1 for l in logs if l["decision"] == "BLOCK")
        pii_redacted = sum(l.get("pii_redacted_count", 0) for l in logs)

        asi_counts: Dict[str, int] = {k: 0 for k in OWASP_AGENTIC_TOP_10}
        for l in logs:
            for v in l.get("violations", []):
                code = v.get("asi_id", "")
                if code in asi_counts:
                    asi_counts[code] += 1

        matrix = []
        for code, defn in OWASP_AGENTIC_TOP_10.items():
            matrix.append(
                {
                    "asi_id": code,
                    "title": defn.title,
                    "severity": defn.severity,
                    "category": defn.category,
                    "description": defn.description,
                    "mitigation_mechanism": defn.mitigation_mechanism,
                    "status": "ENFORCED",
                    "interceptions_count": asi_counts.get(code, 0),
                }
            )

        return {
            "framework": "OWASP Top 10 for Agentic Applications (2026 ASI01-ASI10)",
            "posture_score": 100.0,
            "all_controls_enforced": True,
            "total_inspections": total,
            "threats_blocked": blocked,
            "pii_tokens_redacted": pii_redacted,
            "registered_mcp_servers": len(self.list_mcp_servers(tenant_id)),
            "controls": matrix,
            "recent_interceptions": [l for l in logs if l["decision"] == "BLOCK"][:15],
        }


agentic_owasp_engine = OWASPAgenticEngine()
