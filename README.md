# 🔥 Prometheus Enterprise: Autonomous API Penetration Testing & Runtime Capability Hypervisor

[![Enterprise Grade](https://img.shields.io/badge/Enterprise-API_Security-blueviolet.svg)]()
[![Google GenAI SDK](https://img.shields.io/badge/Google_GenAI-Gemini_3.7_Flash-4285F4.svg)](https://ai.google.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-stdio_%7C_SSE-00C7B7.svg)]()
[![Security](https://img.shields.io/badge/security-ABAC_%7C_Capability_Hypervisor-critical.svg)]()
[![CI/CD SLA](https://img.shields.io/badge/CI%2FCD_Gate-%3C85s_SLA-emerald.svg)]()

> **The Zero False-Positive API Vulnerability Discovery & Autonomous Remediation Engine**  
> *Transforming OpenAPI specifications into topologically sorted route dependency DAGs, verifying BOLA/BFLA exploitability via cryptographic canary reflection defense, synthesizing certified AST source repairs with CEGIS dual-pass verifiers, and enforcing runtime tool safety via an inline cryptographic Capability Hypervisor.*

---

## 🏛️ System Architecture

```text
       [ CI/CD Pipeline / GitHub Actions / Developer Terminal / CLI / MCP ]
                                         │
                                         ▼
                 ┌──────────────────────────────────────────────┐
                 │          API Lineage Graph Engine            │
                 │   - OpenAPI 3.x Ingestion & Schema Parsing   │
                 │   - Tarjan SCC Topological Condensation      │
                 │   - State Synthesizer (Victims / Seed Pairs) │
                 └───────────────────────┬──────────────────────┘
                                         │
                                         ▼
                 ┌──────────────────────────────────────────────┐
                 │       Autonomous Exploit Prober Gate         │
                 │   - Dual-Tenant Persona Probing (BOLA/BFLA)  │
                 │   - Reflection Defense (Cryptographic Canary)│
                 │   - SSRF Multi-Tier Rebinding Defense        │
                 │   - Strict Zero False-Positive Invariant     │
                 └───────────────────────┬──────────────────────┘
                                         │
                                         ▼
                 ┌──────────────────────────────────────────────┐
                 │     CEGIS Dual-Pass Program Repair           │
                 │   - Gemini 3.7 Flash Guided AST Rewriter     │
                 │   - Pass 1: Neutralize Attacker (403/404)    │
                 │   - Pass 2: Preserve Victim Workflows (200)  │
                 │   - Automated Unified Git Patch Generation   │
                 └───────────────────────┬──────────────────────┘
                                         │
                                         ▼
                 ┌──────────────────────────────────────────────┐
                 │         Inline Capability Hypervisor         │
                 │   - Pre-State Witness H(S) Ledger (HMAC)     │
                 │   - Monotonic Single-Use Action Permits      │
                 │   - Structured Semantic Denial Envelopes     │
                 │   - Fail-Closed Policy Enforcement Engine    │
                 └──────────────────────────────────────────────┘
```

---

## ⚡ Core Pillars

### 1. Zero False-Positive Exploitation (Reflection Defense)
Traditional DAST tools flood security teams with false alarms based on HTTP status codes. Prometheus enforces a **cryptographic reflection defense**:
- High-entropy canaries are harvested from legitimate tenant sessions.
- An exploit is confirmed **only if** the unauthorized actor retrieves the exact private canary belonging to the victim tenant.
- Eliminates 100% of status-code hallucinations and benign 200 OK reflections.

### 2. Autonomous Program Repair (CEGIS Dual-Pass AST Verification)
When a flaw is verified, Prometheus does not just alert; it generates and validates source code fixes:
- Parses target source code into Abstract Syntax Trees (AST).
- Synthesizes tenant isolation guards and authorization decorators using Gemini 3.7 Flash.
- Evaluates candidates against a **Counterexample-Guided Inductive Synthesis (CEGIS)** dual-pass test oracle:
  - **Pass 1 (Attacker Invariant)**: Unauthorized probe must yield `403 Forbidden` or `404 Not Found`.
  - **Pass 2 (Victim Invariant)**: Legitimate owner requests must continue to return `200 OK` with valid data.
- Outputs clean, verified unified diff patches ready for merge.

### 3. Inline Capability Hypervisor & Token Authority
To protect APIs from autonomous tool and agent abuse at runtime, Prometheus provides an inline gateway:
- **Capability Tokens**: Cryptographically signed, scoped tokens defining authorized operations.
- **Pre-State Witnesses $H(S)$**: Hashes and validates target resource state prior to mutation to prevent TOCTOU race conditions.
- **Single-Use Action Permits**: Monotonic, tamper-evident action permits that prevent replay attacks.
- **Semantic Denial Envelopes**: Structured recovery payloads returned upon denial, detailing the exact violated invariant and remediation guidance.

### 4. Enterprise ABAC & Security Perimeter
- Sub-millisecond Attribute-Based Access Control (ABAC) evaluation engine.
- Persistent audit logging with microsecond-level timing and deterministic clearance verification.
- SSRF defense blocking RFC 1918 subnets, cloud metadata services (AWS IPv6 `fd00:ec2::254`, GCP, Azure, OCI), and DNS rebinding vectors.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- Virtual environment with dependencies installed:
  ```bash
  pip install -e .
  ```

### Run CI/CD Vulnerability Scan
Execute an autonomous vulnerability assessment against a live OpenAPI endpoint:
```bash
python -m prometheus.cli_scan \
  --target-url http://localhost:8000 \
  --spec-url /openapi.json \
  --sla-budget-s 85.0 \
  --output-sarif prometheus-report.sarif
```

### Run the Prometheus Security Engine Service
```bash
uvicorn prometheus.main:app --host 0.0.0.0 --port 8000 --reload
```
Access the interactive dashboard at `http://localhost:8000/dashboard` and OpenAPI documentation at `http://localhost:8000/docs`.

### Run Test Suite
```bash
pytest tests/ -v
```

---

## 🛡️ Model Context Protocol (MCP) Integration & Live Security Gateway

Prometheus exposes its security engine and hypervisor capabilities as standard MCP tools via both stdio and Server-Sent Events (SSE) transports, and operates as a **Live MCP Reverse-Proxy Security Gateway** (`/api/v1/mcp/gateway/proxy`):
- `scan_api_security`: Trigger autonomous API discovery and dual-tenant penetration testing.
- `mint_capability_token`: Mint cryptographically bound capability tokens for agent operations.
- `request_action_permit`: Request single-use monotonic permits for state-mutating API actions.
- `verify_action_permit`: Validate an action permit against pre-state witness $H(S)$ prior to mutation.
- `inspect_agentic_payload`: Evaluate tool calls and RAG context against the **2026 OWASP Agentic Top 10 (`ASI01`–`ASI10`)** and CoSAI DLP guardrails.

---

## 🏢 Commercial SaaS, Multi-Tenant API Keys & Compliance Exports

Built for **Hybrid PLG + Enterprise Sales** (`Starter` \$0/mo, `Pro` \$499/mo, `Enterprise Guard` \$7,500/mo):
- **Multi-Tenant Scoped API Keys (`/api/v1/saas/api-keys`)**: Mint `prom_live_...` keys hashed with SHA-256 at rest, supporting `X-API-Key` and `Bearer` authentication with per-tenant sliding-window rate limits.
- **OWASP Agentic Top 10 Shield (`/api/v1/security/agentic/*`)**: Real-time deterministic blocking of Agent Goal Hijack (`ASI01`), Tool Misuse (`ASI02`), Non-Human Identity Abuse (`ASI03`), Supply Chain Schema Poisoning (`ASI04`), Sandbox Escape (`ASI05`), Memory Poisoning (`ASI06`), Unsafe Delegation (`ASI07`), Hallucinated IDs (`ASI08`), Human Trust Exploitation (`ASI09`), and Autonomous Exfiltration (`ASI10`).
- **Signed Compliance Ledgers (`/api/v1/saas/compliance/export`)**: Generates cryptographically verifiable **EU AI Act Art. 12/15**, **SOC 2 Type II**, and **CoSAI** audit bundles anchored by a SHA-256 Merkle state root and HMAC-SHA256 signature.

---

## 🔒 Security & Compliance
- **Zero-Mock Policy**: All scan routines, cryptographic verifications, and proxy gates execute real protocols and verifiable payloads.
- **SSRF Defense-in-Depth**: Strict IP validation with loopback-only override support for local test suites.
- **Fail-Closed Runtime**: Missing tokens, expired permits, or altered pre-state witnesses result in deterministic denial.
