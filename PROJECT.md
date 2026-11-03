# Project: Prometheus Enterprise

## Architecture
Prometheus Enterprise is an autonomous API security platform combining a zero false-positive vulnerability discovery engine with a runtime capability hypervisor for modern microservices and AI agent tool execution.

```text
                  ┌──────────────────────────────────────────────────────────┐
                  │                External Ingress Channels                 │
                  │   • Web Dashboard (/dashboard)  • REST API (/api/v1/*)   │
                  │   • MCP Stream (/mcp/sse)       • Webhooks (/webhooks/*) │
                  └─────────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                            Prometheus API Security & Hypervisor Architecture                             │
│                                                                                                          │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ [1] Lineage Graph Engine: OpenAPI 3.x Ingestion, Tarjan SCC Topological Condensation             │   │
│   └─────────────────────────────────────────────┬────────────────────────────────────────────────────┘   │
│                                                 │                                                        │
│                    ┌────────────────────────────┼────────────────────────────┐                           │
│                    ▼                            ▼                            ▼                           │
│   ┌─────────────────────────────┐ ┌─────────────────────────────┐ ┌─────────────────────────────┐        │
│   │ [2] State Synthesizer       │ │ [3] Exploit Prober          │ │ [4] Reflection Defense      │        │
│   │ • Dual-tenant seed pairs    │ │ • BOLA (API1) & BFLA (API5) │ │ • Cryptographic canary      │        │
│   │ • Dynamic JWT minting       │ │ • Multi-tier SSRF blocking  │ │ • Zero false-positive gate  │        │
│   └──────────────┬──────────────┘ └──────────────┬──────────────┘ └──────────────┬──────────────┘        │
│                  └──────────────────────────────┼───────────────────────────────┘                        │
│                                                 ▼                                                        │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ [5] CEGIS Program Repair: Dual-pass AST code synthesis and validation via Gemini 3.7 Flash       │   │
│   │ • Pass 1: Attacker probe neutralization (403/404) • Pass 2: Legitimate owner continuity (200)   │   │
│   └─────────────────────────────────────────────┬────────────────────────────────────────────────────┘   │
│                                                 ▼                                                        │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ [6] Inline Capability Hypervisor & Token Authority: Runtime firewall for API & agent execution   │   │
│   │ • Pre-state witnesses H(S) • Monotonic single-use permits • Semantic denial envelopes            │   │
│   └──────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Code Layout
- `prometheus/`: Root application package:
  - `pentest/`: Core autonomous API penetration testing engine:
    - `lineage_graph.py`: OpenAPI parser and topological dependency condensation.
    - `state_synthesizer.py`: Dual-tenant credential and canary generator.
    - `exploit_prober.py`: BOLA/BFLA probing engine with SSRF guardrails.
    - `reflection_defense.py`: Cryptographic canary reflection verification.
    - `ast_patcher.py`: Abstract Syntax Tree rewriter for automated security patching.
    - `cegis_verifier.py`: Counterexample-Guided Inductive Synthesis dual-pass test oracle.
    - `engine.py` & `agent.py`: High-level scan orchestrator and agent controller.
  - `proxy/`: Inline Capability Hypervisor & Token Authority:
    - `hypervisor.py`: Request interceptor, token validator, and policy gate.
    - `token_authority.py`: Cryptographic token minting and HMAC signature verification.
    - `state_invariants.py`: Pre-state witness hashing $H(S)$ and mutation verification.
    - `denial_envelope.py`: Structured semantic error payloads for agent self-healing.
  - `security/`: ABAC policy evaluation engine (`abac_engine.py`), OWASP Agentic Top 10 (`ASI01`–`ASI10`) & Live MCP Gateway (`agentic_owasp.py`), and prompt/SSRF guardrails (`guardrails.py`).
  - `saas/`: Commercial SaaS multi-tenant organization management, subscription tier catalog (`Starter`/`Pro`/`Enterprise`), SHA-256 API key lifecycle (`prom_live_...`), usage metering, and signed SOC2 / EU AI Act compliance bundle exporter (`models.py`, `engine.py`).
  - `auth/`: Authentication dependencies supporting SaaS API keys (`X-API-Key` / `Bearer`), JWT validation, and RBAC/ABAC models.
  - `mcp/`: JSON-RPC 2.0 Model Context Protocol server exposing security, hypervisor, and OWASP Agentic inspection tools.
  - `memory/`: Google Cloud Firestore client for secure integration credential vaulting.
  - `llm/`: Gemini 3.7 Flash client and telemetry caching layer.
  - `config.py`: Environment settings and configuration validation.
  - `main.py`: FastAPI server, security dashboard, MCP Reverse-Proxy Gateway, SaaS billing APIs, and health checks.
  - `cli_scan.py`: Standalone CLI scanner for CI/CD pipelines (<85s SLA).
- `tests/`: Comprehensive test suite (unit, integration, adversarial matrix, commercial SaaS, and e2e).
