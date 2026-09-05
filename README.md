# 🔥 Prometheus: Enterprise Workstream Observability & Asynchronous Orchestration Platform

[![Enterprise Grade](https://img.shields.io/badge/Enterprise-Fleet_Observability-blueviolet.svg)]()
[![Google GenAI SDK](https://img.shields.io/badge/Google_GenAI-Gemini_3.7_Flash-4285F4.svg)](https://ai.google.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-stdio_%7C_SSE-00C7B7.svg)]()
[![Gemini Enterprise Agent Platform](https://img.shields.io/badge/Agent_Engine-Vertex_AI-34A853.svg)](https://cloud.google.com/vertex-ai)
[![Security](https://img.shields.io/badge/security-ABAC_%7C_Model_Armor-critical.svg)]()
[![HITL](https://img.shields.io/badge/HITL-Propose%2C_Don't_Impose-FF6F00.svg)]()

> **Autonomous AI Chief of Staff & Engineering Fleet Intelligence**  
> *Correlating cross-functional engineering telemetry (GitHub, Jira, Slack, CI/CD), isolating data via deterministic ABAC/RLS, and proposing contextual remediation actions for human sign-off ("Propose, Don't Impose") on Google Cloud Vertex AI and Cloud Run.*

---

## 🏛️ System Architecture & Sub-Agent Fleet

```text
                          [ User Query / 08:00 AM Cron / Webhook / MCP ]
                                                │
                                                ▼
                                ┌───────────────────────────────────┐
                                │    Router & Guardrail Agent       │
                                │   - ABAC & Scope Perimeter Check  │
                                │   - Prompt Defense / PII Filter   │
                                └────────────────┬──────────────────┘
                                                 │
                         ┌───────────────────────┼──────────────────────┐
                         ▼                       ▼                      ▼
             ┌──────────────────────┐ ┌───────────────────┐ ┌──────────────────────┐
             │ Git & CI/CD Ingestion│ │  Project Tracker  │ │ Workstream Ingestion │
             │ - GitHub / GitLab    │ │  - Jira / Linear  │ │ - Public Slack/Teams │
             │ - PR latency / CI    │ │  - Epics/Blockers │ │ - Calendar Metadata  │
             └──────────┬───────────┘ └─────────┬─────────┘ └──────────┬───────────┘
                         │                      │                      │
                         └──────────────────────┼──────────────────────┘
                                                │ (Aggregated Telemetry via MCP)
                                                ▼
                                ┌───────────────────────────────────┐
                                │    Synthesis & Blocker Agent      │
                                │    - Gemini 3.7 Flash on Vertex AI│
                                │    - Enterprise Async Execution   │
                                │    - Root-Cause Bottleneck Finder │
                                └────────────────┬──────────────────┘
                                                 │
                                                 ▼
                                ┌───────────────────────────────────┐
                                │     Action & Drafting Agent       │
                                │     - "Propose, Don't Impose"     │
                                │     - Slack Block Kit Action Cards│
                                └────────────────┬──────────────────┘
                                                 │
                                                 ▼
                                   [ Human Approval Checkpoint ]
                                   (Approve / Edit / Discard)
                                                 │
                                     ┌───────────┴───────────┐
                                     ▼                       ▼
                            [ Approved: Dispatch ]   [ Rejected: Abort ]
                             - Slack DM / Jira SDK
```

---

## 🌟 Enterprise Fleet Architectural Pillars

| Pillar | Platform Implementation | Capabilities |
| :--- | :--- | :--- |
| **Discovery & Lifecycle** | **Agent Registry** (`app/registry/`) | Central cataloging, schema validation, tool binding, and versioning for all 6 sub-agents. |
| **Core Execution & State** | **Async DAG + Memory Bank** (`app/memory/`) | Checkpointing, multi-week blocker lifecycles, SQLite persistence, and human approval state machines. |
| **Security & Governance** | **ABAC Perimeter & Model Armor** (`app/security/`) | Deterministic scope validation $P(U,R)$, PII redaction (tokens, emails, phone numbers), and prompt injection filters. |
| **Observability & Protocols** | **Hybrid MCP + Structured Traces** (`app/mcp/`) | Dual `stdio` & `SSE` Model Context Protocol transports + OpenTelemetry trace headers. |

---

## ⚡ Vertex AI & Gemini Enterprise Agent Platform

Prometheus is unified exclusively on **Gemini 3.7 Flash** powered by Google Cloud Vertex AI & the Gemini Enterprise Agent Platform:

- **Enterprise IAM & ADC**: Uses native Google Cloud Application Default Credentials (ADC) and IAM service accounts with zero raw API keys exposed.
- **Non-Blocking Async Engine**: Native `client.aio.models.generate_content()` execution with timeout guards preventing event loop starvation.
- **Telemetry Delta Caching**: Inputs are hashed (`SHA-256`) to return cached digests for unchanged telemetry, saving token consumption and latency.
- **Agent Engine Hosting**: Designed to deploy natively onto the Gemini Enterprise Agent Platform (Agent Engine).

---

## 📁 Repository Layout

```text
prometheus/
├── app/
│   ├── __init__.py
│   ├── config.py                 # Gemini 3.7 Flash, Vertex AI & Agent Engine settings
│   ├── main.py                   # FastAPI REST API, MCP SSE Stream & CLI runner
│   ├── scheduler.py              # Background 08:00 AM async cron scheduler
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── router_agent.py       # ABAC & Guardrail security perimeter
│   │   ├── git_agent.py          # GitHub/CI ingestion agent
│   │   ├── jira_agent.py         # Jira/Linear project tracker agent
│   │   ├── workstream_agent.py   # Slack & calendar ingestion agent
│   │   ├── synthesis_agent.py    # Multi-domain correlation (Gemini 3.7 Flash)
│   │   └── action_agent.py       # HITL action drafter with Slack Block Kit
│   ├── llm/
│   │   ├── __init__.py
│   │   └── gemini_pool.py        # Vertex AI Gemini 3.7 Flash engine & cache
│   ├── mcp/
│   │   ├── __init__.py
│   │   ├── protocol.py           # MCP JSON-RPC 2.0 schemas
│   │   ├── server.py             # Prometheus MCP Server (stdio & SSE)
│   │   └── client.py             # MCP Client adapter for external tools
│   ├── registry/
│   │   ├── __init__.py
│   │   └── agent_registry.py     # Sub-Agent cataloging & discovery
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── github_tools.py       # Git PR & CI status tools
│   │   ├── jira_tools.py         # Project management tools
│   │   └── slack_tools.py        # Communication drafting & dispatch tools
│   ├── security/
│   │   ├── __init__.py
│   │   ├── abac_guard.py         # Attribute-Based Access Control (ABAC/RLS)
│   │   └── guardrails.py         # Inline prompt defense & PII sanitizer
│   ├── memory/
│   │   ├── __init__.py
│   │   └── state_store.py        # Durable SQLite session checkpointing & audit store
│   └── workflows/
│       ├── __init__.py
│       └── prometheus_flow.py    # Multi-agent asynchronous orchestration DAG
├── tests/
│   ├── mock_telemetry.py         # Test fixtures & telemetry generators
│   └── test_workflow.py          # Hermetic multi-agent & security test suite
├── .github/
│   └── workflows/ci.yml          # GitHub Actions automated CI pipeline
├── deploy_gcp.sh                 # Deployment script for Gemini Enterprise Agent Engine
├── Dockerfile                    # Multi-stage production containerfile
├── Procfile                      # PaaS process definition
├── requirements.txt              # Production & test dependencies
├── PROJECT_SPEC.md               # Detailed system design specification
└── .env.example                  # Environment variables template
```

---

## 🚀 Quickstart & Setup

### 1. Installation

```bash
# Clone repository
git clone https://github.com/Tony-Stark2025/prometheus.git
cd prometheus

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Authenticate with Google Cloud
gcloud auth application-default login
```

### 3. Run the Interactive CLI Demo

```bash
python app/main.py --cli
```

### 4. Run the REST API & MCP Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **OpenAPI Interactive Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **MCP Server-Sent Events Endpoint**: `http://localhost:8000/mcp/sse`
- **Agent Registry Discovery**: `http://localhost:8000/api/v1/registry/agents`

---

## 🌐 Live Google Cloud Deployments

| Component | Target Infrastructure | Live GCP Resource / URL | Status |
| :--- | :--- | :--- | :--- |
| **Multi-Agent Reasoning Fleet** | **Vertex AI Agent Engine** (`us-central1`) | `projects/135010851380/locations/us-central1/reasoningEngines/954065480874721280` | `ACTIVE / SERVING` |
| **FastAPI Backend & MCP Server** | **Google Cloud Run** (`us-central1`) | [prometheus-chief-of-staff-135010851380.us-central1.run.app](https://prometheus-chief-of-staff-135010851380.us-central1.run.app) | `ACTIVE / 100% TRAFFIC` |
| **Interactive Executive Dashboard** | **Cloud Run Web UI** | [prometheus-chief-of-staff-135010851380.us-central1.run.app/dashboard](https://prometheus-chief-of-staff-135010851380.us-central1.run.app/dashboard) | `200 OK` |
| **Model Context Protocol (MCP)** | **Cloud Run SSE Endpoint** | `POST https://prometheus-chief-of-staff-135010851380.us-central1.run.app/mcp/sse` | `JSON-RPC 2.0` |
| **Foundation Model** | **Gemini 3.7 Flash** | Standardized Vertex AI Model | `SERVING` |

---

## 🔌 Connecting to Claude Desktop / Antigravity via MCP

Add Prometheus to your MCP client configuration (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "prometheus-cloud": {
      "url": "https://prometheus-chief-of-staff-135010851380.us-central1.run.app/mcp/sse"
    },
    "prometheus-local": {
      "command": "python",
      "args": ["-m", "prometheus.mcp.server"]
    }
  }
}
```

---

## ☁️ Deployment on Google Cloud (Agent Engine & Cloud Run)

### 1. Deploy Reasoning Engine to Vertex AI Agent Engine:
```bash
python deploy_agent_engine.py --project gen-lang-client-0942141479 --location us-central1
```

### 2. Deploy Container to Google Cloud Run:
```bash
gcloud run deploy prometheus-chief-of-staff \
    --source . \
    --region=us-central1 \
    --allow-unauthenticated \
    --port=8080 \
    --set-env-vars="USE_VERTEX_AI=true,GCP_PROJECT_ID=gen-lang-client-0942141479,GCP_LOCATION=us-central1,AGENT_ENGINE_APP_ID=projects/135010851380/locations/us-central1/reasoningEngines/954065480874721280,ENVIRONMENT=production,MCP_ENABLED=true"
```

### 3. Verify Live Deployments Programmatically:
```bash
# Verify live Vertex AI Reasoning Engine
python deploy_agent_engine.py --verify-only projects/135010851380/locations/us-central1/reasoningEngines/954065480874721280

# Verify full 157-test matrix
pytest -v
```

---

## 🔐 Google Secret Manager Integration

Configure secrets securely via Google Secret Manager URIs in `.env` or Cloud Run environment variables:
```bash
GITHUB_TOKEN=sm://prometheus-github-token
JIRA_API_TOKEN=sm://prometheus-jira-token
SLACK_BOT_TOKEN=sm://prometheus-slack-token
```
Prometheus automatically resolves `sm://<secret_id>` directly from Google Cloud Secret Manager at startup with zero secret exposure in logs.

---

## 🧪 Testing

Run the comprehensive 5-tier test matrix:

```bash
pytest tests/ -v
```
All 157 tests execute hermetically with zero mock leakage.
