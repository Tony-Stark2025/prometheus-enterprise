# Original User Request

## 2026-08-25T20:44:30Z

This is a single self-contained fix; keep it small and focused.

Deploy the Prometheus Autonomous AI Chief of Staff & Workstream Observability Platform onto Google Cloud Vertex AI Agent Engine (Gemini Enterprise Agent Platform) under project `gen-lang-client-0942141479` in `us-central1` and verify live multi-agent execution.

Working directory: `c:\Users\brigh\project\prometheus`
Integrity mode: demo

## Requirements

### R1. Complete Vertex AI Agent Engine Deployment
Execute the deployment of the Prometheus multi-agent fleet to Google Cloud Vertex AI Reasoning Engine / Agent Engine using `deploy_agent_engine.py` with project `gen-lang-client-0942141479` in `us-central1`. Ensure package packaging (`prometheus`), async event loop compatibility, and staging bucket artifacts resolve without container startup errors.

### R2. End-to-End Remote Verification & Health Inspection
Verify that the deployed remote Reasoning Engine resource is fully active and reachable by executing a remote test query. Verify all 6 sub-agents, SQLite memory persistence, and Gemini 3.7 Flash synthesis return valid correlated blocker telemetry.

### R3. Executive Dashboard & Production Finalization
Verify local and cloud endpoints (`/dashboard`, `/healthz`, `/mcp/sse`), ensuring the full enterprise production package is verified and documented.

## Acceptance Criteria

### Deployment & Platform Verification
- [ ] Vertex AI Reasoning Engine resource successfully created and active in `us-central1` on `gen-lang-client-0942141479`.
- [ ] Zero container startup errors or module namespace collisions in Google Cloud Logging.
- [ ] Remote agent responds to sample query with correlated sprint blockers and drafted action cards.
- [ ] Local test suite passes 100% (`pytest`).

## 2026-08-29T15:09:53Z

Refactor and enhance the Prometheus AI Chief of Staff platform with a bespoke, high-polish UI/UX redesign (Deep Obsidian & Electric Sapphire precision dark command console following frontend-design principles), fix front-to-back action card drafting and dispatch bugs (including inline draft editing and toast notifications), ensure 100% CI pipeline reliability across the test matrix, and preserve strict dual-namespace parity between prometheus/ and app/.

Working directory: c:\Users\brigh\project\prometheus
Integrity mode: development

## Requirements

### R1. Frontend UI/UX Redesign & Usability Overhaul
Overhaul the Executive Command Center (dashboard.html and documentation.html) into an intentional, high-precision dark command console:
- Apply the Deep Obsidian & Electric Sapphire aesthetic palette (#0a0d14, #121722, #1c2333, accent sapphire #3b82f6, emerald #10b981, amber #f59e0b, crimson #ef4444) with crisp 1px borders and purposeful typography hierarchy.
- Provide a persistent top navigation bar with active tenant switcher, Google OAuth profile avatar, real-time fleet connection status, and one-click "Run Fleet Ingest" action with SSE animated progress.
- Enhance the 4-stage pipeline visualizer, side-by-side blocker triage with collapsible root-cause evidence trees, interactive ABAC security perimeter sandbox, and responsive grid layouts.

### R2. Action Draft Card Lifecycle & Bug Fixes
- Fix all frontend JavaScript errors in dashboard.html (add null-coalescing on action_type, re-render overview-action-card-container upon workflow completion, safe escaping in event handlers).
- Introduce an Inline Action Card Editor Modal allowing engineering leads to edit message recipients, channel targets, and message body text prior to sign-off.
- Implement animated toast feedback notifications on approval, rejection, edits, and ingestion events.
- Ensure backend /api/v1/actions/{draft_id}/approve and /reject endpoints support custom edited content and return clear provenance metadata.

### R3. Dual-Namespace Invariant & CI Pipeline Optimization
- Mirror all modifications between prometheus/ and app/ using automated synchronization to maintain zero code drift.
- Optimize .github/workflows/ci.yml so that hermetic test runs execute reliably under Python 3.11 and 3.12 with clean mocks and zero flaky timeouts.
- Eliminate test suite deprecation warnings and ensure the full 159+ test matrix passes with 100% pass rate.

## Acceptance Criteria

### Frontend Quality & Usability
- [ ] Action cards render seamlessly on both the Overview tab and Action Cards tab with zero uncaught JavaScript errors in browser console.
- [ ] Users can edit draft content inline or in a modal before clicking "Approve & Dispatch".
- [ ] Live toast notifications provide clear visual confirmation for approvals, rejections, and workflow runs.
- [ ] UI features distinctive Deep Obsidian styling, accessible contrast ratios, and clean mobile responsiveness.

### Functional Resiliency & Parity
- [ ] Approving or rejecting action cards correctly updates SQLite state store, reflections on UI counters, and live Slack dispatch payloads.
- [ ] Dual-namespace parity test pytest tests/integration/test_m1_reviewer2_adversarial.py -k test_app_and_prometheus_namespace_parity passes with 0 failures.
- [ ] Full test suite (pytest tests/ -v) passes 100% (159+ tests) under CI environment flags (ENVIRONMENT=testing, USE_VERTEX_AI=false).

