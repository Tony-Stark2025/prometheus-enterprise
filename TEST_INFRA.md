# E2E Test Infra: Prometheus Enterprise

## Test Philosophy
- Deterministic verification across all security and runtime systems.
- Methodology: Category-Partition + Boundary Value Analysis + Pairwise Combinatorial + Real-World Workload Testing + Adversarial Red-Teaming.
- Zero-mock policy: Tests invoke real ASGI applications, real cryptographic verification (HMAC-SHA256), real AST parsing, and real SSRF validation routines.

## Feature Inventory & Test Coverage Mapping
| # | Feature | Subsystem | Unit | Integration | Adversarial | E2E |
|---|---------|-----------|:----:|:-----------:|:-----------:|:---:|
| 1 | OpenAPI Lineage Graph & Tarjan SCC | `prometheus.pentest.lineage_graph` | ✓ | ✓ | ✓ | ✓ |
| 2 | Dual-Tenant State Synthesizer | `prometheus.pentest.state_synthesizer` | ✓ | ✓ | ✓ | ✓ |
| 3 | BOLA / BFLA Exploit Prober | `prometheus.pentest.exploit_prober` | ✓ | ✓ | ✓ | ✓ |
| 4 | Cryptographic Reflection Defense | `prometheus.pentest.reflection_defense` | ✓ | ✓ | ✓ | ✓ |
| 5 | CEGIS Dual-Pass AST Program Repair | `prometheus.pentest.cegis_verifier` | ✓ | ✓ | ✓ | ✓ |
| 6 | Capability Hypervisor Firewall | `prometheus.proxy.hypervisor` | ✓ | ✓ | ✓ | ✓ |
| 7 | Pre-State Witness H(S) Ledger | `prometheus.proxy.state_invariants` | ✓ | ✓ | ✓ | ✓ |
| 8 | Monotonic Action Permits & Nonces | `prometheus.proxy.token_authority` | ✓ | ✓ | ✓ | ✓ |
| 9 | Structured Semantic Denial Envelopes | `prometheus.proxy.denial_envelope` | ✓ | ✓ | ✓ | ✓ |
| 10 | ABAC Policy Evaluation Engine | `prometheus.security.abac_engine` | ✓ | ✓ | ✓ | ✓ |
| 11 | SSRF Defense-in-Depth & DNS Rebinding | `prometheus.pentest.exploit_prober` | ✓ | ✓ | ✓ | ✓ |
| 12 | Model Context Protocol (MCP) Tools | `prometheus.mcp.server` | ✓ | ✓ | ✓ | ✓ |
| 13 | CI/CD CLI Scanner (<85s SLA) | `prometheus.cli_scan` | ✓ | ✓ | ✓ | ✓ |

## Test Architecture
- **Runner**: `pytest` with `pytest.ini` configuration.
- **Directories**:
  - `tests/unit/`: Hermetic Unit Tests (Config, MCP protocol, ABAC rules, Hypervisor tokens).
  - `tests/integration/`: Integration Tests (Hypervisor proxy lifecycle, Pentest engine, OpenAPI lineage).
  - `tests/adversarial/`: Red-team matrix (HMAC tampering, replay fuzzing, canary collisions, SSRF bypasses).
  - `tests/e2e/`: End-to-end endpoints and live execution tests.
