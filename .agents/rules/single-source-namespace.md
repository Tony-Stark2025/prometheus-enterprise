# Single-Source Namespace Aliasing (`prometheus/` -> `app/`)

`prometheus/` is the **single canonical source of truth** for the codebase.

1. **Zero File Duplication**: Do **not** duplicate `.py` or `.html` source files inside `app/`.
2. **Dynamic Module Aliasing**: [`app/__init__.py`](file:///c:/Users/brigh/project/prometheus-enterprise/app/__init__.py) installs a `sys.meta_path` alias (`_PrometheusAliasFinder`) that binds `app.<submodule>` directly to `prometheus.<submodule>` in `sys.modules`, guaranteeing singleton identity (`app.config.settings is prometheus.config.settings`) and zero drift.
3. **Zero Mock / Zero Toy Data Policy**: Production code in `prometheus/` must never contain hardcoded mock telemetry (`MOCK_PRS`, `MOCK_ISSUES`, `MOCK_MESSAGES`), sandbox seeders, or `/demo-login` bypasses. All telemetry clients must query live APIs (resolving credentials from Firestore Vault or Secret Manager / `.env`) and return empty collections `[]` when unconfigured or unreachable.
