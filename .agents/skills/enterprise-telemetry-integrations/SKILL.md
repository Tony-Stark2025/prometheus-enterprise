---
name: enterprise-telemetry-integrations
description: Robust client patterns for GitHub REST, Jira Cloud REST API, and Slack Web API with zero-mock production safety and dynamic latency handling.
---

# Enterprise Telemetry Integrations Best Practices

## 1. Atlassian Jira Cloud REST API Deprecations
- **Issue**: Atlassian deprecated `GET /rest/api/3/search` (returns HTTP 410 Gone for standard API tokens).
- **Fix**: Use `GET /rest/api/2/search?jql=...` or `POST /rest/api/3/search/jql` with basic auth (`user_email:api_token` base64 encoded).

```python
# Resilient Jira Search
search_url = f"{instance_url}/rest/api/2/search"
params = {"jql": query_jql, "maxResults": 50}
resp = await client.get(search_url, headers=auth_headers, params=params)
```

## 2. Zero-Mock Production Guardrail
- Never allow tools to fall back to hardcoded mock arrays (`cls.MOCK_PRS`, `cls.MOCK_ISSUES`) in production when real API credentials are configured.
- If real credentials return an empty array (`[]`), return `[]` so the application displays a genuine "Healthy / All Clear" state.

## 3. Dynamic Latency Thresholding for Live Demos & Evaluations
- In enterprise production, stale PR thresholds default to `48.0` hours.
- In staging environments, integration tests, or evaluation suites, allow `STALE_PR_HOURS_THRESHOLD` to be configured (e.g. `1.0` or `0.0`) so test PRs are immediately flagged as review bottlenecks.

## 4. Slack Bot User Permissions & Ingestion
- Ensure the bot user is invited to the monitored channel (`/invite @botname`).
- Required OAuth Scopes for full lifecycle: `chat:write`, `channels:history`, `im:write`, `users:read`.
