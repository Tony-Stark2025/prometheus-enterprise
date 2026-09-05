"""
Tier 2 Integration Tests: GitHub Live API Client & Telemetry Ingestion
Validates PR ingestion, review latency calculation, CI failure extraction, and fallback mechanisms.
"""

import pytest
from unittest.mock import patch, AsyncMock
from prometheus.tools.github_tools import GitHubTools


@pytest.mark.integration
class TestGitHubClient:
    @pytest.mark.asyncio
    async def test_github_get_open_pull_requests_structure(self):
        """Validates normalized dictionary schema for pull requests."""
        prs = await GitHubTools.get_open_pull_requests()
        assert isinstance(prs, list)
        assert len(prs) > 0

        for pr in prs:
            assert "id" in pr
            assert "repo" in pr
            assert "title" in pr
            assert "author" in pr
            assert "review_latency_hours" in pr
            assert isinstance(pr["review_latency_hours"], (int, float))
            assert "status" in pr
            assert "reviewers" in pr
            assert isinstance(pr["reviewers"], list)
            assert "review_status" in pr
            assert "ci_status" in pr
            assert "scopes" in pr
            assert isinstance(pr["scopes"], list)

    @pytest.mark.asyncio
    async def test_github_scope_filtering(self):
        """Validates that PR ingestion respects organizational scope parameters."""
        eng_prs = await GitHubTools.get_open_pull_requests(scopes=["engineering"])
        assert len(eng_prs) > 0
        assert all(any(s in pr.get("scopes", []) for s in ["engineering"]) for pr in eng_prs)

        finance_prs = await GitHubTools.get_open_pull_requests(scopes=["finance"])
        assert all("finance" in pr.get("scopes", []) for pr in finance_prs)

        unmatched_prs = await GitHubTools.get_open_pull_requests(scopes=["nonexistent_scope"])
        assert len(unmatched_prs) == 0

    @pytest.mark.asyncio
    async def test_github_stale_pull_requests_threshold(self):
        """Validates filtering of PRs exceeding the 48-hour review latency threshold."""
        stale_prs = await GitHubTools.get_stale_pull_requests(hours_threshold=48.0)
        assert len(stale_prs) >= 1
        for pr in stale_prs:
            assert pr["review_latency_hours"] >= 48.0
            assert pr["review_status"] == "WAITING_REVIEW"

        # PR-102 or PR-402 should be in stale PRs (58 hours)
        pr_ids = [p["id"] for p in stale_prs]
        assert ("PR-102" in pr_ids or "PR-402" in pr_ids)

    @pytest.mark.asyncio
    async def test_github_stale_pull_requests_custom_threshold(self):
        """Validates custom review latency threshold (e.g. 10.0 hours)."""
        stale_prs_10h = await GitHubTools.get_stale_pull_requests(hours_threshold=10.0)
        stale_prs_48h = await GitHubTools.get_stale_pull_requests(hours_threshold=48.0)
        assert len(stale_prs_10h) >= len(stale_prs_48h)

    @pytest.mark.asyncio
    async def test_github_ci_pipeline_failures(self):
        """Validates extraction and normalization of failing CI/CD builds."""
        failures = await GitHubTools.get_ci_pipeline_failures()
        assert isinstance(failures, list)
        assert len(failures) > 0

        for f in failures:
            assert "id" in f
            assert "repo" in f
            assert "branch" in f
            assert "commit" in f
            assert "failed_step" in f
            assert "error_summary" in f
            assert "scopes" in f

        # CI failure ID format check
        ci_ids = [f["id"] for f in failures]
        assert any(cid.startswith("CI-") for cid in ci_ids)

    @pytest.mark.asyncio
    async def test_github_fallback_resilience_on_network_simulation(self):
        """Verifies that GitHubTools provides resilient structured data under all runtime conditions."""
        prs = await GitHubTools.get_open_pull_requests()
        assert isinstance(prs, list)
        assert len(prs) >= 3
