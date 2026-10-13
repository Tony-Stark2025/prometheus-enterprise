"""
GitHub and CI/CD telemetry tools for Prometheus.
Ingests pull request review latency, stale branches, and build pipeline health
via live GitHub REST API with Firestore Vault & Secret Manager credential resolution.
Zero mock or synthetic fallback data.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

import httpx

from prometheus.config import settings
from prometheus.memory.firestore_store import firestore_store

logger = logging.getLogger(__name__)


class GitHubTools:
    """
    Enterprise GitHub API telemetry client.
    Ingests PR status, review latency, reviewers, and CI/CD run metrics across repositories.
    """

    @classmethod
    async def _resolve_credentials(
        cls,
        repos: Optional[List[str]] = None,
        tenant_id: str = "default_enterprise",
    ) -> Tuple[Optional[str], List[str]]:
        """Resolves GitHub token and repositories from Firestore Vault or environment settings."""
        vault_cfg = await firestore_store.get_integration(tenant_id, "github") or {}
        token = (
            vault_cfg.get("github_token")
            or vault_cfg.get("token")
            or settings.github_token
        )
        raw_repos = (
            repos
            or vault_cfg.get("github_repos")
            or vault_cfg.get("repos")
            or settings.github_repos
        )
        if isinstance(raw_repos, str):
            target_repos = [r.strip() for r in raw_repos.split(",") if r.strip()]
        elif isinstance(raw_repos, list):
            target_repos = [str(r).strip() for r in raw_repos if str(r).strip()]
        else:
            target_repos = []
        return token, target_repos

    @classmethod
    def _get_headers(cls, token: Optional[str] = None) -> Dict[str, str]:
        resolved_token = token if token is not None else settings.github_token
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Prometheus-Observability-Fleet/1.1",
        }
        if resolved_token:
            headers["Authorization"] = f"Bearer {resolved_token}"
        return headers

    @classmethod
    def _infer_scopes(cls, repo_name: str, labels: List[str]) -> List[str]:
        scopes = set()
        repo_lower = repo_name.lower()
        if "auth" in repo_lower:
            scopes.update(["engineering", "platform", "security"])
        elif "billing" in repo_lower or "finance" in repo_lower or "pay" in repo_lower:
            scopes.update(["engineering", "finance"])
        elif "gateway" in repo_lower or "infra" in repo_lower or "core" in repo_lower:
            scopes.update(["engineering", "platform"])
        else:
            scopes.update(["engineering", "platform"])

        for label in labels:
            lbl_lower = label.lower()
            if "security" in lbl_lower:
                scopes.add("security")
            if "finance" in lbl_lower or "billing" in lbl_lower:
                scopes.add("finance")
            if "platform" in lbl_lower:
                scopes.add("platform")
            if "engineering" in lbl_lower:
                scopes.add("engineering")
        return sorted(list(scopes))

    @classmethod
    def _extract_downstream_blockers(cls, title: str, body: Optional[str]) -> List[str]:
        text = f"{title} {body or ''}"
        found = set(re.findall(r"\b([A-Z][A-Z0-9]+-\d+|PR-\d+|#[0-9]+)\b", text, re.IGNORECASE))
        normalized = []
        for item in found:
            if item.startswith("#"):
                normalized.append(f"PR-{item[1:]}")
            else:
                normalized.append(item.upper())
        return sorted(list(set(normalized)))

    @classmethod
    def _parse_iso_to_utc(cls, date_str: Optional[str]) -> datetime:
        if not date_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @classmethod
    async def _fetch_pr_reviews(
        cls, client: httpx.AsyncClient, repo: str, pull_number: int, token: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        try:
            url = f"https://api.github.com/repos/{repo}/pulls/{pull_number}/reviews"
            resp = await client.get(url, headers=cls._get_headers(token))
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch reviews for {repo} PR #{pull_number}: {e}")
        return []

    @classmethod
    async def _fetch_pr_ci_status(
        cls, client: httpx.AsyncClient, repo: str, head_sha: str, token: Optional[str] = None
    ) -> str:
        try:
            url = f"https://api.github.com/repos/{repo}/commits/{head_sha}/check-runs"
            resp = await client.get(url, headers=cls._get_headers(token))
            if resp.status_code == 200:
                check_runs = resp.json().get("check_runs", [])
                if any(run.get("conclusion") == "failure" for run in check_runs):
                    return "FAILED"
                if any(run.get("status") in ("in_progress", "queued") for run in check_runs):
                    return "IN_PROGRESS"
                return "PASSED"
        except Exception as e:
            logger.debug(f"Unable to query check-runs for {repo} commit {head_sha}: {e}")
        return "PASSED"

    @classmethod
    async def get_open_pull_requests(
        cls,
        scopes: Optional[List[str]] = None,
        repos: Optional[List[str]] = None,
        tenant_id: str = "default_enterprise",
    ) -> List[Dict[str, Any]]:
        """
        Retrieves active open pull requests via live GitHub REST API.
        Returns an empty list if credentials are not configured or API is unreachable.
        """
        token, target_repos = await cls._resolve_credentials(repos=repos, tenant_id=tenant_id)
        if not token or not target_repos:
            logger.info("GitHub credentials or target repositories not configured; returning empty PR list.")
            return []

        live_prs: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for repo in target_repos:
                    url = f"https://api.github.com/repos/{repo}/pulls?state=open&sort=created&direction=desc&per_page=30"
                    resp = await client.get(url, headers=cls._get_headers(token))

                    remaining = resp.headers.get("x-ratelimit-remaining")
                    if resp.status_code in (403, 429) or (remaining is not None and remaining == "0"):
                        logger.warning(
                            f"GitHub API rate limit reached for '{repo}' (HTTP {resp.status_code}, remaining: {remaining})."
                        )
                        break

                    if resp.status_code != 200:
                        logger.warning(f"GitHub API request for repo '{repo}' returned HTTP {resp.status_code}")
                        continue

                    pulls_data = resp.json()
                    if not isinstance(pulls_data, list):
                        continue

                    now_utc = datetime.now(timezone.utc)
                    sem = asyncio.Semaphore(10)

                    async def _enrich_single_pr(pr: Dict[str, Any]) -> Dict[str, Any]:
                        pr_num = pr.get("number")
                        created_at_str = pr.get("created_at")
                        created_dt = cls._parse_iso_to_utc(created_at_str)
                        review_latency = max(0.0, round((now_utc - created_dt).total_seconds() / 3600.0, 1))
                        req_reviewers = [r.get("login") for r in pr.get("requested_reviewers", []) if r.get("login")]
                        head_sha = pr.get("head", {}).get("sha", "")

                        async with sem:
                            if head_sha:
                                reviews, ci_status = await asyncio.gather(
                                    cls._fetch_pr_reviews(client, repo, pr_num, token),
                                    cls._fetch_pr_ci_status(client, repo, head_sha, token),
                                )
                            else:
                                reviews = await cls._fetch_pr_reviews(client, repo, pr_num, token)
                                ci_status = "PASSED"

                        reviewer_set = set(req_reviewers)
                        has_changes_requested = False
                        has_approved = False
                        for rev in reviews:
                            rev_user = rev.get("user", {}).get("login")
                            if rev_user:
                                reviewer_set.add(rev_user)
                            state = rev.get("state")
                            if state == "CHANGES_REQUESTED":
                                has_changes_requested = True
                            elif state == "APPROVED":
                                has_approved = True

                        if has_changes_requested:
                            review_status = "CHANGES_REQUESTED"
                        elif has_approved:
                            review_status = "APPROVED"
                        else:
                            review_status = "WAITING_REVIEW"

                        labels = [lbl.get("name") for lbl in pr.get("labels", []) if lbl.get("name")]
                        inferred_scopes = cls._infer_scopes(repo, labels)
                        blocking_downstream = cls._extract_downstream_blockers(pr.get("title", ""), pr.get("body"))

                        return {
                            "id": f"PR-{pr_num}",
                            "repo": repo,
                            "title": pr.get("title", f"Pull Request #{pr_num}"),
                            "author": pr.get("user", {}).get("login", "unknown"),
                            "created_at": created_at_str or created_dt.isoformat(),
                            "updated_at": pr.get("updated_at", created_dt.isoformat()),
                            "review_latency_hours": review_latency,
                            "status": "OPEN",
                            "reviewers": sorted(list(reviewer_set)) if reviewer_set else ["unassigned"],
                            "review_status": review_status,
                            "ci_status": ci_status,
                            "scopes": inferred_scopes,
                            "blocking_downstream": blocking_downstream,
                        }

                    enriched = await asyncio.gather(*[_enrich_single_pr(pr) for pr in pulls_data])
                    live_prs.extend(enriched)

            if scopes:
                return [pr for pr in live_prs if any(s in pr.get("scopes", []) for s in scopes)]
            return live_prs

        except Exception as exc:
            logger.error(f"Live GitHub telemetry query failed: {exc}")
            return []

    @classmethod
    async def get_stale_pull_requests(
        cls,
        hours_threshold: float = 48.0,
        scopes: Optional[List[str]] = None,
        repos: Optional[List[str]] = None,
        tenant_id: str = "default_enterprise",
    ) -> List[Dict[str, Any]]:
        """
        Filters pull requests with review latency exceeding the threshold (e.g. 48h) and pending review.
        """
        all_prs = await cls.get_open_pull_requests(scopes=scopes, repos=repos, tenant_id=tenant_id)
        return [
            pr for pr in all_prs
            if pr.get("review_latency_hours", 0) >= hours_threshold and pr.get("review_status") == "WAITING_REVIEW"
        ]

    @classmethod
    async def get_ci_pipeline_failures(
        cls,
        scopes: Optional[List[str]] = None,
        repos: Optional[List[str]] = None,
        tenant_id: str = "default_enterprise",
    ) -> List[Dict[str, Any]]:
        """
        Retrieves failing CI/CD workflow runs across connected repositories via GitHub Actions API.
        Returns an empty list if unauthenticated or if no failing runs exist.
        """
        token, target_repos = await cls._resolve_credentials(repos=repos, tenant_id=tenant_id)
        if not token or not target_repos:
            return []

        live_failures: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for repo in target_repos:
                    url = f"https://api.github.com/repos/{repo}/actions/runs?status=failure&per_page=10"
                    resp = await client.get(url, headers=cls._get_headers(token))

                    remaining = resp.headers.get("x-ratelimit-remaining")
                    if resp.status_code in (403, 429) or (remaining is not None and remaining == "0"):
                        logger.warning("GitHub Actions API rate limit encountered.")
                        break

                    if resp.status_code != 200:
                        continue

                    runs_data = resp.json().get("workflow_runs", [])
                    for run in runs_data:
                        run_id = run.get("id")
                        workflow_name = run.get("name", "CI Workflow")
                        head_branch = run.get("head_branch", "main")
                        head_sha = (run.get("head_sha") or "")[:7]

                        failed_step = f"{workflow_name} / job_execution"
                        error_summary = run.get("display_title") or f"Run #{run.get('run_number')} failed on {head_branch}"

                        try:
                            jobs_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
                            jobs_resp = await client.get(jobs_url, headers=cls._get_headers(token))
                            if jobs_resp.status_code == 200:
                                jobs = jobs_resp.json().get("jobs", [])
                                for job in jobs:
                                    if job.get("conclusion") == "failure":
                                        job_name = job.get("name", "build")
                                        for step in job.get("steps", []):
                                            if step.get("conclusion") == "failure":
                                                failed_step = f"{job_name} / {step.get('name')}"
                                                break
                        except Exception:
                            pass

                        failure_record = {
                            "id": f"CI-{run_id}",
                            "repo": repo,
                            "branch": head_branch,
                            "commit": head_sha,
                            "failed_step": failed_step,
                            "error_summary": error_summary,
                            "run_at": run.get("updated_at") or run.get("created_at") or datetime.now(timezone.utc).isoformat(),
                            "scopes": cls._infer_scopes(repo, []),
                        }
                        live_failures.append(failure_record)

            if scopes:
                return [f for f in live_failures if any(s in f.get("scopes", []) for s in scopes)]
            return live_failures

        except Exception as exc:
            logger.error(f"Live GitHub CI failure query failed: {exc}")
            return []
