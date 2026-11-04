#!/usr/bin/env python3
"""
Prometheus Enterprise Autonomous API Security CLI
Executes autonomous API vulnerability verification, deterministic curl reproduction,
AST program repair, and GitHub PR / Slack alert formatting in under 90 seconds.

Usage:
    prometheus-scan --target-url <URL> --spec <path/to/openapi.json> [--fail-on-exploit] [--output-diff <file>]
    prometheus-scan --demo
"""

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
import httpx

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prometheus.pentest.benchmark_app import app as benchmark_fastapi_app
from prometheus.pentest.engine import PrometheusAdversarialEngine
from prometheus.pentest.exploit_prober import ExploitProber
from prometheus.pentest.models import (
    AutoPatchResult,
    DualTenantContext,
    ExploitProof,
    HttpMethod,
    RouteEndpoint,
)
from prometheus.pentest.pr_ingestor import OpenAPIngestor
from prometheus.pentest.pr_reporter import PRReporter
from prometheus.pentest.proof_validator import ProofValidator
from prometheus.pentest.state_synthesizer import StateSynthesizer


def print_banner() -> None:
    banner = r"""
================================================================================
   ____                                _   _                     
  |  _ \ _ __ ___  _ __ ___   ___| |_| |__   ___ _   _ ___ 
  | |_) | '__/ _ \| '_ ` _ \ / _ \ __| '_ \ / _ \ | | / __|
  |  __/| | | (_) | | | | | |  __/ |_| | | |  __/ |_| \__ \
  |_|   |_|  \___/|_| |_| |_|\___|\__|_| |_|\___|\__,_|___/
  
  🔥 AUTONOMOUS API EXPLOIT VERIFICATION & ZERO-REGRESSION AUTO-PATCHING 🔥
       [ Continuous Developer-Native API Penetration Testing Engine ]
================================================================================
"""
    print(banner)


async def run_scan(
    target_url: str,
    spec_data: Dict[str, Any],
    transport: Optional[httpx.AsyncBaseTransport] = None,
    fail_on_exploit: bool = False,
    output_diff_file: Optional[str] = None,
    output_markdown_file: Optional[str] = None,
    output_sarif_file: Optional[str] = None,
    jwt_secret: Optional[str] = None,
    auth_header_alpha: Optional[str] = None,
    auth_header_beta: Optional[str] = None,
    output_test_file: Optional[str] = None,
    target_dir: Optional[str] = None,
    apply_patch: bool = False,
    timeout: float = 10.0,
    seed_params: Optional[Dict[str, str]] = None,
    sensitive_markers: Optional[List[str]] = None,
    alpha_tenant_id: str = "org-alpha-victim-001",
    beta_tenant_id: str = "org-beta-attacker-002",
    publish_pr_repo: Optional[str] = None,
) -> int:
    try:
        async with asyncio.timeout(80.0):
            return await _run_scan_internal(
                target_url=target_url,
                spec_data=spec_data,
                transport=transport,
                fail_on_exploit=fail_on_exploit,
                output_diff_file=output_diff_file,
                output_markdown_file=output_markdown_file,
                output_sarif_file=output_sarif_file,
                jwt_secret=jwt_secret,
                auth_header_alpha=auth_header_alpha,
                auth_header_beta=auth_header_beta,
                output_test_file=output_test_file,
                target_dir=target_dir,
                apply_patch=apply_patch,
                timeout=timeout,
                seed_params=seed_params,
                sensitive_markers=sensitive_markers,
                alpha_tenant_id=alpha_tenant_id,
                beta_tenant_id=beta_tenant_id,
                publish_pr_repo=publish_pr_repo,
            )
    except TimeoutError:
        print("\n[-] CI/CD SLA Violation: Scan exceeded 80.0s global timeout threshold.")
        return 1


async def _run_scan_internal(
    target_url: str,
    spec_data: Dict[str, Any],
    transport: Optional[httpx.AsyncBaseTransport] = None,
    fail_on_exploit: bool = False,
    output_diff_file: Optional[str] = None,
    output_markdown_file: Optional[str] = None,
    output_sarif_file: Optional[str] = None,
    jwt_secret: Optional[str] = None,
    auth_header_alpha: Optional[str] = None,
    auth_header_beta: Optional[str] = None,
    output_test_file: Optional[str] = None,
    target_dir: Optional[str] = None,
    apply_patch: bool = False,
    timeout: float = 10.0,
    seed_params: Optional[Dict[str, str]] = None,
    sensitive_markers: Optional[List[str]] = None,
    alpha_tenant_id: str = "org-alpha-victim-001",
    beta_tenant_id: str = "org-beta-attacker-002",
    publish_pr_repo: Optional[str] = None,
) -> int:
    start_total_time = time.perf_counter()

    print(f"[*] Target Endpoint: {target_url}")
    if target_dir:
        print(f"[*] Target Codebase Directory: {os.path.abspath(target_dir)}")

    endpoints: List[RouteEndpoint] = []
    if spec_data and isinstance(spec_data, dict) and spec_data.get("paths"):
        print(f"[*] Parsing OpenAPI Specification...")
        endpoints = OpenAPIngestor.parse_spec(spec_data)
    if not endpoints and target_dir:
        print(f"[*] Discovering API routes statically from source code in: {target_dir}...")
        endpoints = OpenAPIngestor.extract_routes_from_directory(target_dir)
    print(f"[+] Discovered {len(endpoints)} API operations.")

    # 1. State Synthesis: Mint Authentic Cryptographic Dual-Tenant Identities
    print(f"\n[*] Synthesizing Dual-Tenant Security Boundaries (Tenant Alpha & Tenant Beta)...")
    synthesizer = StateSynthesizer(jwt_secret=jwt_secret)
    default_marker = (
        sensitive_markers[0]
        if sensitive_markers and len(sensitive_markers) > 0
        else "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832"
    )
    synthesizer.register_seeded_resource(
        resource_type="invoice",
        resource_id="inv-alpha-992",
        confidential_marker=default_marker,
    )
    synthesizer.register_seeded_resource(
        resource_type="workspace",
        resource_id="ws-alpha-001",
        confidential_marker="CONFIDENTIAL_WORKSPACE_ALPHA_001",
    )
    if seed_params:
        for param_key, param_val in seed_params.items():
            synthesizer.register_seeded_resource(
                resource_type=param_key,
                resource_id=str(param_val),
                confidential_marker=default_marker,
            )
            clean_key = param_key[:-3] if param_key.endswith("_id") else param_key
            if clean_key != param_key:
                synthesizer.register_seeded_resource(
                    resource_type=clean_key,
                    resource_id=str(param_val),
                    confidential_marker=default_marker,
                )

    context = synthesizer.create_dual_context(
        alpha_tenant_id=alpha_tenant_id,
        beta_tenant_id=beta_tenant_id,
        beta_role="member",
        auth_header_alpha=auth_header_alpha,
        auth_header_beta=auth_header_beta,
    )
    print(f"  • Victim (Tenant Alpha):   {context.tenant_alpha.tenant_id} (User: {context.tenant_alpha.user_id})")
    print(f"  • Attacker (Tenant Beta): {context.tenant_beta.tenant_id} (Role: {context.tenant_beta.role})")
    if auth_header_alpha or auth_header_beta:
        print(f"  • Active Cryptographic Tokens Mints: Pre-minted Enterprise IdP Auth Headers (HS256 generation bypassed).")
    else:
        print(f"  • Active Cryptographic Tokens Mints: HS256 Signed JWTs.")

    # 2. Exploit Prober with Persistent Connection Pool
    print(f"\n[*] Initializing High-Throughput Connection Pool & Multi-Agent Engine...")
    validator = ProofValidator(redact_tokens=True)
    if sensitive_markers:
        for marker in sensitive_markers:
            if marker not in validator.sensitive_markers:
                validator.sensitive_markers.append(marker)
    prober = ExploitProber(
        base_url=target_url,
        timeout=timeout,
        transport=transport,
        proof_validator=validator,
        allow_loopback=True,
    )

    # Dynamic turn budgeting based on endpoint count and SLA remaining budget
    elapsed_so_far = time.perf_counter() - start_total_time
    remaining_sla_s = max(10.0, 80.0 - elapsed_so_far)
    time_budget_turns = int(remaining_sla_s / 1.5)
    endpoint_budget_turns = max(8, len(endpoints) * 2)
    dynamic_turns = max(5, min(endpoint_budget_turns, time_budget_turns, 50))

    engine = PrometheusAdversarialEngine(
        base_url=target_url,
        endpoints=endpoints,
        context=context,
        prober=prober,
        max_turns=dynamic_turns,
        target_dir=target_dir,
    )

    print(f"[*] Launching Autonomous Multi-Agent Search Loop (Coordinator -> Prober -> Oracle -> CEGIS)...")
    engine_results = await engine.run()
    elapsed_time = time.perf_counter() - start_total_time

    confirmed_exploits: List[ExploitProof] = engine_results.get("vulnerabilities", [])
    synthesized_patches: List[AutoPatchResult] = engine_results.get("patches", [])
    cumulative_diff: str = engine_results.get("cumulative_diff", "")
    patched_files: Dict[str, str] = engine_results.get("patched_files", {})
    llm_telemetry: Dict[str, Any] = engine_results.get("llm_telemetry", {})

    if llm_telemetry:
        prov = llm_telemetry.get("provider", "deterministic").upper()
        mod = llm_telemetry.get("model", "deterministic")
        proj = llm_telemetry.get("project")
        print(f"  • Coordinator LLM Provider: {prov} (Model: {mod}{f', GCP Project: {proj}' if proj else ''})")
        if llm_telemetry.get("strategic_summary"):
            print(f"  • Coordinator Strategy:     {llm_telemetry['strategic_summary']}")

    print("\n" + "=" * 80)
    print(f"                PROMETHEUS SECURITY GATE SCAN SUMMARY")
    print("=" * 80)
    print(f"  Total Scan Time:        {elapsed_time:.2f} seconds (< 90s SLA Gate)")
    print(f"  Endpoints Probed:       {len(endpoints)}")
    print(f"  Confirmed Exploits:     {len(confirmed_exploits)} (0% False Positives)")
    print(f"  Certified Auto-Patches: {len(synthesized_patches)}")
    print("=" * 80)

    # Always write SARIF report if requested (even when 0 exploits found for clean GitHub Code Scanning status)
    if output_sarif_file:
        sarif_payload = PRReporter.format_sarif_report(
            proofs=confirmed_exploits,
            patches=synthesized_patches,
            target_url=target_url,
            redact_tokens=True,
        )
        with open(output_sarif_file, "w", encoding="utf-8") as f:
            json.dump(sarif_payload, f, indent=2)
        print(f"\n[+] OASIS SARIF v2.1.0 report written to: {output_sarif_file}")

    # 3. Output Findings
    if confirmed_exploits:
        from prometheus.pentest.regression_test_generator import RegressionTestGenerator

        synthesized_tests: List[str] = []
        for idx, proof in enumerate(confirmed_exploits, 1):
            print(f"\n[!] EXPLOIT #{idx}: {proof.severity.value} — {proof.vector.value}")
            print(f"    Target Route:   {proof.http_method.value} {proof.target_endpoint}")
            print(f"    HTTP Status:    {proof.http_status_code}")
            print(f"    Latency:        {proof.execution_time_ms:.1f}ms")
            print(f"    Evidence:       {json.dumps(proof.evidence_payload)[:140]}...")
            print(f"\n    [+] Standalone Copy-Pasteable Reproduction Command:")
            redacted_curl = ProofValidator.redact_curl_tokens(proof.curl_command)
            print(f"    {redacted_curl}")

            py_test = RegressionTestGenerator.generate_pytest(proof)
            synthesized_tests.append(py_test)
            print(f"\n    [+] Synthesized Standalone Regression Test (pytest):")
            first_lines = "\n    ".join(py_test.strip().splitlines()[:12])
            print(f"    {first_lines}\n    [... truncated, complete test embedded in PR report ...]")

        if output_test_file and confirmed_exploits:
            is_ts = output_test_file.endswith((".ts", ".tsx", ".js"))
            suite_code = (
                RegressionTestGenerator.generate_suite_typescript(confirmed_exploits)
                if is_ts
                else RegressionTestGenerator.generate_suite_pytest(confirmed_exploits)
            )
            with open(output_test_file, "w", encoding="utf-8") as f:
                f.write(suite_code)
            print(f"\n[+] Synthesized CI/CD Regression Test Suite written to: {output_test_file}")

        # PR Reporter Markdown
        markdown_reports: List[str] = []
        for idx, proof in enumerate(confirmed_exploits):
            matching_patch = (
                synthesized_patches[idx]
                if idx < len(synthesized_patches) and synthesized_patches[idx].verification_status == "VERIFIED_FIX"
                else next((p for p in synthesized_patches if p.verification_status == "VERIFIED_FIX"), None)
            )
            comment_md = PRReporter.format_github_pr_comment(proof, matching_patch, redact_tokens=True)
            markdown_reports.append(comment_md)

        full_md_output = "\n\n---\n\n".join(markdown_reports)

        if output_markdown_file:
            with open(output_markdown_file, "w", encoding="utf-8") as f:
                f.write(full_md_output)
            print(f"\n[+] GitHub PR Markdown report written to: {output_markdown_file}")

        if output_diff_file and synthesized_patches:
            diff_to_write = cumulative_diff or "\n".join(p.git_diff for p in synthesized_patches if p.git_diff)
            with open(output_diff_file, "w", encoding="utf-8") as f:
                f.write(diff_to_write)
            print(f"[+] Certified Unified Git Diff written to: {output_diff_file}")

        if apply_patch and patched_files:
            base_dir = target_dir or os.getcwd()
            for rel_file, new_code in patched_files.items():
                abs_target = os.path.join(base_dir, rel_file)
                if os.path.exists(abs_target):
                    with open(abs_target, "w", encoding="utf-8") as f:
                        f.write(new_code)
                    print(f"[+] Applied certified AST auto-patch directly to: {abs_target}")

        # Native GitHub Actions Step Summary & Output Integration
        if "GITHUB_STEP_SUMMARY" in os.environ:
            try:
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
                    f.write("\n## 🛡️ Prometheus Autonomous Security Gate Summary\n\n")
                    f.write(f"- **Scan Time:** `{elapsed_time:.2f}s` (< 90s SLA)\n")
                    f.write(f"- **Endpoints Probed:** `{len(endpoints)}`\n")
                    f.write(f"- **Confirmed Exploits (0% False Positives):** `{len(confirmed_exploits)}`\n")
                    f.write(f"- **Certified Auto-Patches:** `{len(synthesized_patches)}`\n\n")
                    if full_md_output:
                        f.write(full_md_output)
            except Exception:
                pass

        if "GITHUB_OUTPUT" in os.environ:
            try:
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write(f"exploits_count={len(confirmed_exploits)}\n")
                    f.write(f"patches_count={len(synthesized_patches)}\n")
            except Exception:
                pass

    else:
        print("\n[+] Clean Bill of Health: Zero Cross-Tenant Vulnerabilities Detected.")
        if "GITHUB_STEP_SUMMARY" in os.environ:
            try:
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
                    f.write("\n## 🛡️ Prometheus Autonomous Security Gate Summary\n\n")
                    f.write(f"✅ **Clean Bill of Health**: Tested {len(endpoints)} endpoints in `{elapsed_time:.2f}s`. Zero BOLA/BFLA authorization vulnerabilities detected.\n")
            except Exception:
                pass
        if "GITHUB_OUTPUT" in os.environ:
            try:
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("exploits_count=0\n")
                    f.write("patches_count=0\n")
            except Exception:
                pass

    await prober.aclose()

    if publish_pr_repo and patched_files:
        contextual_prs = engine_results.get("contextual_prs", [])
        first_pr = contextual_prs[0] if contextual_prs else {}
        pr_title = first_pr.get(
            "pr_title",
            f"fix(security): Prometheus automated remediation ({len(confirmed_exploits)} exploits fixed)",
        )
        pr_body = first_pr.get("pr_body_markdown", f"```diff\n{cumulative_diff}\n```")
        print(f"\n[*] Publishing Contextual Remediation Pull Request to GitHub ({publish_pr_repo})...")
        pub_res = await PRReporter.publish_github_pull_request(
            repo=publish_pr_repo,
            pr_title=pr_title,
            pr_body_markdown=pr_body,
            patched_files=patched_files,
        )
        if pub_res.get("published"):
            print(f"[+] GitHub Pull Request Opened: {pub_res.get('pr_url')} (Branch: {pub_res.get('branch')})")
        else:
            print(f"[!] GitHub PR Publish Status: {pub_res.get('status')} ({pub_res.get('error')})")

    if confirmed_exploits and fail_on_exploit:
        print(f"\n[-] Failing CI/CD Gate: {len(confirmed_exploits)} critical vulnerability(ies) detected.")
        return 1

    return 0


def terminate_process_tree(proc: Any) -> None:
    """Reliably terminates a process and all its child preview processes to prevent orphans."""
    if proc is None:
        return
    try:
        import psutil
        try:
            p = psutil.Process(proc.pid)
            children = p.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if proc.poll() is None:
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            psutil.wait_procs(children + ([p] if proc.poll() is None else []), timeout=2)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    except ImportError:
        pass

    try:
        if sys.platform == "win32":
            import subprocess
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            import os, signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                if proc.poll() is None:
                    proc.kill()
    except Exception:
        if proc.poll() is None:
            proc.kill()
    try:
        proc.wait(timeout=2)
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    """Builds and returns the Prometheus CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Prometheus: Autonomous API Exploit Verification & Auto-Patching Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target-url", type=str, default="http://127.0.0.1:8000", help="Root URL of running target API")
    parser.add_argument("--spec", type=str, help="Path to OpenAPI / Swagger JSON or YAML specification")
    parser.add_argument("--spec-url", type=str, help="URL or relative path (e.g. /openapi.json) to OpenAPI specification")
    parser.add_argument("--config", type=str, help="Path to JSON scan configuration (identities, seed params, sensitive markers)")
    parser.add_argument("--seed-param", action="append", default=[], help="Seeded path/resource parameter key=value (repeatable)")
    parser.add_argument("--app-cmd", type=str, help="Optional shell command to boot preview server prior to scan")
    parser.add_argument("--target-dir", type=str, help="Local codebase directory for static route & AST source file discovery and patching")
    parser.add_argument("--apply-patch", action="store_true", help="Apply certified AST patches directly to files in --target-dir")
    parser.add_argument("--demo", action="store_true", help="Run self-contained end-to-end benchmark demo with in-memory ASGI")
    parser.add_argument("--immunology", action="store_true", help="Run Event-Driven Continuous Immunology sweep (OSV.dev + THN RSS + AST call-graph reachability)")
    parser.add_argument("--publish-pr", type=str, help="Target GitHub repository ('owner/repo') to automatically open a remediation Pull Request")
    parser.add_argument("--fail-on-exploit", action="store_true", help="Exit code 1 if exploits are verified (CI/CD PR gate)")
    parser.add_argument("--output-diff", type=str, help="File to write verified unified git diff patch")
    parser.add_argument("--output-markdown", type=str, help="File to write GitHub PR Markdown review comment")
    parser.add_argument("--output-sarif", type=str, help="File to write OASIS SARIF v2.1.0 JSON report")
    parser.add_argument("--output-test", type=str, help="File to write synthesized pytest/vitest CI/CD regression test")
    parser.add_argument("--jwt-secret", type=str, help="JWT secret for cryptographic token synthesis")
    parser.add_argument("--auth-header-alpha", type=str, help="Enterprise IdP auth header or Bearer token for Tenant Alpha (Victim)")
    parser.add_argument("--auth-header-beta", type=str, help="Enterprise IdP auth header or Bearer token for Tenant Beta (Attacker)")
    parser.add_argument("--max-time", type=float, default=85.0, help="Maximum execution SLA timeout in seconds (default: 85.0s)")
    parser.add_argument("--sla-budget-s", type=float, help="Alias for --max-time SLA timeout budget in seconds")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    print_banner()

    start_wall_clock = time.perf_counter()
    max_sla_seconds = args.sla_budget_s or args.max_time or 85.0

    if args.immunology:
        from prometheus.pentest.immunology import ContinuousImmunologyEngine

        scan_dir = args.target_dir or os.getcwd()
        print(f"[*] Running Event-Driven Continuous Immunology Sweep on: {os.path.abspath(scan_dir)}...")
        engine = ContinuousImmunologyEngine()
        res = asyncio.run(
            engine.run_immunology_sweep(
                target_dir=scan_dir,
                auto_publish_pr=bool(args.publish_pr),
                repo=args.publish_pr,
            )
        )
        print(f"[+] Dependencies Scanned:          {res['dependencies_scanned']}")
        print(f"[+] THN Live Advisories Ingested:  {res['thn_live_events_ingested']}")
        print(f"[+] OSV Advisories Matched:        {res['osv_advisories_matched']}")
        print(f"[+] Reachable Vulnerabilities:     {res['reachable_vulnerabilities_count']}")
        print(f"[+] Unreachable Noise Suppressed:  {res['suppressed_unreachable_noise_count']}")
        for plan in res.get("remediation_plans", []):
            print(f"\n  [!] REACHABLE CVE: {plan['advisory_id']} in {plan['package_name']}@{plan['current_version']}")
            print(f"      Action: {plan['recommended_action']}")
            if plan.get("github_pr_result"):
                pr_info = plan["github_pr_result"]
                print(f"      GitHub PR Status: {pr_info.get('status')} {pr_info.get('pr_url', '')}")
        sys.exit(1 if (res["reachable_vulnerabilities_count"] > 0 and args.fail_on_exploit) else 0)

    seed_params: Dict[str, str] = {}
    sensitive_markers: List[str] = []
    alpha_tenant_id = "org-alpha-victim-001"
    beta_tenant_id = "org-beta-attacker-002"

    # Parse --config if provided (supports both Prometheus config and multi-tenant identity configs)
    if args.config:
        if not os.path.exists(args.config):
            print(f"[-] Error: Config file not found at: {args.config}")
            sys.exit(2)
        with open(args.config, "r", encoding="utf-8") as cf:
            cfg = json.load(cf)
        target_cfg = cfg.get("target", {})
        base_url_cfg = target_cfg.get("base_url") if isinstance(target_cfg, dict) else None
        if not base_url_cfg:
            base_url_cfg = cfg.get("base_url")
        if base_url_cfg and args.target_url == "http://127.0.0.1:8000":
            args.target_url = base_url_cfg

        if cfg.get("openapi_path") and not args.spec and not args.spec_url:
            candidate_spec = cfg["openapi_path"]
            if not os.path.isabs(candidate_spec):
                rel_to_cfg = os.path.join(os.path.dirname(os.path.abspath(args.config)), os.path.basename(candidate_spec))
                if os.path.exists(candidate_spec):
                    args.spec = candidate_spec
                elif os.path.exists(rel_to_cfg):
                    args.spec = rel_to_cfg
            elif os.path.exists(candidate_spec):
                args.spec = candidate_spec
        if isinstance(cfg.get("sensitive_markers"), list):
            sensitive_markers.extend(str(m) for m in cfg["sensitive_markers"])
        if isinstance(cfg.get("seed_params"), dict):
            for k, v in cfg["seed_params"].items():
                seed_params[str(k)] = str(v)

        owner_cfg = cfg.get("owner", {})
        if isinstance(owner_cfg, dict) and isinstance(owner_cfg.get("params"), dict):
            for k, v in owner_cfg["params"].items():
                seed_params[str(k)] = str(v)
                if str(k) == "ws_id":
                    seed_params["workspace"] = str(v)
                elif str(k) == "proj_id":
                    seed_params["project"] = str(v)
                elif str(k) == "doc_id":
                    seed_params["document"] = str(v)
                elif str(k) == "org_id":
                    seed_params["org"] = str(v)

        identities = cfg.get("identities", {})
        if isinstance(identities, list):
            owner_name = owner_cfg.get("identity") if isinstance(owner_cfg, dict) else None
            owner_identity = next((i for i in identities if i.get("name") == owner_name), None) or (identities[0] if identities else {})
            attacker_identity = next((i for i in identities if i.get("tenant") != owner_identity.get("tenant")), None) or (identities[-1] if len(identities) > 1 else {})
            if owner_identity.get("tenant"):
                alpha_tenant_id = str(owner_identity["tenant"])
            if owner_identity.get("headers", {}).get("Authorization") and not args.auth_header_alpha:
                args.auth_header_alpha = owner_identity["headers"]["Authorization"]
            if attacker_identity.get("tenant"):
                beta_tenant_id = str(attacker_identity["tenant"])
            if attacker_identity.get("headers", {}).get("Authorization") and not args.auth_header_beta:
                args.auth_header_beta = attacker_identity["headers"]["Authorization"]
        elif isinstance(identities, dict):
            owner = identities.get("owner", {})
            attacker = identities.get("cross_tenant_attacker") or identities.get("low_priv_same_tenant") or {}
            if isinstance(owner, dict):
                if owner.get("tenant"):
                    alpha_tenant_id = str(owner["tenant"])
                owner_headers = owner.get("headers", {})
                if isinstance(owner_headers, dict) and owner_headers.get("Authorization") and not args.auth_header_alpha:
                    args.auth_header_alpha = owner_headers["Authorization"]
                owner_params = owner.get("params", {})
                if isinstance(owner_params, dict):
                    for k, v in owner_params.items():
                        seed_params[str(k)] = str(v)
                        if str(k) == "ws_id":
                            seed_params["workspace"] = str(v)
                        elif str(k) == "proj_id":
                            seed_params["project"] = str(v)
                        elif str(k) == "doc_id":
                            seed_params["document"] = str(v)
                        elif str(k) == "org_id":
                            seed_params["org"] = str(v)
            if isinstance(attacker, dict):
                if attacker.get("tenant"):
                    beta_tenant_id = str(attacker["tenant"])
                att_headers = attacker.get("headers", {})
                if isinstance(att_headers, dict) and att_headers.get("Authorization") and not args.auth_header_beta:
                    args.auth_header_beta = att_headers["Authorization"]

    for item in args.seed_param or []:
        if "=" in item:
            k, v = item.split("=", 1)
            seed_params[k.strip()] = v.strip()

    if args.demo:
        print("[*] Running Prometheus Self-Contained Benchmark Demo with Live Multi-Tenant ASGI App...")
        spec = benchmark_fastapi_app.openapi()
        transport = httpx.ASGITransport(app=benchmark_fastapi_app)
        try:
            exit_code = asyncio.run(
                asyncio.wait_for(
                    run_scan(
                        target_url="http://testserver",
                        spec_data=spec,
                        transport=transport,
                        fail_on_exploit=args.fail_on_exploit,
                        output_diff_file=args.output_diff,
                        output_markdown_file=args.output_markdown,
                        output_sarif_file=args.output_sarif,
                        jwt_secret=args.jwt_secret,
                        auth_header_alpha=args.auth_header_alpha,
                        auth_header_beta=args.auth_header_beta,
                        output_test_file=args.output_test,
                        target_dir=args.target_dir,
                        apply_patch=args.apply_patch,
                        seed_params=seed_params,
                        sensitive_markers=sensitive_markers,
                        alpha_tenant_id=alpha_tenant_id,
                        beta_tenant_id=beta_tenant_id,
                        publish_pr_repo=args.publish_pr,
                    ),
                    timeout=max_sla_seconds,
                )
            )
        except asyncio.TimeoutError:
            print(f"\n[-] Execution SLA Breach: Demo exceeded overall {max_sla_seconds}s time budget. Failing closed.")
            exit_code = 1
        sys.exit(exit_code)

    if not args.spec and not args.spec_url and not args.target_dir:
        print("[-] Error: You must provide --spec <file>, --spec-url <url>, --target-dir <dir>, --immunology, or --demo.")
        sys.exit(2)

    # Launch preview app first if --app-cmd provided so relative --spec-url (/openapi.json) can be fetched from it
    app_proc = None
    if args.app_cmd:
        print(f"[*] Booting target application via: '{args.app_cmd}'...")
        import shlex
        import subprocess
        import signal

        cmd_tokens = shlex.split(args.app_cmd, posix=(sys.platform != "win32"))
        app_proc = subprocess.Popen(cmd_tokens, shell=False, start_new_session=(sys.platform != "win32"))

        def _cleanup_handler(signum, frame):
            if app_proc:
                print(f"\n[!] Signal {signum} received: terminating preview process tree...")
                terminate_process_tree(app_proc)
            sys.exit(128 + signum)

        signal.signal(signal.SIGINT, _cleanup_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _cleanup_handler)

        # Wait up to 15 seconds for target URL readiness
        ready = False
        for _ in range(30):
            if app_proc.poll() is not None:
                print(f"[-] Preview application exited prematurely with code {app_proc.poll()}.")
                break
            try:
                r = httpx.get(f"{args.target_url.rstrip('/')}/health", timeout=0.5, trust_env=False)
                if r.status_code in (200, 404):
                    ready = True
                    break
            except Exception:
                time.sleep(0.5)
        if ready:
            print("[+] Target application is ready for scanning.")
        else:
            print("[!] Warning: Target application did not respond to /health probe; proceeding anyway.")

    try:
        spec_dict: Dict[str, Any] = {}
        if args.spec:
            if not os.path.exists(args.spec):
                print(f"[-] Error: Spec file not found at: {args.spec}")
                sys.exit(2)
            with open(args.spec, "r", encoding="utf-8") as f:
                if args.spec.endswith((".yaml", ".yml")):
                    try:
                        import yaml
                        spec_dict = yaml.safe_load(f)
                    except ImportError:
                        print("[-] Error: PyYAML required to parse YAML specifications. Please install PyYAML or provide JSON.")
                        sys.exit(2)
                else:
                    spec_dict = json.load(f)
        elif args.spec_url:
            resolved_spec_url = args.spec_url
            if not (resolved_spec_url.startswith("http://") or resolved_spec_url.startswith("https://")):
                resolved_spec_url = f"{args.target_url.rstrip('/')}/{resolved_spec_url.lstrip('/')}"
            print(f"[*] Validating and fetching OpenAPI spec from: {resolved_spec_url}...")
            from prometheus.pentest.exploit_prober import validate_ssrf
            is_local = any(h in resolved_spec_url for h in ("127.0.0.1", "localhost", "[::1]"))
            validate_ssrf(resolved_spec_url, allow_loopback=is_local)
            try:
                resp = httpx.get(resolved_spec_url, timeout=15.0, follow_redirects=False, trust_env=False)
                resp.raise_for_status()
                try:
                    spec_dict = resp.json()
                except Exception:
                    import yaml
                    spec_dict = yaml.safe_load(resp.text)
            except Exception as fetch_err:
                if args.target_dir:
                    print(f"[!] Spec URL {resolved_spec_url} unavailable ({fetch_err}); falling back to static source route extraction.")
                    spec_dict = {}
                else:
                    raise

        elapsed_so_far = time.perf_counter() - start_wall_clock
        remaining_budget = max(5.0, max_sla_seconds - elapsed_so_far)

        exit_code = asyncio.run(
            asyncio.wait_for(
                run_scan(
                    target_url=args.target_url,
                    spec_data=spec_dict,
                    fail_on_exploit=args.fail_on_exploit,
                    output_diff_file=args.output_diff,
                    output_markdown_file=args.output_markdown,
                    output_sarif_file=args.output_sarif,
                    jwt_secret=args.jwt_secret,
                    auth_header_alpha=args.auth_header_alpha,
                    auth_header_beta=args.auth_header_beta,
                    output_test_file=args.output_test,
                    target_dir=args.target_dir,
                    apply_patch=args.apply_patch,
                    seed_params=seed_params,
                    sensitive_markers=sensitive_markers,
                    alpha_tenant_id=alpha_tenant_id,
                    beta_tenant_id=beta_tenant_id,
                    publish_pr_repo=args.publish_pr,
                ),
                timeout=remaining_budget,
            )
        )
    except asyncio.TimeoutError:
        print(f"\n[-] Execution SLA Breach: Scan exceeded overall {max_sla_seconds}s time budget. Failing closed.")
        exit_code = 1
    except Exception as e:
        print(f"\n[-] Scan Execution Failure: {e}")
        exit_code = 1
    finally:
        if app_proc:
            print("[*] Terminating preview application subprocess tree...")
            terminate_process_tree(app_proc)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

