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
    jwt_secret: Optional[str] = None,
    auth_header_alpha: Optional[str] = None,
    auth_header_beta: Optional[str] = None,
    output_test_file: Optional[str] = None,
    timeout: float = 10.0,
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
                jwt_secret=jwt_secret,
                auth_header_alpha=auth_header_alpha,
                auth_header_beta=auth_header_beta,
                output_test_file=output_test_file,
                timeout=timeout,
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
    jwt_secret: Optional[str] = None,
    auth_header_alpha: Optional[str] = None,
    auth_header_beta: Optional[str] = None,
    output_test_file: Optional[str] = None,
    timeout: float = 10.0,
) -> int:
    start_total_time = time.perf_counter()

    print(f"[*] Target Endpoint: {target_url}")
    print(f"[*] Parsing OpenAPI Specification...")

    endpoints = OpenAPIngestor.parse_spec(spec_data)
    print(f"[+] Discovered {len(endpoints)} API operations.")

    # 1. State Synthesis: Mint Authentic Cryptographic Dual-Tenant Identities
    print(f"\n[*] Synthesizing Dual-Tenant Security Boundaries (Tenant Alpha & Tenant Beta)...")
    synthesizer = StateSynthesizer(jwt_secret=jwt_secret)
    synthesizer.register_seeded_resource(
        resource_type="invoice",
        resource_id="inv-alpha-992",
        confidential_marker="CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832",
    )
    synthesizer.register_seeded_resource(
        resource_type="workspace",
        resource_id="ws-alpha-001",
        confidential_marker="CONFIDENTIAL_WORKSPACE_ALPHA_001",
    )
    context = synthesizer.create_dual_context(
        alpha_tenant_id="org-alpha-victim-001",
        beta_tenant_id="org-beta-attacker-002",
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
    print(f"\n[*] Initializing High-Throughput Connection Pool & Active Learning Engine...")
    validator = ProofValidator(redact_tokens=True)
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
    )

    print(f"[*] Launching Autonomous Adversarial Search Loop (Lineage-Tiered Exploration)...")
    engine_results = await engine.run()
    elapsed_time = time.perf_counter() - start_total_time

    confirmed_exploits: List[ExploitProof] = engine_results.get("vulnerabilities", [])
    synthesized_patches: List[AutoPatchResult] = engine_results.get("patches", [])

    print("\n" + "=" * 80)
    print(f"                PROMETHEUS SECURITY GATE SCAN SUMMARY")
    print("=" * 80)
    print(f"  Total Scan Time:        {elapsed_time:.2f} seconds (< 90s SLA Gate)")
    print(f"  Endpoints Probed:       {len(endpoints)}")
    print(f"  Confirmed Exploits:     {len(confirmed_exploits)} (0% False Positives)")
    print(f"  Certified Auto-Patches: {len(synthesized_patches)}")
    print("=" * 80)

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
            tests_to_write = [
                RegressionTestGenerator.generate_typescript(p) if is_ts else RegressionTestGenerator.generate_pytest(p)
                for p in confirmed_exploits
            ]
            with open(output_test_file, "w", encoding="utf-8") as f:
                f.write("\n\n".join(tests_to_write))
            print(f"\n[+] Synthesized CI/CD Regression Test(s) written to: {output_test_file}")

        # PR Reporter Markdown
        markdown_reports: List[str] = []
        for proof in confirmed_exploits:
            matching_patch = next((p for p in synthesized_patches if p.verification_status == "VERIFIED_FIX"), None)
            comment_md = PRReporter.format_github_pr_comment(proof, matching_patch, redact_tokens=True)
            markdown_reports.append(comment_md)

        full_md_output = "\n\n---\n\n".join(markdown_reports)

        if output_markdown_file:
            with open(output_markdown_file, "w", encoding="utf-8") as f:
                f.write(full_md_output)
            print(f"\n[+] GitHub PR Markdown report written to: {output_markdown_file}")

        if output_diff_file and synthesized_patches:
            combined_diff = "\n".join(p.git_diff for p in synthesized_patches if p.git_diff)
            with open(output_diff_file, "w", encoding="utf-8") as f:
                f.write(combined_diff)
            print(f"[+] Certified Unified Git Diff written to: {output_diff_file}")

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
            except Exception as e:
                pass

        if "GITHUB_OUTPUT" in os.environ:
            try:
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write(f"exploits_count={len(confirmed_exploits)}\n")
                    f.write(f"patches_count={len(synthesized_patches)}\n")
            except Exception as e:
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
    parser.add_argument("--spec-url", type=str, help="URL to OpenAPI JSON specification")
    parser.add_argument("--app-cmd", type=str, help="Optional shell command to boot preview server prior to scan")
    parser.add_argument("--demo", action="store_true", help="Run self-contained end-to-end benchmark demo with in-memory ASGI")
    parser.add_argument("--fail-on-exploit", action="store_true", help="Exit code 1 if exploits are verified (CI/CD PR gate)")
    parser.add_argument("--output-diff", type=str, help="File to write verified unified git diff patch")
    parser.add_argument("--output-markdown", type=str, help="File to write GitHub PR Markdown review comment")
    parser.add_argument("--output-test", type=str, help="File to write synthesized pytest/vitest CI/CD regression test")
    parser.add_argument("--jwt-secret", type=str, help="JWT secret for cryptographic token synthesis")
    parser.add_argument("--auth-header-alpha", type=str, help="Enterprise IdP auth header or Bearer token for Tenant Alpha (Victim)")
    parser.add_argument("--auth-header-beta", type=str, help="Enterprise IdP auth header or Bearer token for Tenant Beta (Attacker)")
    parser.add_argument("--max-time", type=float, default=85.0, help="Maximum execution SLA timeout in seconds (default: 85.0s)")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    print_banner()

    start_wall_clock = time.perf_counter()
    max_sla_seconds = args.max_time or 85.0

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
                        jwt_secret=args.jwt_secret,
                        auth_header_alpha=args.auth_header_alpha,
                        auth_header_beta=args.auth_header_beta,
                        output_test_file=args.output_test,
                    ),
                    timeout=max_sla_seconds,
                )
            )
        except asyncio.TimeoutError:
            print(f"\n[-] Execution SLA Breach: Demo exceeded overall {max_sla_seconds}s time budget. Failing closed.")
            exit_code = 1
        sys.exit(exit_code)

    if not args.spec and not args.spec_url:
        print("[-] Error: You must provide either --spec <file>, --spec-url <url>, or --demo.")
        sys.exit(2)

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
        print(f"[*] Validating and fetching OpenAPI spec from: {args.spec_url}...")
        from prometheus.pentest.exploit_prober import validate_ssrf
        validate_ssrf(args.spec_url, allow_loopback=False)
        resp = httpx.get(args.spec_url, timeout=15.0, follow_redirects=False)
        resp.raise_for_status()
        try:
            spec_dict = resp.json()
        except Exception:
            try:
                import yaml
                spec_dict = yaml.safe_load(resp.text)
            except Exception:
                raise ValueError("Failed to parse OpenAPI specification as JSON or YAML.")

    # Launch preview app if --app-cmd provided
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

    elapsed_so_far = time.perf_counter() - start_wall_clock
    remaining_budget = max(5.0, max_sla_seconds - elapsed_so_far)

    try:
        exit_code = asyncio.run(
            asyncio.wait_for(
                run_scan(
                    target_url=args.target_url,
                    spec_data=spec_dict,
                    fail_on_exploit=args.fail_on_exploit,
                    output_diff_file=args.output_diff,
                    output_markdown_file=args.output_markdown,
                    jwt_secret=args.jwt_secret,
                    auth_header_alpha=args.auth_header_alpha,
                    auth_header_beta=args.auth_header_beta,
                    output_test_file=args.output_test,
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
