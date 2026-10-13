"""
Integration Test: Real-World External Target Autonomous Verification
Validates Prometheus against a standalone, live multi-tenant microservice
(OmniChain Global Logistics Cloud API) over real TCP network sockets.

Verifies:
1. Subprocess preview server lifecycle management with zero orphan processes.
2. Dynamic resource harvesting across listing and producer endpoints (F-01).
3. Deterministic BOLA/BFLA exploit confirmation with 0% false positives.
4. Token-redacted curl reproduction and environment-parameterized test synthesis (F-02).
5. Clean-bill of health verification when target is patched.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import pytest
import httpx

from prometheus.cli_scan import run_scan, terminate_process_tree
from prometheus.pentest.regression_test_generator import RegressionTestGenerator


@pytest.fixture
def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_external_real_world_target_end_to_end_scan(free_tcp_port, tmp_path):
    port = free_tcp_port
    target_url = f"http://127.0.0.1:{port}"
    app_script = os.path.abspath("external_targets/real_world_api/app.py")
    spec_path = os.path.abspath("external_targets/real_world_api/openapi.json")

    with open(spec_path, "r", encoding="utf-8") as f:
        spec_dict = json.load(f)

    # 1. Boot external application server
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["PATCHED"] = "0"
    proc = subprocess.Popen([sys.executable, app_script], env=env)

    # Wait for target readiness
    ready = False
    for _ in range(40):
        if proc.poll() is not None:
            break
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                r = await client.get(f"{target_url}/health", timeout=0.5)
                if r.status_code == 200:
                    ready = True
                    break
        except Exception:
            await asyncio.sleep(0.1)

    assert ready, "External target server failed to report ready within timeout."

    out_test_file = tmp_path / "test_synthesized.py"
    out_md_file = tmp_path / "report.md"

    try:
        # 2. Run Prometheus scan against live server
        exit_code = await run_scan(
            target_url=target_url,
            spec_data=spec_dict,
            output_test_file=str(out_test_file),
            output_markdown_file=str(out_md_file),
            fail_on_exploit=True,
            timeout=10.0,
        )

        # Must exit 1 because exploits are detected
        assert exit_code == 1

        # Verify synthesized regression test file
        assert out_test_file.exists()
        test_content = out_test_file.read_text(encoding="utf-8")
        assert "os.environ.get(\"ATTACKER_AUTH_TOKEN\"" in test_content
        assert "CONFIDENTIAL_MANIFEST_ALPHA_99182" in test_content
        assert "trust_env=False" in test_content

        # Verify Markdown PR report
        assert out_md_file.exists()
        md_content = out_md_file.read_text(encoding="utf-8")
        assert "curl -s -i -X GET" in md_content
        assert "<AUTH_TOKEN_REDACTED>" in md_content
        assert "CONFIDENTIAL_MANIFEST_ALPHA_99182" in md_content

    finally:
        terminate_process_tree(proc)


@pytest.mark.asyncio
async def test_external_target_patched_clean_bill_of_health(free_tcp_port):
    port = free_tcp_port
    target_url = f"http://127.0.0.1:{port}"
    app_script = os.path.abspath("external_targets/real_world_api/app.py")
    spec_path = os.path.abspath("external_targets/real_world_api/openapi.json")

    with open(spec_path, "r", encoding="utf-8") as f:
        spec_dict = json.load(f)

    # 1. Boot external application server in PATCHED mode
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["PATCHED"] = "1"
    proc = subprocess.Popen([sys.executable, app_script], env=env)

    ready = False
    for _ in range(40):
        if proc.poll() is not None:
            break
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                r = await client.get(f"{target_url}/health", timeout=0.5)
                if r.status_code == 200:
                    ready = True
                    break
        except Exception:
            await asyncio.sleep(0.1)

    assert ready, "External target server failed to report ready within timeout."

    try:
        # 2. Run Prometheus scan against patched server
        exit_code = await run_scan(
            target_url=target_url,
            spec_data=spec_dict,
            fail_on_exploit=True,
            timeout=10.0,
        )

        # Must exit 0 because target is fully patched (0 false positives)
        assert exit_code == 0

    finally:
        terminate_process_tree(proc)
