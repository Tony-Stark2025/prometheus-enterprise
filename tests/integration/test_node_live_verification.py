"""
Integration test: Live Node.js API Exploit Verification & CEGIS Dual-Pass Oracle.
Spins up tests/fixtures/node_benchmark_app.js using local Node.js runtime,
executes live adversarial probes via ExploitProber, validates curl PoCs,
and verifies CEGIS oracle neutralization.
"""

import asyncio
import os
import shutil
import subprocess
import pytest
import httpx

from prometheus.pentest.models import (
    DualTenantContext,
    ExploitProbeRequest,
    HttpMethod,
    RouteEndpoint,
    VulnerabilityCategory,
)
from prometheus.pentest.exploit_prober import ExploitProber
from prometheus.pentest.state_synthesizer import StateSynthesizer


@pytest.fixture
def node_server_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def dual_tenant_context():
    synthesizer = StateSynthesizer(jwt_secret="prometheus-secret-key-123")
    synthesizer.register_seeded_resource(
        resource_type="invoice",
        resource_id="inv-alpha-992",
        confidential_marker="CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832",
    )
    return synthesizer.create_dual_context()


@pytest.mark.asyncio
async def test_live_nodejs_exploit_and_patch_verification(node_server_port, dual_tenant_context):
    node_bin = shutil.which("node") or "node"
    cmd = [node_bin, "tests/fixtures/node_benchmark_app.js"]
    env = os.environ.copy()
    env["PORT"] = str(node_server_port)
    env["NO_PROXY"] = "*"
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    base_url = f"http://127.0.0.1:{node_server_port}"

    # Wait for server readiness
    ready = False
    for _ in range(50):
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise RuntimeError(f"Node server exited prematurely ({proc.returncode}): stdout={stdout}, stderr={stderr}")
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                res = await client.get(f"{base_url}/health", timeout=0.5)
                if res.status_code == 200:
                    ready = True
                    break
        except Exception:
            await asyncio.sleep(0.1)

    if not ready:
        stdout, stderr = proc.communicate(timeout=2)
        proc.kill()
        raise RuntimeError(f"Node server failed to answer /health in time. stdout={stdout}, stderr={stderr}")

    try:
        prober = ExploitProber(base_url=base_url)
        beta_headers = {
            "Authorization": f"Bearer {dual_tenant_context.tenant_beta.jwt_token}",
            "X-Tenant-ID": dual_tenant_context.tenant_beta.tenant_id,
        }

        # 1. Probe BOLA exploit using high-level probe_bola
        route = RouteEndpoint(
            path="/api/v1/invoices/{id}",
            method=HttpMethod.GET,
            path_parameters=["id"],
        )
        proof = await prober.probe_bola(route, dual_tenant_context)

        assert proof.is_vulnerable is True
        assert proof.http_status_code == 200
        assert "curl " in proof.curl_command
        assert "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832" in str(proof.evidence_payload)

        # 2. Probe BFLA exploit (Attacker deletes workspace without admin role)
        bfla_req = ExploitProbeRequest(
            target_url=f"{base_url}/api/v1/workspaces/ws-alpha-001",
            method=HttpMethod.DELETE,
            headers=beta_headers,
            path_params={"id": "ws-alpha-001"},
            query_params={},
            vector=VulnerabilityCategory.BFLA,
            hypothesis="Member role can invoke administrative workspace deletion endpoint",
        )

        status, data, latency = await prober.execute_probe(bfla_req)
        assert status == 200
        assert data.get("status") == "DELETED"

        await prober.aclose()

    finally:
        proc.terminate()
        proc.wait(timeout=3)

    # 3. CEGIS Dual-Pass Test: Start server in --patched mode
    patched_proc = subprocess.Popen(
        [node_bin, "tests/fixtures/node_benchmark_app.js", "--patched"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    ready_patched = False
    for _ in range(50):
        if patched_proc.poll() is not None:
            stdout, stderr = patched_proc.communicate()
            raise RuntimeError(f"Patched server exited prematurely ({patched_proc.returncode}): stdout={stdout}, stderr={stderr}")
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                res = await client.get(f"{base_url}/health", timeout=0.5)
                if res.status_code == 200:
                    ready_patched = True
                    break
        except Exception:
            await asyncio.sleep(0.1)

    if not ready_patched:
        stdout, stderr = patched_proc.communicate(timeout=2)
        patched_proc.kill()
        raise RuntimeError(f"Patched server failed to answer /health in time. stdout={stdout}, stderr={stderr}")

    try:
        patched_prober = ExploitProber(base_url=base_url)

        # CEGIS Pass 1 (Attacker Neutralization): Attacker must receive 404
        bola_req = ExploitProbeRequest(
            target_url=f"{base_url}/api/v1/invoices/inv-alpha-992",
            method=HttpMethod.GET,
            headers=beta_headers,
            path_params={"id": "inv-alpha-992"},
            query_params={},
            vector=VulnerabilityCategory.BOLA_IDOR,
            hypothesis="Attacker tenant Beta can read invoice belonging to victim tenant Alpha",
        )
        status_pass1, data_pass1, _ = await patched_prober.execute_probe(bola_req)
        assert status_pass1 == 404, f"Patched server failed to block attacker (Pass 1 status={status_pass1})"

        # CEGIS Pass 2 (Victim Invariant Preservation): Victim must receive 200 OK
        alpha_headers = {
            "Authorization": f"Bearer {dual_tenant_context.tenant_alpha.jwt_token}",
            "X-Tenant-ID": dual_tenant_context.tenant_alpha.tenant_id,
        }
        victim_req = ExploitProbeRequest(
            target_url=f"{base_url}/api/v1/invoices/inv-alpha-992",
            method=HttpMethod.GET,
            headers=alpha_headers,
            path_params={"id": "inv-alpha-992"},
            query_params={},
            vector=VulnerabilityCategory.BOLA_IDOR,
            hypothesis="Victim retains legitimate authorized access to own invoice",
        )

        status_pass2, data_pass2, _ = await patched_prober.execute_probe(victim_req)
        assert status_pass2 == 200, f"Victim legitimate access was broken (Pass 2 status={status_pass2})"
        assert data_pass2.get("secret_marker") == "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832"

        await patched_prober.aclose()

    finally:
        patched_proc.terminate()
        patched_proc.wait(timeout=3)
