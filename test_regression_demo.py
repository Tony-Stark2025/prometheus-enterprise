"""
Prometheus Enterprise Autonomous Security Regression Test (httpx)
Target Route: DELETE /api/v1/workspaces/ws-alpha-001
OWASP Vector: API1:2023 - Broken Object Level Authorization

Ensures strict cross-tenant isolation and prevents BOLA / IDOR regressions.
"""

import os
import pytest
import httpx

TARGET_BASE_URL = os.environ.get("TARGET_URL", "http://testserver")


def test_api_v1_workspaces_ws_alpha_001_tenant_isolation():
    """
    Automated Tenant Isolation Regression Gate:
    1. Unauthorized attacker targeting victim resource receives 403 or 404 (zero canary leakage).
    2. Legitimate victim accessing own resource receives 200 with canary intact.
    """
    target_url = TARGET_BASE_URL.rstrip('/') + "/api/v1/workspaces/ws-alpha-001"
    canary_marker = "CONFIDENTIAL_WORKSPACE_ALPHA_001"

    attacker_headers = {
        "Authorization": os.environ.get("ATTACKER_AUTH_TOKEN", "<ATTACKER_AUTH_TOKEN>"),
        "X-Tenant-ID": "org-beta-attacker-002",
        "X-Organization-ID": "org-beta-attacker-002",
    }
    victim_headers = {
        "Authorization": os.environ.get("VICTIM_AUTH_TOKEN", "<VICTIM_AUTH_TOKEN>"),
        "X-Tenant-ID": "org-alpha-victim-001",
        "X-Organization-ID": "org-alpha-victim-001",
    }

    with httpx.Client(timeout=10.0) as client:
        # Phase 1: Attacker probing victim resource MUST be rejected
        attacker_response = client.request(
            method="DELETE",
            url=target_url,
            headers=attacker_headers,
        )
        assert attacker_response.status_code in (403, 404), (
            f"Tenant boundary failure: Attacker received {attacker_response.status_code}, expected 403 or 404."
        )
        assert canary_marker not in attacker_response.text, (
            "Tenant boundary failure: Confidential victim data leaked to unauthorized tenant!"
        )

        # Phase 2: Victim accessing own resource MUST succeed with data intact
        victim_response = client.request(
            method="DELETE",
            url=target_url,
            headers=victim_headers,
        )
        assert victim_response.status_code == 200, (
            f"Legitimate access failure: Victim received {victim_response.status_code}, expected 200."
        )
        assert canary_marker in victim_response.text, (
            "Data integrity failure: Expected canary marker not found in victim response."
        )


"""
Prometheus Enterprise Autonomous Security Regression Test (httpx)
Target Route: DELETE /api/v1/workspaces/ws-alpha-001
OWASP Vector: API5:2023 - Broken Function Level Authorization

Ensures strict cross-tenant isolation and prevents BOLA / IDOR regressions.
"""

import os
import pytest
import httpx

TARGET_BASE_URL = os.environ.get("TARGET_URL", "http://testserver")


def test_api_v1_workspaces_ws_alpha_001_tenant_isolation():
    """
    Automated Tenant Isolation Regression Gate:
    1. Unauthorized attacker targeting victim resource receives 403 or 404 (zero canary leakage).
    2. Legitimate victim accessing own resource receives 200 with canary intact.
    """
    target_url = TARGET_BASE_URL.rstrip('/') + "/api/v1/workspaces/ws-alpha-001"
    canary_marker = "org-alpha-victim-001"

    attacker_headers = {
        "Authorization": os.environ.get("ATTACKER_AUTH_TOKEN", "<ATTACKER_AUTH_TOKEN>"),
        "X-Tenant-ID": "org-beta-attacker-002",
        "X-Organization-ID": "org-beta-attacker-002",
    }
    victim_headers = {
        "Authorization": os.environ.get("VICTIM_AUTH_TOKEN", "<VICTIM_AUTH_TOKEN>"),
        "X-Tenant-ID": "org-alpha-victim-001",
        "X-Organization-ID": "org-alpha-victim-001",
    }

    with httpx.Client(timeout=10.0) as client:
        # Phase 1: Attacker probing victim resource MUST be rejected
        attacker_response = client.request(
            method="DELETE",
            url=target_url,
            headers=attacker_headers,
        )
        assert attacker_response.status_code in (403, 404), (
            f"Tenant boundary failure: Attacker received {attacker_response.status_code}, expected 403 or 404."
        )
        assert canary_marker not in attacker_response.text, (
            "Tenant boundary failure: Confidential victim data leaked to unauthorized tenant!"
        )

        # Phase 2: Victim accessing own resource MUST succeed with data intact
        victim_response = client.request(
            method="DELETE",
            url=target_url,
            headers=victim_headers,
        )
        assert victim_response.status_code == 200, (
            f"Legitimate access failure: Victim received {victim_response.status_code}, expected 200."
        )
        assert canary_marker in victim_response.text, (
            "Data integrity failure: Expected canary marker not found in victim response."
        )


"""
Prometheus Enterprise Autonomous Security Regression Test (httpx)
Target Route: GET /api/v1/invoices/inv-alpha-992
OWASP Vector: API1:2023 - Broken Object Level Authorization

Ensures strict cross-tenant isolation and prevents BOLA / IDOR regressions.
"""

import os
import pytest
import httpx

TARGET_BASE_URL = os.environ.get("TARGET_URL", "http://testserver")


def test_api_v1_invoices_inv_alpha_992_tenant_isolation():
    """
    Automated Tenant Isolation Regression Gate:
    1. Unauthorized attacker targeting victim resource receives 403 or 404 (zero canary leakage).
    2. Legitimate victim accessing own resource receives 200 with canary intact.
    """
    target_url = TARGET_BASE_URL.rstrip('/') + "/api/v1/invoices/inv-alpha-992"
    canary_marker = "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832"

    attacker_headers = {
        "Authorization": os.environ.get("ATTACKER_AUTH_TOKEN", "<ATTACKER_AUTH_TOKEN>"),
        "X-Tenant-ID": "org-beta-attacker-002",
        "X-Organization-ID": "org-beta-attacker-002",
    }
    victim_headers = {
        "Authorization": os.environ.get("VICTIM_AUTH_TOKEN", "<VICTIM_AUTH_TOKEN>"),
        "X-Tenant-ID": "org-alpha-victim-001",
        "X-Organization-ID": "org-alpha-victim-001",
    }

    with httpx.Client(timeout=10.0) as client:
        # Phase 1: Attacker probing victim resource MUST be rejected
        attacker_response = client.request(
            method="GET",
            url=target_url,
            headers=attacker_headers,
        )
        assert attacker_response.status_code in (403, 404), (
            f"Tenant boundary failure: Attacker received {attacker_response.status_code}, expected 403 or 404."
        )
        assert canary_marker not in attacker_response.text, (
            "Tenant boundary failure: Confidential victim data leaked to unauthorized tenant!"
        )

        # Phase 2: Victim accessing own resource MUST succeed with data intact
        victim_response = client.request(
            method="GET",
            url=target_url,
            headers=victim_headers,
        )
        assert victim_response.status_code == 200, (
            f"Legitimate access failure: Victim received {victim_response.status_code}, expected 200."
        )
        assert canary_marker in victim_response.text, (
            "Data integrity failure: Expected canary marker not found in victim response."
        )
