"""
OmniChain Global Logistics Cloud API
Realistic enterprise multi-tenant microservice handling freight manifests,
shipment telemetry, and carrier administration.

Exposes authentic OWASP API Top 10 vulnerabilities (BOLA/IDOR API1:2023, BFLA API5:2023)
alongside secured counterparts for zero-false-positive validation.
"""

import os
import sys
from typing import Dict, List, Optional
import jwt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Header, status
from pydantic import BaseModel

DEFAULT_JWT_SECRET = "prometheus-test-jwt-secret-key-32bytes-long!"
DEFAULT_JWT_ALGORITHM = "HS256"

app = FastAPI(
    title="OmniChain Global Logistics Cloud API",
    version="3.2.0",
    description="Enterprise multi-tenant logistics microservice with supply chain tracking and carrier administration.",
)


class UserSession(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    role: str


class Shipment(BaseModel):
    id: str
    tenant_id: str
    origin: str
    destination: str
    tracking_number: str
    declared_value: float
    secret_marker: str


class ShipmentCreateRequest(BaseModel):
    id: Optional[str] = None
    origin: str = "Rotterdam Port Terminal 4"
    destination: str = "Zurich Global Cargo Hub"
    tracking_number: str = "TRK-EXPEDITE-9941"
    declared_value: float = 145000.0
    secret_marker: Optional[str] = None


class Carrier(BaseModel):
    id: str
    name: str
    status: str
    active_routes: int


# --- Real-World Persistent In-Memory Multi-Tenant Store ---

SHIPMENTS_DB: Dict[str, Shipment] = {
    "shp-alpha-8832": Shipment(
        id="shp-alpha-8832",
        tenant_id="org-alpha-victim-001",
        origin="Rotterdam Port Terminal 4",
        destination="Zurich Global Cargo Hub",
        tracking_number="TRK-ALPHA-0992",
        declared_value=485000.0,
        secret_marker="CONFIDENTIAL_MANIFEST_ALPHA_99182",
    ),
    "shp-beta-1001": Shipment(
        id="shp-beta-1001",
        tenant_id="org-beta-attacker-002",
        origin="Antwerp Terminal 2",
        destination="Frankfurt Freight Hub",
        tracking_number="TRK-BETA-7712",
        declared_value=12500.0,
        secret_marker="PUBLIC_MANIFEST_BETA_1001",
    ),
}

CARRIERS_DB: Dict[str, Carrier] = {
    "carr-001": Carrier(
        id="carr-001",
        name="Global Atlantic Freightways",
        status="active",
        active_routes=42,
    ),
    "carr-002": Carrier(
        id="carr-002",
        name="Pacific Star Cargo Fleet",
        status="active",
        active_routes=18,
    ),
}


def get_current_user(
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
) -> UserSession:
    """Authenticates caller via cryptographic JWT or Bearer token."""
    raw_token = None
    if authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ")[1]
    elif x_auth_token:
        raw_token = x_auth_token

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )

    try:
        payload = jwt.decode(
            raw_token,
            DEFAULT_JWT_SECRET,
            algorithms=[DEFAULT_JWT_ALGORITHM],
        )
        return UserSession(
            user_id=payload.get("user_id", "usr-anon"),
            tenant_id=payload.get("tenant_id", "org-unknown"),
            email=payload.get("email", "user@enterprise.local"),
            role=payload.get("role", "member"),
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid cryptographic authentication token: {str(e)}",
        )


# --- System Health & Readiness ---

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "omnichain-logistics-api",
        "version": "3.2.0",
        "active_tenants": 2,
    }


# --- Dynamic Resource Listing & Harvesting Endpoints ---

@app.get("/api/v1/shipments", response_model=List[Shipment])
async def list_shipments(current_user: UserSession = Depends(get_current_user)):
    """
    Returns shipments belonging to the authenticated tenant.
    Used by dynamic harvesting to discover tenant resource IDs and canaries.
    """
    return [s for s in SHIPMENTS_DB.values() if s.tenant_id == current_user.tenant_id]


@app.post("/api/v1/shipments", response_model=Shipment, status_code=status.HTTP_201_CREATED)
async def create_shipment(
    payload: ShipmentCreateRequest,
    current_user: UserSession = Depends(get_current_user),
):
    """
    Creates a new freight shipment belonging to the calling tenant.
    """
    shp_id = payload.id or f"shp-{current_user.tenant_id[:5]}-{len(SHIPMENTS_DB) + 1}"
    canary = payload.secret_marker or f"DYNAMIC_CANARY_SHIPMENT_{shp_id}"
    shipment = Shipment(
        id=shp_id,
        tenant_id=current_user.tenant_id,
        origin=payload.origin,
        destination=payload.destination,
        tracking_number=payload.tracking_number,
        declared_value=payload.declared_value,
        secret_marker=canary,
    )
    SHIPMENTS_DB[shp_id] = shipment
    return shipment


@app.get("/api/v1/carriers", response_model=List[Carrier])
async def list_carriers(current_user: UserSession = Depends(get_current_user)):
    """Returns active logistics carriers."""
    return list(CARRIERS_DB.values())


IS_PATCHED = os.environ.get("PATCHED", "false").lower() in ("true", "1", "yes") or "--patched" in sys.argv


# --- Vulnerable BOLA (OWASP API1:2023) Endpoint ---

@app.get("/api/v1/shipments/{shipment_id}", response_model=Shipment)
async def get_shipment_vulnerable(
    shipment_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    """
    VULNERABLE BOLA: Retrieves freight shipment details.
    Defect: Fails to enforce tenant boundary (shipment.tenant_id == current_user.tenant_id).
    Permits cross-tenant exfiltration of confidential manifests and canaries.
    """
    shipment = SHIPMENTS_DB.get(shipment_id)
    if not shipment:
        raise HTTPException(status_code=404, detail="Shipment not found")
    if IS_PATCHED and shipment.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return shipment


# --- Secured BOLA Endpoint (False Positive Control) ---

@app.get("/api/v1/secure/shipments/{shipment_id}", response_model=Shipment)
async def get_shipment_secured(
    shipment_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    """
    SECURED BOLA: Properly validates tenant boundary before returning shipment.
    Returns 404 to avoid leaking cross-tenant resource existence.
    """
    shipment = SHIPMENTS_DB.get(shipment_id)
    if not shipment or shipment.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return shipment


# --- Vulnerable BFLA (OWASP API5:2023) Endpoint ---

@app.delete("/api/v1/admin/carriers/{carrier_id}")
async def delete_carrier_vulnerable(
    carrier_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    """
    VULNERABLE BFLA: Deletes logistics carrier contract.
    Defect: Fails to verify that current_user has 'admin' role.
    Unprivileged members can execute destructive administrative actions.
    """
    if IS_PATCHED and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrative privileges required to terminate carriers",
        )
    if carrier_id not in CARRIERS_DB:
        raise HTTPException(status_code=404, detail="Carrier contract not found")
    del CARRIERS_DB[carrier_id]
    return {
        "status": "TERMINATED",
        "carrier_id": carrier_id,
        "terminated_by": current_user.user_id,
        "role_used": current_user.role,
        "tenant_id": current_user.tenant_id,
    }


# --- Secured BFLA Endpoint (False Positive Control) ---

@app.delete("/api/v1/secure/admin/carriers/{carrier_id}")
async def delete_carrier_secured(
    carrier_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    """
    SECURED BFLA: Enforces admin role check before carrier termination.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrative privileges required to terminate carriers",
        )
    if carrier_id not in CARRIERS_DB:
        raise HTTPException(status_code=404, detail="Carrier contract not found")
    del CARRIERS_DB[carrier_id]
    return {"status": "TERMINATED", "carrier_id": carrier_id}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
