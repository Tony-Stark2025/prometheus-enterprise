"""
OWASP crAPI (completely ridiculous Application) Benchmark App.
Simulates realistic microservice with BOLA (API1:2023) and BFLA (API5:2023) vulnerabilities.
"""

from typing import Dict, Optional
import jwt
from fastapi import Depends, FastAPI, HTTPException, Header, status
from pydantic import BaseModel

DEFAULT_JWT_SECRET = "prometheus-test-jwt-secret-key-32bytes-long!"
DEFAULT_JWT_ALGORITHM = "HS256"

crapi_app = FastAPI(title="OWASP crAPI Benchmark Microservice", version="2.0.0")


class UserSession(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    role: str


class VehicleLocation(BaseModel):
    vehicle_id: str
    tenant_id: str
    latitude: float
    longitude: float
    secret_marker: str


VEHICLES_DB: Dict[str, VehicleLocation] = {
    "veh-alpha-771": VehicleLocation(
        vehicle_id="veh-alpha-771",
        tenant_id="org-alpha-victim-001",
        latitude=37.7749,
        longitude=-122.4194,
        secret_marker="CONFIDENTIAL_VEHICLE_GPS_COORDINATES_ALPHA_481",
    )
}

ORDERS_DB: Dict[str, str] = {
    "order-alpha-001": "org-alpha-victim-001",
}


def get_current_user(authorization: Optional[str] = Header(None)) -> UserSession:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, DEFAULT_JWT_SECRET, algorithms=[DEFAULT_JWT_ALGORITHM])
        return UserSession(
            user_id=payload["user_id"],
            tenant_id=payload["tenant_id"],
            email=payload["email"],
            role=payload.get("role", "member"),
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )


@crapi_app.get("/health")
async def health():
    return {"status": "ok", "service": "crapi-benchmark"}


# --- CRAPI ROUTE 1: VULNERABLE BOLA GPS LOCATION ---
@crapi_app.get("/api/v2/vehicle/{vehicle_id}/location")
async def get_vehicle_location_vulnerable(
    vehicle_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    vehicle = VEHICLES_DB.get(vehicle_id)
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    # BUG: No tenant boundary check! Cross-tenant tracking permitted!
    return vehicle


# --- CRAPI ROUTE 2: SECURED BOLA LOCATION ---
@crapi_app.get("/api/v2/secure-vehicle/{vehicle_id}/location")
async def get_vehicle_location_secured(
    vehicle_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    vehicle = VEHICLES_DB.get(vehicle_id)
    if not vehicle or vehicle.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    return vehicle


# --- CRAPI ROUTE 3: VULNERABLE BFLA ORDER DELETION ---
@crapi_app.delete("/api/v2/admin/mechanic/orders/{order_id}")
async def delete_mechanic_order_vulnerable(
    order_id: str,
    current_user: UserSession = Depends(get_current_user),
):
    if order_id != "order-alpha-001" and order_id not in ORDERS_DB:
        raise HTTPException(status_code=404, detail="Order not found")
    # BUG: No admin role check! Low-privilege members can delete orders!
    return {"status": "DELETED", "order_id": order_id, "deleted_by": current_user.user_id}
