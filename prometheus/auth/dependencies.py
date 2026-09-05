
import logging
from typing import Optional, List
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from prometheus.auth.oauth import decode_session_token
from prometheus.memory.firestore_store import firestore_store, UserProfile

logger = logging.getLogger('prometheus.auth.dependencies')
security_bearer = HTTPBearer(auto_error=False)

class UserContext(BaseModel):
    user_id: str = 'elena.lead'
    email: str = 'elena.lead@acme.corp'
    name: str = 'Elena Rostova'
    picture: Optional[str] = None
    tenant_id: str = 'default_enterprise'
    roles: List[str] = Field(default_factory=lambda: ['lead', 'admin', 'chief_of_staff'])
    org_scopes: List[str] = Field(default_factory=lambda: ['engineering', 'platform'])

async def get_current_user_optional(
    request: Request,
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> UserContext:
    # 1. Check Authorization header
    token = None
    if auth_header:
        token = auth_header.credentials
    # 2. Check Cookie
    if not token:
        token = request.cookies.get('session_token')
    
    if token:
        payload = decode_session_token(token)
        if payload:
            user_id = payload.get('sub', 'lead-01')
            user_profile = await firestore_store.get_user(user_id)
            if user_profile:
                return UserContext(
                    user_id=user_profile.user_id,
                    email=user_profile.email,
                    name=user_profile.name,
                    picture=user_profile.picture,
                    tenant_id=user_profile.tenant_id,
                    roles=user_profile.roles,
                    org_scopes=user_profile.org_scopes
                )
            return UserContext(
                user_id=user_id,
                email=payload.get('email', 'alex.lead@enterprise.io'),
                tenant_id=payload.get('tenant_id', 'default_enterprise'),
                org_scopes=payload.get('scopes', ['engineering', 'platform'])
            )

    # Default fallback context for open trial / demo access
    return UserContext()

async def get_current_user(
    user: UserContext = Depends(get_current_user_optional)
) -> UserContext:
    return user
