
import logging
from typing import Optional, List
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from prometheus.auth.oauth import decode_session_token
from prometheus.memory.firestore_store import firestore_store, UserProfile

logger = logging.getLogger('prometheus.auth.dependencies')
security_bearer = HTTPBearer(auto_error=False)

from prometheus.config import settings

class UserContext(BaseModel):
    user_id: str = 'anonymous'
    email: str = 'anonymous@prometheus.internal'
    name: str = 'Anonymous User'
    picture: Optional[str] = None
    tenant_id: str = 'default_enterprise'
    roles: List[str] = Field(default_factory=list)
    org_scopes: List[str] = Field(default_factory=list)
    is_authenticated: bool = False


async def get_current_user_optional(
    request: Request,
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> UserContext:
    token = None
    if auth_header:
        token = auth_header.credentials
    if not token:
        token = request.cookies.get('session_token')

    if token:
        payload = decode_session_token(token)
        if payload:
            user_id = payload.get('sub', 'service-principal')
            user_profile = await firestore_store.get_user(user_id)
            if user_profile:
                return UserContext(
                    user_id=user_profile.user_id,
                    email=user_profile.email,
                    name=user_profile.name,
                    picture=user_profile.picture,
                    tenant_id=user_profile.tenant_id,
                    roles=user_profile.roles,
                    org_scopes=user_profile.org_scopes,
                    is_authenticated=True,
                )
            return UserContext(
                user_id=user_id,
                email=payload.get('email', 'service@prometheus.internal'),
                tenant_id=payload.get('tenant_id', 'default_enterprise'),
                roles=payload.get('roles', ['operator']),
                org_scopes=payload.get('scopes', ['engineering', 'platform']),
                is_authenticated=True,
            )

    return UserContext()


async def get_current_user(
    user: UserContext = Depends(get_current_user_optional)
) -> UserContext:
    if not user.is_authenticated:
        if settings.environment == 'production':
            raise HTTPException(status_code=401, detail='Authentication required: missing or invalid session credentials.')
        # In non-production environments (development/testing), provide authenticated default context
        return UserContext(
            user_id='service-principal',
            email='service@prometheus.internal',
            name='Prometheus Service Principal',
            tenant_id='default_enterprise',
            roles=['operator'],
            org_scopes=['engineering', 'platform'],
            is_authenticated=True,
        )
    return user


async def get_current_admin_user(
    user: UserContext = Depends(get_current_user)
) -> UserContext:
    from prometheus.security.abac_engine import abac_engine
    is_admin = 'admin' in user.roles or 'vp_engineering' in user.roles
    if not is_admin:
        abac_user = abac_engine.get_user(user.user_id)
        if abac_user and abac_user.is_admin:
            is_admin = True
    if not is_admin:
        allow_insecure = getattr(settings, 'allow_insecure_admin', False)
        if not (allow_insecure and settings.environment in ('development', 'staging')):
            raise HTTPException(status_code=403, detail='Forbidden: Administrative clearance required.')
    return user
