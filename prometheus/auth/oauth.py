
import os
import time
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import jwt
import httpx
from pydantic import BaseModel
from prometheus.memory.firestore_store import firestore_store, UserProfile

logger = logging.getLogger('prometheus.auth')

JWT_SECRET = os.getenv('JWT_SECRET', 'prometheus_enterprise_jwt_secret_dev_key_12345')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_HOURS = 24

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'https://prometheus-chief-of-staff-135010851380.us-central1.run.app/api/v1/auth/google/callback')

def create_session_token(
    user_id: str,
    email: str,
    tenant_id: str,
    scopes: Optional[list] = None,
    roles: Optional[list] = None,
) -> str:
    payload = {
        'sub': user_id,
        'email': email,
        'tenant_id': tenant_id,
        'scopes': scopes or ['engineering', 'platform'],
        'roles': roles or ['operator'],
        'exp': datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_session_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception as e:
        logger.debug(f'Invalid session token: {e}')
        return None

def get_google_auth_url(state: str = 'default') -> str:
    if not GOOGLE_CLIENT_ID:
        return '/login?error=missing_google_client_id'
    
    base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'state': state,
        'access_type': 'offline',
        'prompt': 'select_account'
    }
    query = '&'.join([f'{k}={v}' for k, v in params.items()])
    return f'{base_url}?{query}'

async def exchange_google_code(code: str) -> Optional[Dict[str, Any]]:
    token_url = 'https://oauth2.googleapis.com/token'
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(token_url, data=data, timeout=10.0)
            if resp.status_code != 200:
                logger.error(f'Google token exchange failed: {resp.text}')
                return None
            tokens = resp.json()
            id_token_jwt = tokens.get('id_token')
            if id_token_jwt:
                try:
                    from google.oauth2 import id_token
                    from google.auth.transport import requests as google_requests
                    user_info = id_token.verify_oauth2_token(
                        id_token_jwt,
                        google_requests.Request(),
                        GOOGLE_CLIENT_ID or None,
                    )
                    return user_info
                except Exception as verify_err:
                    if os.getenv('ENVIRONMENT') == 'production':
                        logger.error(f'Google ID token signature verification failed: {verify_err}')
                        return None
                    user_info = jwt.decode(id_token_jwt, options={'verify_signature': False})
                    return user_info
    except Exception as e:
        logger.error(f'Exception during Google code exchange: {e}')
    return None
