
import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from prometheus.security.vault_crypto import vault_crypto

logger = logging.getLogger('prometheus.memory.firestore')

class TenantIntegration(BaseModel):
    service: str
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class UserProfile(BaseModel):
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    tenant_id: str = 'default_enterprise'
    roles: List[str] = Field(default_factory=lambda: ['lead'])
    org_scopes: List[str] = Field(default_factory=lambda: ['engineering', 'platform'])
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class FirestoreStore:
    _instance = None

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.getenv('GCP_PROJECT_ID', os.getenv('GOOGLE_CLOUD_PROJECT', 'gen-lang-client-0942141479'))
        self._db = None
        self._memory_cache = {
            'users': {},
            'integrations': {},
            'tenants': {}
        }
        self._init_client()

    def _init_client(self):
        try:
            from google.cloud import firestore
            self._db = firestore.AsyncClient(project=self.project_id)
            logger.info(f'Connected to Google Cloud Firestore (project: {self.project_id})')
        except Exception as e:
            logger.warning(f'Firestore async client initialization skipped (using memory cache): {e}')
            self._db = None

    async def save_user(self, profile: UserProfile) -> UserProfile:
        self._memory_cache['users'][profile.user_id] = profile.model_dump()
        if self._db:
            try:
                doc_ref = self._db.collection('users').document(profile.user_id)
                await doc_ref.set(profile.model_dump())
            except Exception as e:
                logger.warning(f'Failed to write user to Firestore: {e}')
        return profile

    async def get_user(self, user_id: str) -> Optional[UserProfile]:
        if user_id in self._memory_cache['users']:
            return UserProfile(**self._memory_cache['users'][user_id])
        if self._db:
            try:
                doc_ref = self._db.collection('users').document(user_id)
                doc = await doc_ref.get()
                if doc.exists:
                    data = doc.to_dict()
                    self._memory_cache['users'][user_id] = data
                    return UserProfile(**data)
            except Exception as e:
                logger.warning(f'Failed to read user from Firestore: {e}')
        return None

    async def save_integration(self, tenant_id: str, service: str, config: Dict[str, Any]) -> TenantIntegration:
        # Encrypt sensitive secret fields before saving
        encrypted_config = {}
        for k, v in config.items():
            if any(s in k.lower() for s in ['token', 'secret', 'key', 'password']) and isinstance(v, str):
                encrypted_config[k] = vault_crypto.encrypt(v)
            else:
                encrypted_config[k] = v

        integration = TenantIntegration(service=service, enabled=True, config=encrypted_config)
        key = f'{tenant_id}:{service}'
        self._memory_cache['integrations'][key] = integration.model_dump()

        if self._db:
            try:
                doc_ref = self._db.collection('tenants').document(tenant_id).collection('integrations').document(service)
                await doc_ref.set(integration.model_dump())
            except Exception as e:
                logger.warning(f'Failed to write integration to Firestore: {e}')
        return integration

    async def get_integration(self, tenant_id: str, service: str) -> Optional[Dict[str, Any]]:
        key = f'{tenant_id}:{service}'
        raw_config = None
        if key in self._memory_cache['integrations']:
            raw_config = self._memory_cache['integrations'][key].get('config')
        elif self._db:
            try:
                doc_ref = self._db.collection('tenants').document(tenant_id).collection('integrations').document(service)
                doc = await doc_ref.get()
                if doc.exists:
                    data = doc.to_dict()
                    self._memory_cache['integrations'][key] = data
                    raw_config = data.get('config')
            except Exception as e:
                logger.warning(f'Failed to read integration from Firestore: {e}')

        if not raw_config:
            return None

        # Decrypt sensitive secret fields before returning to tool clients
        decrypted_config = {}
        for k, v in raw_config.items():
            if isinstance(v, str) and v.startswith('enc:v1:'):
                decrypted_config[k] = vault_crypto.decrypt(v)
            else:
                decrypted_config[k] = v
        return decrypted_config

    async def list_integrations(self, tenant_id: str) -> Dict[str, Dict[str, Any]]:
        result = {}
        for service in ['github', 'jira', 'slack']:
            cfg = await self.get_integration(tenant_id, service)
            if cfg:
                masked = {}
                for k, v in cfg.items():
                    if any(s in k.lower() for s in ['token', 'secret', 'key', 'password']) and isinstance(v, str):
                        masked[k] = vault_crypto.mask_token(v)
                    else:
                        masked[k] = v
                result[service] = {'connected': True, 'config': masked}
            else:
                result[service] = {'connected': False, 'config': {}}
        return result

    async def delete_integration(self, tenant_id: str, service: str) -> bool:
        key = f'{tenant_id}:{service}'
        if key in self._memory_cache['integrations']:
            del self._memory_cache['integrations'][key]

        if self._db:
            try:
                doc_ref = self._db.collection('tenants').document(tenant_id).collection('integrations').document(service)
                await doc_ref.delete()
            except Exception as e:
                logger.warning(f'Failed to delete integration in Firestore: {e}')
        return True

    async def get_sandbox_telemetry(self, tenant_id: str, telemetry_type: str) -> List[Dict[str, Any]]:
        """
        Retrieves dynamic sandbox telemetry records from Firestore or memory cache for isolated demo/testing.
        telemetry_type: 'prs', 'issues', or 'messages'
        """
        cache_key = f'{tenant_id}:sandbox_{telemetry_type}'
        if cache_key in self._memory_cache:
            return self._memory_cache[cache_key]

        if self._db:
            try:
                col_ref = self._db.collection('tenants').document(tenant_id).collection(f'sandbox_{telemetry_type}')
                docs = await col_ref.get()
                if docs:
                    data = [d.to_dict() for d in docs]
                    self._memory_cache[cache_key] = data
                    return data
            except Exception as e:
                logger.warning(f'Failed to read sandbox telemetry from Firestore: {e}')

        # Default fallback: dynamic clean enterprise data if unseeded
        from tools.seed_firestore_sandbox import seed_tenant_sandbox
        await seed_tenant_sandbox(tenant_id)
        return self._memory_cache.get(cache_key, [])


firestore_store = FirestoreStore()

