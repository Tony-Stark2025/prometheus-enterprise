"""
Enterprise Cryptographic Vault Security for Prometheus.
Provides AES-256-GCM symmetric encryption for tenant integration secrets, API tokens, and PATs at rest in Firestore.
"""

import os
import base64
import hashlib
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("prometheus.security.vault_crypto")

DEFAULT_VAULT_SEED = os.getenv("VAULT_MASTER_KEY", os.getenv("SECRET_KEY", "prometheus-enterprise-master-vault-seed-2026"))


class VaultCrypto:
    """
    AES-256-GCM symmetric cipher utility for securing third-party credentials.
    """

    def __init__(self, master_key: Optional[str] = None):
        seed = (master_key or DEFAULT_VAULT_SEED).encode("utf-8")
        # Derive 256-bit key via SHA-256
        self._key = hashlib.sha256(seed).digest()
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts plaintext string with fresh 96-bit nonce and returns URL-safe Base64 ciphertext.
        Format: nonce (12 bytes) + ciphertext + auth_tag (16 bytes)
        """
        if not plaintext:
            return ""
        try:
            nonce = os.urandom(12)
            ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
            combined = nonce + ciphertext
            return "enc:v1:" + base64.urlsafe_b64encode(combined).decode("ascii")
        except Exception as e:
            logger.error(f"Failed to encrypt secret payload: {e}")
            raise

    def decrypt(self, encoded_ciphertext: str) -> str:
        """
        Decrypts an encrypted string. If the string is not encrypted (e.g. legacy or plaintext), returns it as-is.
        """
        if not encoded_ciphertext:
            return ""
        if not encoded_ciphertext.startswith("enc:v1:"):
            return encoded_ciphertext
        try:
            raw_b64 = encoded_ciphertext[7:]
            combined = base64.urlsafe_b64decode(raw_b64.encode("ascii"))
            nonce = combined[:12]
            ciphertext = combined[12:]
            decrypted = self._aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode("utf-8")
        except Exception as e:
            logger.warning(f"Failed to decrypt vault secret (possible key mismatch or corrupted data): {e}")
            return encoded_ciphertext

    @staticmethod
    def mask_token(token: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """
        Generates a secure display mask for API tokens (e.g. ghp_••••••••••••3a9f).
        """
        if not token:
            return ""
        # If token is encrypted string, don't display raw cipher
        if token.startswith("enc:v1:"):
            return "••••••••••••••••"
        if len(token) <= (prefix_len + suffix_len):
            return "••••••••"
        prefix = token[:prefix_len]
        suffix = token[-suffix_len:]
        return f"{prefix}••••••••{suffix}"


vault_crypto = VaultCrypto()

