"""Device Key — Ed25519 keypair for signing events.

Each device gets a unique Ed25519 keypair generated at install time.
The private key is stored with 600 permissions. Every event signed
with this key is cryptographically attributable to this device.

When TPM hardware is available, the key would be stored in TPM
instead of filesystem. The signing interface is identical — only
the storage backend changes.

Usage:
    dk = DeviceKey()
    signature = dk.sign(b"event data")
    assert dk.verify(b"event data", signature)
    
    # Export public key for verification by others
    pub_pem = dk.public_key_pem
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("substrate_guard.attest.device_key")

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography package not installed — DeviceKey will use HMAC fallback")


class DeviceKey:
    """Ed25519 device signing key.
    
    Generates or loads an Ed25519 keypair for the current device.
    Signs event data so every action is attributable to a specific device.
    
    Args:
        key_dir: Directory to store the keypair.
        key_name: Base name for key files.
    """

    def __init__(
        self,
        key_dir: str = "/var/lib/substrate-guard/keys",
        key_name: str = "device_ed25519",
    ):
        self._key_dir = Path(key_dir)
        self._priv_path = self._key_dir / key_name
        self._pub_path = self._key_dir / f"{key_name}.pub"
        self._backend = "ed25519" if HAS_CRYPTO else "hmac-fallback"
        
        self._private_key = None
        self._public_key = None
        
        if HAS_CRYPTO:
            self._load_or_generate()
        else:
            # HMAC fallback — use a random secret as "key"
            self._hmac_secret = self._load_or_generate_hmac()

    def _load_or_generate(self):
        """Load existing Ed25519 key or generate new one."""
        if self._priv_path.exists():
            try:
                key_bytes = self._priv_path.read_bytes()
                self._private_key = serialization.load_pem_private_key(key_bytes, password=None)
                self._public_key = self._private_key.public_key()
                logger.info(f"Device key loaded: {self._priv_path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load key: {e} — generating new one")
        
        self._generate_key()

    def _generate_key(self):
        """Generate a new Ed25519 keypair."""
        self._key_dir.mkdir(parents=True, exist_ok=True)
        
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        
        # Save private key with restrictive permissions
        priv_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._priv_path.write_bytes(priv_pem)
        os.chmod(self._priv_path, 0o600)
        
        # Save public key
        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._pub_path.write_bytes(pub_pem)
        os.chmod(self._pub_path, 0o644)
        
        logger.info(f"New device key generated: {self._priv_path}")

    def _load_or_generate_hmac(self) -> bytes:
        """Fallback: use HMAC with a random secret."""
        secret_path = self._key_dir / "device_hmac.secret"
        self._key_dir.mkdir(parents=True, exist_ok=True)
        
        if secret_path.exists():
            return secret_path.read_bytes()
        
        secret = os.urandom(32)
        secret_path.write_bytes(secret)
        os.chmod(secret_path, 0o600)
        return secret

    def sign(self, data: bytes) -> bytes:
        """Sign data with the device key.
        
        Returns Ed25519 signature (64 bytes) or HMAC-SHA256 (32 bytes).
        """
        if HAS_CRYPTO and self._private_key:
            return self._private_key.sign(data)
        else:
            import hashlib, hmac
            return hmac.new(self._hmac_secret, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against the device's public key."""
        if HAS_CRYPTO and self._public_key:
            try:
                self._public_key.verify(signature, data)
                return True
            except InvalidSignature:
                return False
        else:
            import hashlib, hmac
            expected = hmac.new(self._hmac_secret, data, hashlib.sha256).digest()
            return hmac.compare_digest(signature, expected)

    def sign_hex(self, data: str) -> str:
        """Sign a string, return hex signature."""
        return self.sign(data.encode()).hex()

    def verify_hex(self, data: str, signature_hex: str) -> bool:
        """Verify a hex signature against a string."""
        return self.verify(data.encode(), bytes.fromhex(signature_hex))

    @property
    def public_key_pem(self) -> str:
        """Export public key as PEM string."""
        if HAS_CRYPTO and self._public_key:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        return "hmac-fallback-no-public-key"

    @property
    def backend(self) -> str:
        """Key storage backend: 'ed25519' or 'hmac-fallback'."""
        return self._backend

    def info(self) -> dict:
        """Key information for reports."""
        return {
            "backend": self._backend,
            "key_dir": str(self._key_dir),
            "tpm_available": False,
            "attestation_backend": "software-key",
            "public_key_path": str(self._pub_path) if HAS_CRYPTO else "N/A",
            "algorithm": "Ed25519" if HAS_CRYPTO else "HMAC-SHA256",
        }
