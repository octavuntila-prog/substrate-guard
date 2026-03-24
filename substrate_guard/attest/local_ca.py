"""Local CA — Mini certificate authority for short-lived device certificates.

Issues 24-hour certificates to devices, auto-rotates before expiry.
This is what S3 described in 9 independent variants: credentials are
insufficient; only cryptographic identity proves provenance.

When `cryptography` is not available, falls back to a JSON-based
certificate format with HMAC signatures.

Usage:
    ca = LocalCA()
    cert = ca.issue_certificate(device_fingerprint="a3f8c2...")
    assert cert.is_valid()
    
    # After 24h, auto-renew
    cert = ca.renew_if_needed(cert)
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger("substrate_guard.attest.local_ca")

DEFAULT_TTL = 86400  # 24 hours
RENEW_BEFORE = 3600  # Renew 1 hour before expiry


@dataclass
class DeviceCert:
    """A short-lived device certificate."""
    serial: str
    device_fingerprint: str
    issued_at: float
    expires_at: float
    issuer: str
    signature: str  # HMAC or Ed25519 over the cert contents

    def is_valid(self, now: Optional[float] = None) -> bool:
        """Check if certificate is currently valid."""
        t = now or time.time()
        return self.issued_at <= t <= self.expires_at

    def needs_renewal(self, now: Optional[float] = None) -> bool:
        """Check if certificate should be renewed."""
        t = now or time.time()
        return t >= (self.expires_at - RENEW_BEFORE)

    def remaining_seconds(self, now: Optional[float] = None) -> float:
        t = now or time.time()
        return max(0, self.expires_at - t)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> DeviceCert:
        return cls(**d)


class LocalCA:
    """Mini certificate authority for device attestation.
    
    Issues short-lived certificates (default 24h) that bind a device
    fingerprint to a time window. Auto-rotates before expiry.
    
    Args:
        ca_dir: Directory for CA key and issued certs.
        ttl: Certificate time-to-live in seconds.
        ca_name: Issuer name for certificates.
    """

    def __init__(
        self,
        ca_dir: str = "/var/lib/substrate-guard/ca",
        ttl: int = DEFAULT_TTL,
        ca_name: str = "substrate-guard-ca",
    ):
        self._ca_dir = Path(ca_dir)
        self._ttl = ttl
        self._ca_name = ca_name
        self._ca_dir.mkdir(parents=True, exist_ok=True)
        
        # CA signing key (HMAC-based for simplicity)
        self._ca_secret = self._load_or_create_ca_key()
        self._certs_issued = 0

    def _load_or_create_ca_key(self) -> bytes:
        """Load or generate the CA signing key."""
        key_path = self._ca_dir / "ca.key"
        if key_path.exists():
            return key_path.read_bytes()
        
        key = os.urandom(32)
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
        logger.info(f"New CA key generated: {key_path}")
        return key

    def _sign_cert_data(self, cert_data: str) -> str:
        """HMAC-SHA256 sign the certificate data."""
        return hmac_mod.new(
            self._ca_secret, cert_data.encode(), hashlib.sha256
        ).hexdigest()

    def issue_certificate(
        self,
        device_fingerprint: str,
        ttl: Optional[int] = None,
    ) -> DeviceCert:
        """Issue a new short-lived certificate for a device.
        
        Args:
            device_fingerprint: Device's fingerprint hash.
            ttl: Override default TTL (seconds).
        """
        now = time.time()
        cert_ttl = ttl or self._ttl
        serial = str(uuid.uuid4())
        
        # Data to sign
        cert_data = json.dumps({
            "serial": serial,
            "device_fingerprint": device_fingerprint,
            "issued_at": now,
            "expires_at": now + cert_ttl,
            "issuer": self._ca_name,
        }, sort_keys=True)
        
        signature = self._sign_cert_data(cert_data)
        
        cert = DeviceCert(
            serial=serial,
            device_fingerprint=device_fingerprint,
            issued_at=now,
            expires_at=now + cert_ttl,
            issuer=self._ca_name,
            signature=signature,
        )
        
        self._certs_issued += 1
        logger.info(
            f"Certificate issued: serial={serial[:8]}... "
            f"device={device_fingerprint[:8]}... TTL={cert_ttl}s"
        )
        
        return cert

    def verify_certificate(self, cert: DeviceCert) -> tuple[bool, Optional[str]]:
        """Verify a certificate's signature and validity.
        
        Returns:
            (True, None) if valid
            (False, reason) if invalid
        """
        # Check expiry
        if not cert.is_valid():
            return False, "Certificate expired"
        
        # Verify signature
        cert_data = json.dumps({
            "serial": cert.serial,
            "device_fingerprint": cert.device_fingerprint,
            "issued_at": cert.issued_at,
            "expires_at": cert.expires_at,
            "issuer": cert.issuer,
        }, sort_keys=True)
        
        expected_sig = self._sign_cert_data(cert_data)
        if not hmac_mod.compare_digest(cert.signature, expected_sig):
            return False, "Signature mismatch — certificate may be tampered"
        
        return True, None

    def renew_if_needed(self, cert: DeviceCert) -> DeviceCert:
        """Renew certificate if it's near expiry.
        
        Returns the same cert if still valid, or a new cert if renewed.
        """
        if cert.needs_renewal():
            logger.info(f"Renewing certificate {cert.serial[:8]}...")
            return self.issue_certificate(cert.device_fingerprint)
        return cert

    def info(self) -> dict:
        """CA information for reports."""
        return {
            "ca_name": self._ca_name,
            "ca_dir": str(self._ca_dir),
            "default_ttl_s": self._ttl,
            "certs_issued": self._certs_issued,
            "signing_algorithm": "HMAC-SHA256",
        }
