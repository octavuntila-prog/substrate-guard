"""Layer 5: Device Attestation — cryptographic device identity for every event.

Components:
- DeviceFingerprint: stable hash from machine-id, SSH key, MACs
- DeviceKey: Ed25519 signing (or HMAC fallback)
- LocalCA: mini CA issuing 24h certificates
- AttestedGuard: wraps Guard with attestation on every event
"""

from .fingerprint import DeviceFingerprint
from .device_key import DeviceKey
from .local_ca import LocalCA, DeviceCert
from .attested_guard import AttestedGuard, AttestedGuardEvent, EventAttestation

__all__ = [
    "DeviceFingerprint",
    "DeviceKey",
    "LocalCA",
    "DeviceCert",
    "AttestedGuard",
    "AttestedGuardEvent",
    "EventAttestation",
]
