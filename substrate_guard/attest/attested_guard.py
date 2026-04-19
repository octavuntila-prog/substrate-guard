"""Attested Guard — Wraps Guard with device attestation on every event.

Every event that passes through the Guard pipeline gets a cryptographic
device attestation attached: device fingerprint, certificate serial,
Ed25519 signature. This proves provenance — which physical device
generated which action.

Usage:
    guard = AttestedGuard(
        observe=True, policy="policies/", verify=True,
    )
    
    result = guard.evaluate_event(event)
    # result.attestation contains: device_id, cert_serial, signature
    
    # Full status
    print(guard.attestation_status())
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import Optional

from ..guard import Guard, GuardEvent
from ..observe.events import Event
from .fingerprint import DeviceFingerprint
from .device_key import DeviceKey
from .local_ca import LocalCA, DeviceCert

logger = logging.getLogger("substrate_guard.attest.guard")


@dataclass
class EventAttestation:
    """Device attestation attached to a single event."""
    device_id: str          # First 16 chars of fingerprint
    device_fingerprint: str # Full SHA-256 fingerprint
    cert_serial: str        # Certificate serial number
    cert_valid: bool        # Is the certificate currently valid?
    signature: str          # Ed25519/HMAC signature of event data
    key_backend: str        # "ed25519" or "hmac-fallback"
    tpm_available: bool     # Always False on Hetzner VPS
    timestamp: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttestedGuardEvent:
    """A GuardEvent with device attestation."""
    guard_event: GuardEvent
    attestation: EventAttestation

    def to_dict(self) -> dict:
        ge = {
            "event": self.guard_event.event.to_dict() if hasattr(self.guard_event.event, 'to_dict') else str(self.guard_event.event),
            "policy_allowed": self.guard_event.policy_decision.allowed,
            "policy_reasons": self.guard_event.policy_decision.reasons,
        }
        return {
            "guard": ge,
            "attestation": self.attestation.to_dict(),
        }


class AttestedGuard:
    """Guard with Layer 5 device attestation.
    
    Wraps the standard Guard pipeline and adds cryptographic
    device attestation to every event:
    
    1. Device fingerprint (from machine-id, SSH key, MACs)
    2. Short-lived certificate (24h, auto-renewed)
    3. Ed25519 signature on event data
    
    The attestation proves: "this event was generated on device X,
    certified by CA Y, at time Z, and signed with key K."
    
    On Hetzner VPS (no TPM), attestation_backend is "software-key".
    The protocol is identical to TPM-backed attestation — only the
    key storage differs. When TPM is available, change one line.
    
    Args:
        key_dir: Directory for device keys and CA.
        cert_ttl: Certificate TTL in seconds (default 24h).
        **guard_kwargs: Passed to Guard constructor.
    """

    def __init__(
        self,
        key_dir: str = "/var/lib/substrate-guard",
        cert_ttl: int = 86400,
        **guard_kwargs,
    ):
        # Core Guard (L1 + L2 + L3 + chain)
        self._guard = Guard(**guard_kwargs)
        
        # L5: Device attestation components
        self._fingerprint = DeviceFingerprint(
            cache_path=f"{key_dir}/device_fingerprint.json"
        )
        self._device_key = DeviceKey(key_dir=f"{key_dir}/keys")
        self._ca = LocalCA(ca_dir=f"{key_dir}/ca", ttl=cert_ttl)
        
        # Issue initial certificate
        self._cert = self._ca.issue_certificate(self._fingerprint.fingerprint)
        
        # Verify device hasn't changed
        if not self._fingerprint.verify():
            logger.warning("Device fingerprint mismatch — device may have changed!")
        self._fingerprint.save()
        
        self._attested_events = 0
        
        logger.info(
            f"AttestedGuard initialized: device={self._fingerprint.fingerprint[:16]}... "
            f"key={self._device_key.backend} cert={self._cert.serial[:8]}..."
        )

    def evaluate_event(self, event: Event) -> AttestedGuardEvent:
        """Evaluate event through Guard pipeline + attach attestation."""
        # Full Guard pipeline (L1 → L2 → L3 → chain)
        guard_event = self._guard.evaluate_event(event)
        
        # Auto-renew certificate if needed
        self._cert = self._ca.renew_if_needed(self._cert)
        
        # Sign the event data
        event_data = event.to_dict() if hasattr(event, 'to_dict') else {"raw": str(event)}
        event_data["_policy_allowed"] = guard_event.policy_decision.allowed
        canonical = json.dumps(event_data, sort_keys=True, default=str)
        signature = self._device_key.sign_hex(canonical)
        
        attestation = EventAttestation(
            device_id=self._fingerprint.fingerprint[:16],
            device_fingerprint=self._fingerprint.fingerprint,
            cert_serial=self._cert.serial,
            cert_valid=self._cert.is_valid(),
            signature=signature,
            key_backend=self._device_key.backend,
            tpm_available=False,
            timestamp=time.time(),
        )
        
        self._attested_events += 1
        
        return AttestedGuardEvent(
            guard_event=guard_event,
            attestation=attestation,
        )

    def verify_attestation(self, attested_event: AttestedGuardEvent) -> bool:
        """Verify an event's attestation signature."""
        att = attested_event.attestation
        ge = attested_event.guard_event
        
        event_data = ge.event.to_dict() if hasattr(ge.event, 'to_dict') else {"raw": str(ge.event)}
        event_data["_policy_allowed"] = ge.policy_decision.allowed
        canonical = json.dumps(event_data, sort_keys=True, default=str)
        
        return self._device_key.verify_hex(canonical, att.signature)

    def monitor(self, agent_id: str):
        """Delegate to Guard's monitor."""
        return self._guard.monitor(agent_id)

    def attestation_status(self) -> dict:
        """Full attestation status report."""
        cert_ok, cert_reason = self._ca.verify_certificate(self._cert)
        
        return {
            "device": self._fingerprint.to_dict(),
            "key": self._device_key.info(),
            "certificate": {
                "serial": self._cert.serial,
                "valid": cert_ok,
                "reason": cert_reason,
                "remaining_s": round(self._cert.remaining_seconds()),
                "expires_at": self._cert.expires_at,
            },
            "ca": self._ca.info(),
            "attested_events": self._attested_events,
            "tpm_available": False,
            "attestation_backend": "software-key",
        }

    @property
    def guard(self) -> Guard:
        return self._guard

    @property
    def device_fingerprint(self) -> str:
        return self._fingerprint.fingerprint

    @property
    def cert(self) -> DeviceCert:
        return self._cert
