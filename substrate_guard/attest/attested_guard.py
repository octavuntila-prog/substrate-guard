"""Optional wrapper: sign events after Guard processing."""

from __future__ import annotations

import logging
from typing import Any

from .device_key import DeviceKey
from .fingerprint import DeviceFingerprint
from .local_ca import LocalCA
from .signer import EventSigner

logger = logging.getLogger("substrate_guard.attest")


class AttestedGuard:
    """Layer 5: attach software device attestation to each event dict."""

    def __init__(self, guard: Any | None = None, config: dict | None = None) -> None:
        config = config or {}
        key_dir = config.get("key_dir")
        ca_dir = config.get("ca_dir")
        if not key_dir or not ca_dir:
            raise ValueError("AttestedGuard requires config key_dir and ca_dir (use tempfile in tests)")
        self.guard = guard
        self.fingerprint = DeviceFingerprint()
        self.device_key = DeviceKey(key_dir=key_dir)
        self.ca = LocalCA(self.device_key, ca_dir=ca_dir)
        self.signer = EventSigner(self.device_key, self.fingerprint, self.ca)
        logger.info(
            "Device attestation: device_id=%s fingerprint=%s... cert=%s",
            self.device_key.device_id,
            self.fingerprint.fingerprint()[:16],
            self.ca.current["serial"],
        )

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.signer.sign_event(event)

    def status(self) -> dict[str, Any]:
        cur = self.ca.current
        st: dict[str, Any] = {
            "device_id": self.device_key.device_id,
            "fingerprint": self.fingerprint.fingerprint(),
            "cert_serial": cur["serial"],
            "cert_expires": cur["expires_at"],
            "cert_valid": self.ca._is_valid(cur),
            "attestation_backend": "software-key",
            "tpm_available": False,
        }
        if self.guard is not None and hasattr(self.guard, "status"):
            st["guard"] = self.guard.status()
        return st
