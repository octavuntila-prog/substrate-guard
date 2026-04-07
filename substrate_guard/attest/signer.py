"""Sign event payloads with device key + attach attestation metadata."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .device_key import DeviceKey
    from .fingerprint import DeviceFingerprint
    from .local_ca import LocalCA


class EventSigner:
    """Attach ``device_attestation`` block and sign ``event`` + attestation payload."""

    def __init__(
        self,
        device_key: DeviceKey,
        fingerprint: DeviceFingerprint,
        local_ca: LocalCA,
    ) -> None:
        self.device_key = device_key
        self.fingerprint = fingerprint
        self.ca = local_ca

    def sign_event(self, event: dict[str, Any]) -> dict[str, Any]:
        attestation = dict(self.ca.attestation())
        attestation["device_fingerprint"] = self.fingerprint.fingerprint()
        payload = json.dumps(
            {"event": event, "attestation": attestation},
            sort_keys=True,
        ).encode()
        signature = self.device_key.sign(payload)
        out = {
            **event,
            "device_attestation": {
                **attestation,
                "signature": signature.hex(),
                "backend": "software-key",
            },
        }
        return out

    def verify_signed_event(self, signed_event: dict[str, Any]) -> bool:
        att = signed_event.get("device_attestation")
        if not isinstance(att, dict):
            return False
        sig_hex = att.get("signature")
        if not sig_hex:
            return False
        event_copy = {k: v for k, v in signed_event.items() if k != "device_attestation"}
        att_copy = {
            k: v
            for k, v in att.items()
            if k not in ("signature", "backend")
        }
        payload = json.dumps(
            {"event": event_copy, "attestation": att_copy},
            sort_keys=True,
        ).encode()
        return self.device_key.verify(payload, bytes.fromhex(sig_hex))
