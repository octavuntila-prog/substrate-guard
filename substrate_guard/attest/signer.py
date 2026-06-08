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
        """Verify a signed event against THIS signer's device key.

        Self-attestation: validates events signed by the local device key only
        (the embedded signature is checked against ``self.device_key``, not against
        the attestation's ``public_key`` — which is a truncated preview). There is
        no cross-device PKI, so an event from another device is not validated here.
        The signature covers ``{event, attestation}``, so the event body AND every
        attestation field (device_id, fingerprint, ...) are tamper-evident.
        """
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
