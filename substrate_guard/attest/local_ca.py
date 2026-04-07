"""Short-lived local device certificate (signed with device key; software CA)."""

from __future__ import annotations

import json
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .device_key import DeviceKey

logger = logging.getLogger("substrate_guard.attest")


class LocalCA:
    """Issue a JSON certificate for the device key; rotate when expired (default 24h)."""

    def __init__(self, device_key: DeviceKey, ca_dir: str | Path) -> None:
        self.device_key = device_key
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self._cert_path = self.ca_dir / "current_cert.json"
        self._current_cert: dict[str, Any] | None = None
        self._load_or_issue()

    def _load_or_issue(self) -> None:
        if self._cert_path.exists():
            try:
                cert = json.loads(self._cert_path.read_text(encoding="utf-8"))
                if self._is_valid(cert):
                    self._current_cert = cert
                    return
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Could not load cert: %s", e)
        self._issue_new()

    def _issue_new(self) -> None:
        now = datetime.now(timezone.utc)
        cert_data = {
            "version": 1,
            "device_id": self.device_key.device_id,
            "public_key": self.device_key.public_key_hex,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=24)).isoformat(),
            "issuer": "substrate-guard-local-ca",
            "serial": hashlib.sha256(
                f"{self.device_key.device_id}:{now.isoformat()}".encode()
            ).hexdigest()[:16],
        }
        cert_bytes = json.dumps(cert_data, sort_keys=True).encode()
        signature = self.device_key.sign(cert_bytes)
        cert: dict[str, Any] = {
            **cert_data,
            "signature": signature.hex(),
        }
        self._cert_path.write_text(json.dumps(cert, indent=2), encoding="utf-8")
        self._current_cert = cert

    def _is_valid(self, cert: dict[str, Any]) -> bool:
        try:
            expires = datetime.fromisoformat(cert["expires_at"])
            return datetime.now(timezone.utc) < expires
        except (KeyError, ValueError, TypeError):
            return False

    @property
    def current(self) -> dict[str, Any]:
        if not self._current_cert or not self._is_valid(self._current_cert):
            self._issue_new()
        assert self._current_cert is not None
        return self._current_cert

    def verify_cert(self, cert: dict[str, Any]) -> bool:
        """Verify certificate signature (non-mutating)."""
        c = dict(cert)
        sig_hex = c.pop("signature", None)
        if not sig_hex:
            return False
        payload = json.dumps(c, sort_keys=True).encode()
        ok = self.device_key.verify(payload, bytes.fromhex(sig_hex))
        return ok

    def attestation(self) -> dict[str, Any]:
        cert = self.current
        pk = cert["public_key"]
        preview = pk[:32] + "..." if len(pk) > 32 else pk
        return {
            "device_id": cert["device_id"],
            "cert_serial": cert["serial"],
            "cert_expires": cert["expires_at"],
            "public_key_preview": preview,
            "attested_at": datetime.now(timezone.utc).isoformat(),
        }
