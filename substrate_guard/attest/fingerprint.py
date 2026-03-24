"""Device Fingerprint — Stable hash from hardware identifiers.

Creates a unique, deterministic fingerprint for the current device
from /etc/machine-id, SSH host keys, and network MAC addresses.
Detects if the device has changed between runs.

The fingerprint is NOT a secret — it's a public identifier.
The device key (device_key.py) provides the signing capability.

Usage:
    fp = DeviceFingerprint()
    print(fp.fingerprint)       # "a3f8c2d1..."
    print(fp.components)        # what went into the hash
    assert fp.verify()          # True if device hasn't changed
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import socket
from pathlib import Path
from typing import Optional

logger = logging.getLogger("substrate_guard.attest.fingerprint")


class DeviceFingerprint:
    """Stable device fingerprint from hardware identifiers.
    
    Components (in order of stability):
    1. /etc/machine-id — set at OS install, survives reboots
    2. SSH host ed25519 public key — set at first boot
    3. MAC addresses — stable unless NIC replaced
    4. hostname — can change but rarely does on servers
    
    The fingerprint is SHA-256(canonical JSON of all components).
    Missing components are marked as "unavailable" — the fingerprint
    is still valid, just less unique.
    """

    def __init__(self, cache_path: Optional[str] = None):
        self._cache_path = cache_path or "/var/lib/substrate-guard/device_fingerprint.json"
        self._components = self._collect_components()
        self._fingerprint = self._compute_fingerprint()

    def _collect_components(self) -> dict:
        """Collect all hardware identifiers."""
        components = {
            "machine_id": self._read_machine_id(),
            "ssh_host_key": self._read_ssh_host_key(),
            "mac_addresses": self._read_mac_addresses(),
            "hostname": socket.gethostname(),
            "platform": {
                "system": platform.system(),
                "machine": platform.machine(),
                "release": platform.release(),
            },
        }
        return components

    def _read_machine_id(self) -> str:
        """Read /etc/machine-id (set at OS install)."""
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            try:
                mid = Path(path).read_text().strip()
                if mid:
                    return mid
            except (FileNotFoundError, PermissionError):
                continue
        return "unavailable"

    def _read_ssh_host_key(self) -> str:
        """Read SSH host ed25519 public key."""
        key_path = "/etc/ssh/ssh_host_ed25519_key.pub"
        try:
            content = Path(key_path).read_text().strip()
            # Extract just the key data (skip type and comment)
            parts = content.split()
            return parts[1] if len(parts) >= 2 else content
        except (FileNotFoundError, PermissionError):
            return "unavailable"

    def _read_mac_addresses(self) -> list[str]:
        """Read MAC addresses from /sys/class/net/."""
        macs = []
        net_path = Path("/sys/class/net")
        if not net_path.exists():
            return ["unavailable"]
        
        for iface in sorted(net_path.iterdir()):
            name = iface.name
            if name == "lo":
                continue
            addr_file = iface / "address"
            try:
                mac = addr_file.read_text().strip()
                if mac and mac != "00:00:00:00:00:00":
                    macs.append(f"{name}={mac}")
            except (FileNotFoundError, PermissionError):
                continue
        
        return macs if macs else ["unavailable"]

    def _compute_fingerprint(self) -> str:
        """SHA-256 of canonical JSON of all components."""
        # Use only the stable components for the hash
        stable = {
            "machine_id": self._components["machine_id"],
            "ssh_host_key": self._components["ssh_host_key"],
            "mac_addresses": self._components["mac_addresses"],
        }
        canonical = json.dumps(stable, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def save(self):
        """Save fingerprint to disk for later verification."""
        Path(self._cache_path).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "fingerprint": self._fingerprint,
            "components": self._components,
        }
        Path(self._cache_path).write_text(json.dumps(data, indent=2))
        logger.info(f"Device fingerprint saved: {self._fingerprint[:16]}...")

    def verify(self) -> bool:
        """Verify current device matches saved fingerprint.
        
        Returns True if no saved fingerprint exists (first run).
        """
        try:
            saved = json.loads(Path(self._cache_path).read_text())
            return saved["fingerprint"] == self._fingerprint
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return True  # No saved fingerprint = first run

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def components(self) -> dict:
        return self._components.copy()

    def to_dict(self) -> dict:
        return {
            "device_id": self._fingerprint[:16],
            "fingerprint": self._fingerprint,
            "hostname": self._components["hostname"],
            "machine": self._components["platform"]["machine"],
            "system": self._components["platform"]["system"],
        }
