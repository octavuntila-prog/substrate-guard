"""Stable device fingerprint (no TPM): hostname, machine-id, SSH host key hash, etc."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import uuid
from pathlib import Path


class DeviceFingerprint:
    """Stable hash of host identity markers (best-effort on Linux; works on Windows)."""

    def __init__(self) -> None:
        self._cache: str | None = None

    def collect(self) -> dict:
        return {
            "hostname": platform.node(),
            "machine": platform.machine(),
            "system": platform.system(),
            "cpu_count": os.cpu_count() or 0,
            "machine_id": self._read_file("/etc/machine-id"),
            "ssh_host_key": self._get_ssh_host_key_fingerprint(),
            "mac_addresses": self._get_mac_addresses(),
            "boot_id": self._read_file("/proc/sys/kernel/random/boot_id"),
        }

    def fingerprint(self) -> str:
        if self._cache is not None:
            return self._cache
        data = self.collect()
        stable = {
            "machine_id": data["machine_id"],
            "ssh_host_key": data["ssh_host_key"],
            "hostname": data["hostname"],
            "machine": data["machine"],
            "mac_addresses": data["mac_addresses"],
        }
        raw = json.dumps(stable, sort_keys=True).encode()
        self._cache = hashlib.sha256(raw).hexdigest()
        return self._cache

    def clear_cache(self) -> None:
        self._cache = None

    def _read_file(self, path: str) -> str:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace").strip()
        except (OSError, FileNotFoundError):
            return "unknown"

    def _get_ssh_host_key_fingerprint(self) -> str:
        candidates = [
            Path("/etc/ssh/ssh_host_ed25519_key.pub"),
            Path("/etc/ssh/ssh_host_rsa_key.pub"),
            Path.home() / ".ssh" / "id_ed25519.pub",
        ]
        for p in candidates:
            try:
                if not p.exists():
                    continue
                content = p.read_text(encoding="utf-8", errors="replace").strip()
                return hashlib.sha256(content.encode()).hexdigest()[:32]
            except OSError:
                continue
        return "no-ssh-key"

    def _get_mac_addresses(self) -> list[str]:
        macs: list[str] = []
        net_path = Path("/sys/class/net")
        try:
            if net_path.is_dir():
                for iface in sorted(net_path.iterdir()):
                    if iface.name in ("lo",):
                        continue
                    addr_file = iface / "address"
                    if addr_file.exists():
                        mac = addr_file.read_text().strip()
                        if mac and mac != "00:00:00:00:00:00":
                            macs.append(mac)
        except OSError:
            pass
        if not macs:
            node = uuid.getnode()
            if (node >> 40) % 2 == 0 and node:
                parts = [f"{(node >> i) & 0xFF:02x}" for i in range(40, -8, -8)]
                macs.append(":".join(parts))
        return sorted(macs)

    def verify(self, expected_fingerprint: str) -> bool:
        return self.fingerprint() == expected_fingerprint
