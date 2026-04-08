"""Ed25519 device identity using cryptography (no PyNaCl required)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class DeviceKey:
    """Load or generate a device Ed25519 keypair under ``key_dir``."""

    def __init__(self, key_dir: str | Path) -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self._private_path = self.key_dir / "device.key"
        self._public_path = self.key_dir / "device.pub"
        self._signing_key: Ed25519PrivateKey | None = None
        self._verify_key = None
        self._load_or_generate()

    def _load_or_generate(self) -> None:
        if self._private_path.exists():
            self._load()
        else:
            self._generate()

    def _generate(self) -> None:
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self._private_path.write_bytes(priv)
        self._public_path.write_bytes(pub)
        if os.name != "nt":
            try:
                os.chmod(self._private_path, 0o600)
                os.chmod(self._public_path, 0o644)
            except OSError:
                pass
        self._signing_key = sk
        self._verify_key = sk.public_key()

    def _load(self) -> None:
        priv_bytes = self._private_path.read_bytes()
        self._signing_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        self._verify_key = self._signing_key.public_key()
        pub = self._verify_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if not self._public_path.exists():
            self._public_path.write_bytes(pub)

    def sign(self, data: bytes) -> bytes:
        if self._signing_key is None:
            raise RuntimeError("DeviceKey has no signing key")
        return self._signing_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self._verify_key is None:
            return False
        try:
            self._verify_key.verify(signature, data)
            return True
        except Exception:
            return False

    @property
    def public_key_hex(self) -> str:
        if self._verify_key is None:
            raise RuntimeError("DeviceKey has no verify key")
        raw = self._verify_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return raw.hex()

    @property
    def device_id(self) -> str:
        raw = bytes.fromhex(self.public_key_hex)
        return hashlib.sha256(raw).hexdigest()[:16]
