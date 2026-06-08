"""Ed25519 device identity using cryptography (no PyNaCl required).

The private key is stored UNENCRYPTED on disk (raw Ed25519, NoEncryption) and is
protected by file permissions: owner-only via ``chmod 0o600`` on POSIX and via an
``icacls`` ACL restriction on Windows. The audited gap was that Windows had NO
restriction (``chmod`` only toggles the read-only bit there), leaving the key
readable by other accounts. At-rest passphrase encryption is future work; until
then ``key_dir`` should live on a protected volume.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger("substrate_guard.attest")


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
        self._restrict_private()
        if os.name != "nt":
            try:
                os.chmod(self._public_path, 0o644)
            except OSError:
                pass
        self._signing_key = sk
        self._verify_key = sk.public_key()

    def _restrict_private(self) -> None:
        """Restrict the at-rest private key to the owner only.

        POSIX: ``chmod 0o600``. Windows: ``os.chmod`` only toggles the read-only bit
        (not the ACL), so use ``icacls`` to remove inherited permissions and grant
        the current user alone -- otherwise the unencrypted key is readable by other
        accounts. Failures are logged loudly (the key is exposed), never raised.
        """
        path = self._private_path
        if not path.exists():
            return
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError as e:
                logger.warning("Could not chmod device private key: %s", e)
            return
        import getpass
        import shutil
        import subprocess

        icacls = shutil.which("icacls")  # full path (avoids partial-path exec)
        if icacls is None:
            logger.warning(
                "icacls not found; cannot restrict the device private-key ACL. The key "
                "at %s is stored UNENCRYPTED and may be readable by other accounts.", path,
            )
            return
        user = os.environ.get("USERNAME") or getpass.getuser()
        try:
            subprocess.run(
                [icacls, str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                check=True, capture_output=True, timeout=15,
            )
        except Exception as e:  # best-effort hardening: must not crash key setup
            logger.warning(
                "Could not restrict the device private-key ACL on Windows (%s). The "
                "key at %s is stored UNENCRYPTED and may be readable by other accounts "
                "-- restrict it manually or move key_dir to a protected location.",
                e, path,
            )

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
        self._restrict_private()  # ensure an existing key is owner-only

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

    @staticmethod
    def verify_with_public_key(public_key_hex: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature against an arbitrary raw Ed25519 public key (hex).

        Used to check a self-signed certificate against the key it embeds, rather
        than against a fixed local key (which would accept any identity that fixed
        key chose to sign).
        """
        try:
            verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            verifier.verify(signature, data)
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
