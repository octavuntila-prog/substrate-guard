"""Ed25519 device identity using cryptography (no PyNaCl required).

At-rest protection has two levels (audit 2026-07-17 item #14):

1. **Passphrase encryption (recommended):** pass ``passphrase=`` or set
   ``SUBSTRATE_ATTEST_KEY_PASSPHRASE`` — the private key is stored as
   PKCS#8 PEM under ``BestAvailableEncryption``. An existing raw key is
   transparently UPGRADED to the encrypted format on first load with a
   passphrase. Loading an encrypted key without the passphrase (or with a
   wrong one) fails LOUDLY — it never silently regenerates an identity.
2. **File permissions (always applied):** owner-only via ``chmod 0o600`` on
   POSIX and via an ``icacls`` ACL restriction on Windows (the audited gap
   was that ``chmod`` only toggles the read-only bit there).

Without a passphrase the key remains raw-unencrypted on disk (prototype
default, permissions-only) — the loader warns about it.
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

_PASSPHRASE_ENV = "SUBSTRATE_ATTEST_KEY_PASSPHRASE"  # nosec B105 -- env-var NAME, not a secret value
_PEM_HEADER = b"-----BEGIN"


class DeviceKey:
    """Load or generate a device Ed25519 keypair under ``key_dir``.

    ``passphrase`` (or env ``SUBSTRATE_ATTEST_KEY_PASSPHRASE``) enables at-rest
    encryption of the private key (PKCS#8 PEM, BestAvailableEncryption).
    """

    def __init__(self, key_dir: str | Path, passphrase: str | None = None) -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self._private_path = self.key_dir / "device.key"
        self._public_path = self.key_dir / "device.pub"
        self._passphrase = (passphrase or os.environ.get(_PASSPHRASE_ENV) or None)
        self._signing_key: Ed25519PrivateKey | None = None
        self._verify_key = None
        self._load_or_generate()

    def _load_or_generate(self) -> None:
        if self._private_path.exists():
            self._load()
        else:
            self._generate()

    def _private_bytes_for_storage(self, sk: Ed25519PrivateKey) -> bytes:
        """Serialized private key for disk: encrypted PKCS#8 PEM when a
        passphrase is configured, raw bytes otherwise (prototype default)."""
        if self._passphrase:
            return sk.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self._passphrase.encode()),
            )
        logger.warning(
            "Device private key at %s is stored UNENCRYPTED (permissions-only). "
            "Set %s to enable at-rest encryption.",
            self._private_path, _PASSPHRASE_ENV,
        )
        return sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def _generate(self) -> None:
        sk = Ed25519PrivateKey.generate()
        priv = self._private_bytes_for_storage(sk)
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
        if priv_bytes.startswith(_PEM_HEADER):
            # Encrypted PKCS#8 PEM (or unencrypted PEM). FAIL LOUD on a missing or
            # wrong passphrase — never silently regenerate a device identity.
            pw = self._passphrase.encode() if self._passphrase else None
            try:
                key = serialization.load_pem_private_key(priv_bytes, password=pw)
            except TypeError as e:  # encrypted file, no passphrase supplied
                raise RuntimeError(
                    f"Device key at {self._private_path} is passphrase-encrypted; "
                    f"set {_PASSPHRASE_ENV} (or pass passphrase=) to load it."
                ) from e
            except ValueError as e:  # wrong passphrase / corrupt PEM
                raise RuntimeError(
                    f"Could not decrypt device key at {self._private_path}: wrong "
                    f"passphrase or corrupted key file."
                ) from e
            if not isinstance(key, Ed25519PrivateKey):
                raise RuntimeError(
                    f"Device key at {self._private_path} is not an Ed25519 key."
                )
            self._signing_key = key
        else:
            self._signing_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
            if not self._passphrase:
                logger.warning(
                    "Device private key at %s is stored UNENCRYPTED (permissions-"
                    "only). Set %s to upgrade it to at-rest encryption.",
                    self._private_path, _PASSPHRASE_ENV,
                )
            if self._passphrase:
                # UPGRADE path: raw legacy key + passphrase now configured ->
                # rewrite at rest as encrypted PKCS#8 PEM (same identity).
                self._private_path.write_bytes(
                    self._private_bytes_for_storage(self._signing_key)
                )
                logger.info(
                    "Device key at %s upgraded from raw to passphrase-encrypted "
                    "PKCS#8 PEM (same key material).", self._private_path,
                )
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
