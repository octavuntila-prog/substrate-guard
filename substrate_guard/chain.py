"""Tamper-Evident Chain — HMAC-SHA256 audit chain on every event.

Each event is hashed with the previous hash, creating a tamper-evident chain.
Mid-chain modification, reordering, or insertion breaks it. (Tail-truncation -- a
valid prefix is itself a valid chain -- is NOT caught by verify() alone: pass
expected_count/expected_head, or anchor the head externally.)

This is the "black box" integrity layer — like a flight recorder's
crash-survivable storage, but for AI agent actions.

Usage:
    chain = AuditChain(secret="your-hmac-secret")
    
    # Add events as they flow through the pipeline
    chain.append(event)
    chain.append(event2)
    
    # Verify integrity
    assert chain.verify()  # True if chain is intact
    
    # Export signed audit trail
    chain.export("audit_trail.json")
    
    # Later: verify an exported trail
    AuditChain.verify_export("audit_trail.json", secret="your-hmac-secret")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import os
from dataclasses import dataclass, asdict
from typing import Any, Optional
from pathlib import Path


GENESIS_HASH = "0" * 64  # SHA-256 of nothing — chain starts here


@dataclass
class ChainEntry:
    """A single entry in the tamper-evident chain."""
    index: int
    timestamp: float
    event_type: str
    agent_id: str
    event_data: dict
    prev_hash: str
    hash: str  # HMAC-SHA256(secret, index + timestamp + event_data + prev_hash)

    def to_dict(self) -> dict:
        return asdict(self)


class ChainConfigError(ValueError):
    """Raised when AuditChain is constructed without HMAC secret and without
    explicit ``allow_random_fallback=True`` opt-in.

    Per M0.3 / v13.4.0 design: production deployments must always provide a
    stable HMAC secret (via ``secret=`` parameter or ``GUARD_HMAC_SECRET``
    environment variable). Random-key fallback is testing/demo only and must
    be opted into explicitly to prevent silent loss of cross-run chain
    verifiability.
    """
    pass


class AuditChain:
    """HMAC-SHA256 tamper-evident audit chain.
    
    Every event gets a hash that depends on:
    - The event data itself
    - The previous event's hash
    - A secret key (HMAC)
    - The event's position in the chain (index)
    
    Modifying, reordering, or inserting any event breaks the chain. NOTE: a valid
    PREFIX of the chain is itself a valid chain, so deleting events from the END
    (tail-truncation) is NOT detected by verify() alone -- pass expected_count /
    expected_head (held out-of-band) or anchor the head externally to catch it.

    Args:
        secret: HMAC secret key. If None, reads from ``GUARD_HMAC_SECRET``
                environment variable. If still None, raises
                ``ChainConfigError`` unless ``allow_random_fallback=True``.
        allow_random_fallback: If True, generates a random secret when none
                provided (chain not verifiable across runs — random key lost
                at process exit). For testing/demo only — production must
                always provide a stable secret. Default: False (fail-loud).
        bijotel_db: Optional path to a bijotel chain.db. When set, every
                ``append`` ALSO seals the event into bijotel's durable,
                tamper-evident chain (additive dual-write) — the in-memory
                chain is unchanged. This grants substrate-guard bijotel's
                persistent verify / Ed25519 export / Rekor / federation. The
                sink is FAIL-OPEN: a bijotel write error never breaks the
                guard's audit path. Default: None (sink off; behaviour
                byte-identical to before).
        bijotel_secret_hex: HMAC secret for the bijotel sink, as a HEX string
                (bijotel decodes via ``bytes.fromhex`` — a SEPARATE secret from
                substrate-guard's raw ``secret``). Falls back to the
                ``BIJOTEL_HMAC_SECRET`` env var. Required (and validated at
                construction, before any write) when ``bijotel_db`` is set.

    Raises:
        ChainConfigError: If no secret available (neither parameter nor env)
                and ``allow_random_fallback=False`` (default); also if
                ``bijotel_db`` is set but no valid hex bijotel secret is
                available (missing, invalid hex, or < 16 bytes) or the
                ``bijotel`` package is not importable.
    """

    def __init__(
        self,
        secret: Optional[str] = None,
        allow_random_fallback: bool = False,
        bijotel_db: Optional[str] = None,
        bijotel_secret_hex: Optional[str] = None,
    ):
        # Accept SUBSTRATE_GUARD_HMAC_SECRET (the operational/cron name, set from
        # /etc/substrate-guard/hmac.key) first, then the legacy GUARD_HMAC_SECRET.
        resolved_secret = (
            secret
            or os.environ.get("SUBSTRATE_GUARD_HMAC_SECRET")
            or os.environ.get("GUARD_HMAC_SECRET", "")
        )

        if not resolved_secret:
            if not allow_random_fallback:
                raise ChainConfigError(
                    "AuditChain requires an HMAC secret. Pass secret=, set "
                    "SUBSTRATE_GUARD_HMAC_SECRET (or GUARD_HMAC_SECRET) env, or pass "
                    "allow_random_fallback=True (testing only — not verifiable across runs)."
                )
            resolved_secret_bytes = os.urandom(32)
            import logging
            logging.getLogger("substrate_guard.chain").warning(
                "Using random HMAC secret — chain not verifiable across runs. "
                "Set SUBSTRATE_GUARD_HMAC_SECRET env or pass secret= for production."
            )
        else:
            resolved_secret_bytes = resolved_secret.encode()

        self._secret = resolved_secret_bytes
        self._entries: list[ChainEntry] = []
        self._head_hash: str = GENESIS_HASH
        self._lock = threading.Lock()  # serialize append; snapshot verify reads

        # --- Optional bijotel durable sink (F1, additive dual-write) ---
        # When bijotel_db is set, append() ALSO seals each event into bijotel's
        # persistent HMAC chain (gaining verify / Ed25519 export / Rekor /
        # federation). Config is validated NOW (pre-write), not at first seal:
        # a missing package, missing secret, bad hex, or short key fails loud
        # HERE. Runtime write errors, by contrast, are fail-open (see append) —
        # they must never break the guard's audit path.
        self._bijotel_db: Optional[str] = bijotel_db
        self._bijotel_secret: Optional[bytes] = None
        self._bijotel_append = None
        if bijotel_db is not None:
            try:
                from bijotel import append_event as _bijotel_append_event
            except ImportError as exc:
                raise ChainConfigError(
                    "bijotel_db set but the 'bijotel' package is not installed "
                    "(pip install 'substrate-guard[bijotel]' or 'bijotel>=2.16.0')."
                ) from exc
            hex_secret = bijotel_secret_hex or os.environ.get("BIJOTEL_HMAC_SECRET", "")
            if not hex_secret:
                raise ChainConfigError(
                    "bijotel_db set but no bijotel secret. Pass bijotel_secret_hex= "
                    "or set BIJOTEL_HMAC_SECRET (a HEX string, separate from the "
                    "substrate-guard secret)."
                )
            try:
                bijotel_secret_bytes = bytes.fromhex(hex_secret)
            except ValueError as exc:
                raise ChainConfigError(
                    f"BIJOTEL_HMAC_SECRET must be a valid hex string: {exc}"
                ) from exc
            if len(bijotel_secret_bytes) < 16:
                raise ChainConfigError(
                    "bijotel secret must be >= 16 bytes (32 hex chars)."
                )
            self._bijotel_secret = bijotel_secret_bytes
            self._bijotel_append = _bijotel_append_event

    def _compute_hash(self, index: int, timestamp: float,
                      event_data: str, prev_hash: str) -> str:
        """Compute HMAC-SHA256 for a chain entry."""
        payload = f"{index}:{timestamp}:{event_data}:{prev_hash}"
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def append(self, event) -> ChainEntry:
        """Add an event to the chain. Returns the chain entry with hash.
        
        Accepts either an Event object (from observe layer) or a dict.
        """
        # Normalize to dict (no shared state). The raw fallback carries type="raw"
        # INSIDE event_data so the denormalized event_type is always bound to a hashed
        # field (the verify/verify_export event_type check is unconditional).
        if hasattr(event, 'to_dict'):
            event_data = event.to_dict()
            event_type = event_data.get("type", "unknown")
            agent_id = event_data.get("agent_id", "unknown")
        elif isinstance(event, dict):
            event_data = event
            event_type = event.get("type", "unknown")
            agent_id = event.get("agent_id", "unknown")
        else:
            event_data = {"raw": str(event), "type": "raw"}
            event_type = "raw"
            agent_id = "unknown"

        # Canonical JSON for deterministic hashing
        canonical = json.dumps(event_data, sort_keys=True, default=str)

        # Critical section: index + head_hash + append must be atomic across threads,
        # else concurrent appends produce duplicate indices and break verify().
        with self._lock:
            index = len(self._entries)
            timestamp = time.time()
            entry_hash = self._compute_hash(index, timestamp, canonical, self._head_hash)
            entry = ChainEntry(
                index=index,
                timestamp=timestamp,
                event_type=event_type,
                agent_id=agent_id,
                event_data=event_data,
                prev_hash=self._head_hash,
                hash=entry_hash,
            )
            self._entries.append(entry)
            self._head_hash = entry_hash

        # Dual-write sink (additive, FAIL-OPEN): also seal into the durable
        # bijotel chain if configured. Done OUTSIDE the in-memory lock so a slow
        # bijotel write never blocks other appends, and wrapped so a bijotel
        # failure NEVER breaks the guard's audit path — the in-memory entry above
        # is already committed and is returned regardless.
        if self._bijotel_db is not None:
            try:
                # Pass the JSON-coerced dict (default=str already applied in
                # `canonical`) so bijotel's RFC 8785 canonicalizer never trips on
                # a non-JSON type that substrate-guard tolerated.
                self._bijotel_append(
                    self._bijotel_db,
                    self._bijotel_secret,
                    json.loads(canonical),
                    event_name=f"substrate-guard.{event_type}",
                )
            except Exception as exc:
                import logging
                logging.getLogger("substrate_guard.chain").warning(
                    "bijotel sink seal failed (in-memory chain intact): %s: %s",
                    type(exc).__name__,
                    exc,
                )

        return entry

    def verify(self, expected_count: Optional[int] = None,
               expected_head: Optional[str] = None) -> tuple[bool, Optional[int]]:
        """Verify the entire chain integrity.

        Returns (True, None) if intact, (False, index) if it breaks at ``index``.

        Detects mid-chain modification, reordering, insertion, and any edit by a party
        WITHOUT the secret. It does NOT by itself detect TAIL-TRUNCATION: a valid prefix
        of an HMAC chain is itself a valid chain. To catch a shortened chain, pass
        ``expected_count`` / ``expected_head`` held OUT-OF-BAND (a value the entity that
        could truncate the store cannot also rewrite -- a monitoring counter, a
        separately-anchored head, an external timestamp). Without them, truncation by a
        secret-holder is invisible here -- anchor the head externally (e.g. OpenTimestamps).
        """
        with self._lock:
            entries = list(self._entries)  # consistent snapshot; no lock held during walk
        prev_hash = GENESIS_HASH

        for entry in entries:
            canonical = json.dumps(entry.event_data, sort_keys=True, default=str)
            expected = self._compute_hash(
                entry.index, entry.timestamp, canonical, prev_hash
            )

            if entry.hash != expected:
                return False, entry.index
            if entry.prev_hash != prev_hash:
                return False, entry.index
            # Denormalized event_type/agent_id are not covered by the hash; require
            # them to match the authenticated event_data so a tampered copy is caught.
            # UNCONDITIONAL: event_data always carries a 'type' (default "unknown",
            # "raw" for the raw fallback), so a forged event_type is rejected even when
            # the original had no explicit type.
            if entry.agent_id != entry.event_data.get("agent_id", "unknown"):
                return False, entry.index
            if entry.event_type != entry.event_data.get("type", "unknown"):
                return False, entry.index

            prev_hash = entry.hash

        # Out-of-band anchors: a valid PREFIX verifies, so enforce the expected length /
        # head when the caller can supply one -- this is what closes tail-truncation.
        if expected_count is not None and len(entries) != expected_count:
            return False, len(entries)
        if expected_head is not None and prev_hash != expected_head:
            return False, len(entries)
        return True, None

    @staticmethod
    def _head_commitment(head: str, count: int) -> bytes:
        """The exact bytes both the HMAC ``chain_signature`` and the Ed25519
        ``head_signature`` bind. A single source of truth so the two signatures
        commit to the identical (head, count) tuple -- never edit this format alone."""
        return f"chain:{head}:{count}".encode()

    def export(self, path: str, device_key: Any = None) -> str:
        """Export the chain as signed JSON.

        The export always includes a ``chain_signature`` — HMAC of ``chain:{head}:
        {count}`` (symmetric: a verifier needs the secret). When a ``device_key``
        (attest.DeviceKey) is supplied, ALSO attach an Ed25519 ``head_signature`` over
        the SAME commitment plus the signer's public key + device id, giving PUBLIC
        verifiability + non-repudiation of the head — anyone holding the public key can
        check it without the HMAC secret. Additive: the HMAC path is unchanged.
        """
        # Snapshot entries + head TOGETHER under the lock so a concurrent append cannot
        # produce a torn export (count/head/entry-list captured at different instants).
        with self._lock:
            entries = list(self._entries)
            head = self._head_hash
        commitment = self._head_commitment(head, len(entries))
        chain_data = {
            "version": "1.0",
            "format": "substrate-guard-audit-chain",
            "created_at": time.time(),
            "entries_count": len(entries),
            "genesis_hash": GENESIS_HASH,
            "head_hash": head,
            "chain_signature": hmac.new(
                self._secret, commitment, hashlib.sha256,
            ).hexdigest(),
            "entries": [e.to_dict() for e in entries],
        }

        if device_key is not None:
            # Ed25519 over the identical head commitment. Public-key verifiable, so a
            # third party checks the head without the HMAC secret (non-repudiation is
            # relative to a TRUSTED public key -- see verify_export).
            chain_data["head_signature"] = device_key.sign(commitment).hex()
            chain_data["head_signature_alg"] = "Ed25519"
            chain_data["signer_public_key"] = device_key.public_key_hex
            chain_data["signer_device_id"] = device_key.device_id

        Path(path).write_text(json.dumps(chain_data, indent=2, default=str))
        try:
            os.chmod(path, 0o600)  # the export embeds pipeline I/O -- not world-readable
        except OSError:
            pass
        return path

    @classmethod
    def verify_head_signature(cls, head: str, count: int, signature_hex: str,
                              public_key_hex: str) -> bool:
        """Publicly verify the Ed25519 head signature — NO HMAC secret required.

        Proves that the holder of ``public_key_hex``'s private key signed this exact
        (head, count). This is the non-repudiation / public-verifiability path: a third
        party who trusts the public key can check the head without the chain secret.

        Scope: it attests (head, count) to the device identity. It does NOT by itself
        prove head↔entries — recomputing the head from the entries is HMAC-gated
        (needs the secret, via verify_export). Use both together: the HMAC binds head to
        entries; the Ed25519 binds head to a device, publicly and non-repudiably.
        """
        from .attest.device_key import DeviceKey
        try:
            return DeviceKey.verify_with_public_key(
                public_key_hex, cls._head_commitment(head, count), bytes.fromhex(signature_hex)
            )
        except (ValueError, TypeError):
            return False

    @classmethod
    def verify_export(cls, path: str, secret: str, expected_count: Optional[int] = None,
                      expected_head: Optional[str] = None, *,
                      trusted_public_key: Optional[str] = None,
                      require_signature: bool = False) -> tuple[bool, Optional[str]]:
        """Verify an exported chain file.

        Returns (True, None) if valid, (False, reason) if invalid.

        The chain_signature binds head+count, but BOTH are recomputed from the file, so a
        secret-holder could truncate-and-re-sign undetected. Pass ``expected_count`` /
        ``expected_head`` held out-of-band to detect tail-truncation.

        Ed25519 head signature (optional): if the export carries a ``head_signature`` it
        is checked against the embedded ``signer_public_key`` (or ``trusted_public_key``
        if supplied). NON-REPUDIATION IS RELATIVE TO A TRUSTED KEY: verifying against the
        EMBEDDED key only proves the head was signed by whoever wrote the file
        (self-consistent). Pin the signer's public key out-of-band and pass it as
        ``trusted_public_key`` for real non-repudiation. ``require_signature=True`` fails
        an export that lacks the Ed25519 signature.
        """
        try:
            data = json.loads(Path(path).read_text())
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return False, f"Cannot read file: {e}"

        if data.get("format") != "substrate-guard-audit-chain":
            return False, "Not a substrate-guard audit chain file"

        chain = cls(secret=secret)
        
        entries = data.get("entries", [])
        prev_hash = GENESIS_HASH
        for expected_index, entry_data in enumerate(entries):
            # Rebuild chain entry by entry
            canonical = json.dumps(entry_data["event_data"], sort_keys=True, default=str)
            expected = chain._compute_hash(
                entry_data["index"],
                entry_data["timestamp"],
                canonical,
                entry_data["prev_hash"],
            )
            if entry_data["hash"] != expected:
                return False, f"Hash mismatch at index {entry_data['index']}"
            # Linkage + ordering: each entry must chain to the previous one and
            # indices must be sequential. The chain_signature only binds the head
            # hash and the count, so WITHOUT this per-entry walk an adversary
            # holding only the exported JSON (no secret) could reorder middle
            # entries or delete-and-clone one while keeping head/count intact and
            # the file would still verify. Mirrors the in-memory verify() walk.
            if entry_data["prev_hash"] != prev_hash:
                return False, f"Broken chain link at index {entry_data['index']}"
            if entry_data["index"] != expected_index:
                return False, (
                    f"Non-sequential index at position {expected_index} "
                    f"(got {entry_data['index']})"
                )
            # Denormalized event_type/agent_id are not in the hash; bind them to the
            # authenticated event_data so a tampered copy is rejected.
            ev_data = entry_data["event_data"]
            if entry_data.get("agent_id", "unknown") != ev_data.get("agent_id", "unknown"):
                return False, f"agent_id inconsistent with event_data at index {entry_data['index']}"
            if entry_data.get("event_type") != ev_data.get("type", "unknown"):
                return False, f"event_type inconsistent with event_data at index {entry_data['index']}"

            prev_hash = entry_data["hash"]
            chain._head_hash = entry_data["hash"]
            chain._entries.append(ChainEntry(**entry_data))

        # Verify chain signature
        expected_sig = hmac.new(
            secret.encode(),
            f"chain:{chain._head_hash}:{len(entries)}".encode(),
            hashlib.sha256,
        ).hexdigest()
        
        if data.get("chain_signature") != expected_sig:
            return False, "Chain signature mismatch — file may be tampered"

        # Ed25519 head signature (public-key verifiable, no secret needed).
        head_sig = data.get("head_signature")
        if head_sig is None:
            if require_signature:
                return False, "Missing Ed25519 head_signature (require_signature=True)"
        else:
            pub = trusted_public_key or data.get("signer_public_key")
            if not pub:
                return False, "head_signature present but no signer_public_key to check it"
            if trusted_public_key is not None and data.get("signer_public_key") not in (None, trusted_public_key):
                return False, "signer_public_key does not match the trusted key (wrong signer)"
            commitment = cls._head_commitment(chain._head_hash, len(entries))
            from .attest.device_key import DeviceKey
            try:
                ok = DeviceKey.verify_with_public_key(pub, commitment, bytes.fromhex(head_sig))
            except (ValueError, TypeError) as e:
                return False, f"Malformed Ed25519 head_signature: {e}"
            if not ok:
                return False, "Ed25519 head signature invalid — head may be tampered"

        # Tail-truncation: the signature is recomputed from the file, so enforce an
        # out-of-band expected count/head when the caller can supply one.
        if expected_count is not None and len(entries) != expected_count:
            return False, f"Entry count {len(entries)} != expected {expected_count} (possible truncation)"
        if expected_head is not None and chain._head_hash != expected_head:
            return False, "Head mismatch vs expected (possible truncation)"

        return True, None

    @property
    def length(self) -> int:
        return len(self._entries)

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def entries(self) -> list[ChainEntry]:
        return self._entries.copy()

    def summary(self) -> dict:
        """Chain summary for reporting."""
        agents = set(e.agent_id for e in self._entries)
        types = {}
        for e in self._entries:
            types[e.event_type] = types.get(e.event_type, 0) + 1
        
        return {
            "chain_length": len(self._entries),
            "genesis_hash": GENESIS_HASH,
            "head_hash": self._head_hash,
            "unique_agents": len(agents),
            "event_types": types,
            "integrity": "verified" if self.verify()[0] else "BROKEN",
        }
