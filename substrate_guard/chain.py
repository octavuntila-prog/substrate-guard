"""Tamper-Evident Chain — HMAC-SHA256 audit chain on every event.

Each event is hashed with the previous hash, creating an unbreakable chain.
If any event is modified, deleted, or inserted, the chain breaks.

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
import time
import os
from dataclasses import dataclass, field, asdict
from typing import Optional
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


class AuditChain:
    """HMAC-SHA256 tamper-evident audit chain.
    
    Every event gets a hash that depends on:
    - The event data itself
    - The previous event's hash
    - A secret key (HMAC)
    - The event's position in the chain (index)
    
    Modifying, deleting, or inserting any event breaks the chain.
    
    Args:
        secret: HMAC secret key. If None, reads from GUARD_HMAC_SECRET env
                or generates a random one (logged as warning).
    """

    def __init__(self, secret: Optional[str] = None):
        self._secret = (secret or os.environ.get("GUARD_HMAC_SECRET", "")).encode()
        if not self._secret:
            self._secret = os.urandom(32)
            import logging
            logging.getLogger("substrate_guard.chain").warning(
                "No HMAC secret provided — generated random key. "
                "Set GUARD_HMAC_SECRET env or pass secret= for persistence."
            )
        
        self._entries: list[ChainEntry] = []
        self._head_hash: str = GENESIS_HASH

    def _compute_hash(self, index: int, timestamp: float,
                      event_data: str, prev_hash: str) -> str:
        """Compute HMAC-SHA256 for a chain entry."""
        payload = f"{index}:{timestamp}:{event_data}:{prev_hash}"
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def append(self, event) -> ChainEntry:
        """Add an event to the chain. Returns the chain entry with hash.
        
        Accepts either an Event object (from observe layer) or a dict.
        """
        index = len(self._entries)
        timestamp = time.time()

        # Normalize to dict
        if hasattr(event, 'to_dict'):
            event_data = event.to_dict()
            event_type = event_data.get("type", "unknown")
            agent_id = event_data.get("agent_id", "unknown")
        elif isinstance(event, dict):
            event_data = event
            event_type = event.get("type", "unknown")
            agent_id = event.get("agent_id", "unknown")
        else:
            event_data = {"raw": str(event)}
            event_type = "raw"
            agent_id = "unknown"

        # Canonical JSON for deterministic hashing
        canonical = json.dumps(event_data, sort_keys=True, default=str)
        
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

        return entry

    def verify(self) -> tuple[bool, Optional[int]]:
        """Verify the entire chain integrity.
        
        Returns:
            (True, None) if chain is intact
            (False, index) if chain breaks at given index
        """
        prev_hash = GENESIS_HASH

        for entry in self._entries:
            canonical = json.dumps(entry.event_data, sort_keys=True, default=str)
            expected = self._compute_hash(
                entry.index, entry.timestamp, canonical, prev_hash
            )
            
            if entry.hash != expected:
                return False, entry.index
            if entry.prev_hash != prev_hash:
                return False, entry.index
            
            prev_hash = entry.hash

        return True, None

    def export(self, path: str) -> str:
        """Export the chain as signed JSON.
        
        The export includes a chain_signature — HMAC of the final hash,
        so the entire export can be verified as a unit.
        """
        chain_data = {
            "version": "1.0",
            "format": "substrate-guard-audit-chain",
            "created_at": time.time(),
            "entries_count": len(self._entries),
            "genesis_hash": GENESIS_HASH,
            "head_hash": self._head_hash,
            "chain_signature": hmac.new(
                self._secret,
                f"chain:{self._head_hash}:{len(self._entries)}".encode(),
                hashlib.sha256,
            ).hexdigest(),
            "entries": [e.to_dict() for e in self._entries],
        }

        Path(path).write_text(json.dumps(chain_data, indent=2, default=str))
        return path

    @classmethod
    def verify_export(cls, path: str, secret: str) -> tuple[bool, Optional[str]]:
        """Verify an exported chain file.
        
        Returns:
            (True, None) if valid
            (False, reason) if invalid
        """
        try:
            data = json.loads(Path(path).read_text())
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return False, f"Cannot read file: {e}"

        if data.get("format") != "substrate-guard-audit-chain":
            return False, "Not a substrate-guard audit chain file"

        chain = cls(secret=secret)
        
        entries = data.get("entries", [])
        for entry_data in entries:
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
