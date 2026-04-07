"""CLI hooks for Layer 5 (registered from substrate_guard.cli)."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path


def register_attest_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "attest",
        help="Layer 5: device fingerprint + Ed25519 signing (software identity)",
    )
    sp = p.add_subparsers(dest="attest_action", required=True)
    sp.add_parser(
        "demo",
        help="Generate temp keys, sign a sample event, verify signature",
    )


def cmd_attest(args: argparse.Namespace) -> int:
    if args.attest_action == "demo":
        return run_attest_demo()
    return 1


def run_attest_demo() -> int:
    from .attested_guard import AttestedGuard

    base = Path(tempfile.mkdtemp(prefix="substrate-guard-attest-"))
    key_dir = base / "keys"
    ca_dir = base / "ca"
    ag = AttestedGuard(
        guard=None,
        config={"key_dir": str(key_dir), "ca_dir": str(ca_dir)},
    )
    event = {"type": "demo", "agent_id": "agent-1", "note": "attest demo"}
    signed = ag.process_event(event)
    ok = ag.signer.verify_signed_event(signed)
    print("Layer 5 attestation demo (software key, not TPM)")
    print(f"  device_id:     {ag.device_key.device_id}")
    print(f"  fingerprint: {ag.fingerprint.fingerprint()[:24]}...")
    print(f"  cert_serial:   {ag.ca.current['serial']}")
    print(f"  verify_ok:     {ok}")
    print(f"  signature:     {signed['device_attestation']['signature'][:32]}...")
    return 0 if ok else 1
