"""CLI hooks for Layer 4 (registered from substrate_guard.cli)."""

from __future__ import annotations

import argparse


def register_comply_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "comply",
        help="Layer 4: semantic non-membership over a committed corpus (ZK-SNM prototype)",
    )
    sp = p.add_subparsers(dest="comply_action", required=True)
    sp.add_parser(
        "demo",
        help="Run deterministic pipeline (SHA256 embeddings + Merkle + threshold check)",
    )


def cmd_comply(args: argparse.Namespace) -> int:
    if args.comply_action == "demo":
        return run_demo()
    return 1


def run_demo() -> int:
    from .fingerprinter import DeterministicFingerprinter
    from .protocol import ZKSNMProtocol

    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(threshold=0.85, use_z3=True, fingerprinter=fp)
    corpus = ["protected-alpha-unique-string", "other-beta-secret"]
    c = p.commit_training_data(corpus)
    print("ZK-SNM demo (deterministic encoder)")
    print(f"  commitment_root: {c['commitment_root'][:24]}...")
    print(f"  encoder:         {c['encoder']}")

    q_same = "protected-alpha-unique-string"
    q_diff = "totally-unrelated-query-xyz-12345-not-in-corpus"
    r1 = p.verify_non_membership(q_same)
    r2 = p.verify_non_membership(q_diff)
    print(f"  query (exact training line): verified={r1['result']['verified']} max_sim={r1['result']['max_similarity']}")
    print(f"  query (unrelated):          verified={r2['result']['verified']} max_sim={r2['result']['max_similarity']}")
    print(f"  certificate_hash (2nd query): {r2['certificate_hash'][:24]}...")
    return 0
