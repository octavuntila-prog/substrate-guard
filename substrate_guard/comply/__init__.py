"""Layer 4: ZK-SNM Copyright Compliance — semantic non-membership verification.

Implements the protocol from "Attribution Without Disclosure"
(DOI: 10.5281/zenodo.19185843):

Phase 1: Fingerprint (sentence-transformers embeddings)
Phase 2: Commit (Merkle tree over training data)
Phase 3: Verify (similarity check + Z3 confirmation)
Phase 4: Certify (compliance certificate)

Honest about limitations: verification is real, ZK privacy layer
requires Halo2/circom circuits (future work).
"""

from .fingerprinter import SemanticFingerprinter
from .commitment import TrainingDataCommitment, MerkleProof
from .verifier import NonMembershipVerifier, VerificationResult
from .protocol import ZKSNMProtocol, ComplianceCertificate
from .comply_guard import ComplyGuard, ComplianceCheckResult

__all__ = [
    "SemanticFingerprinter",
    "TrainingDataCommitment",
    "MerkleProof",
    "NonMembershipVerifier",
    "VerificationResult",
    "ZKSNMProtocol",
    "ComplianceCertificate",
    "ComplyGuard",
    "ComplianceCheckResult",
]
