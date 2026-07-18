"""Layer 4: threshold non-membership over committed embeddings (prototype).

Paper-era brand: "ZK-SNM" — kept only as the certificate wire identifier and a
backward-compat class alias; the code is threshold-plus-Merkle, not ZK.
"""

from .fingerprinter import DeterministicFingerprinter, SemanticFingerprinter
from .commitment import EmbeddingCommitment
from .verifier import NonMembershipVerifier
from .protocol import ThresholdNonMembershipProtocol, ZKSNMProtocol
from .comply_guard import ComplyGuard

__all__ = [
    "DeterministicFingerprinter",
    "SemanticFingerprinter",
    "EmbeddingCommitment",
    "NonMembershipVerifier",
    "ThresholdNonMembershipProtocol",
    "ZKSNMProtocol",  # backward-compat alias (paper-era brand)
    "ComplyGuard",
]
