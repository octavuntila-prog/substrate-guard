"""Layer 4: semantic non-membership (ZK-SNM prototype) over committed embeddings."""

from .fingerprinter import DeterministicFingerprinter, SemanticFingerprinter
from .commitment import EmbeddingCommitment
from .verifier import NonMembershipVerifier
from .protocol import ZKSNMProtocol
from .comply_guard import ComplyGuard

__all__ = [
    "DeterministicFingerprinter",
    "SemanticFingerprinter",
    "EmbeddingCommitment",
    "NonMembershipVerifier",
    "ZKSNMProtocol",
    "ComplyGuard",
]
