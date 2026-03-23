"""Layer 2: OPA/Rego Policy — Does the AI agent have permission to do this?"""
from .engine import PolicyEngine, PolicyDecision

__all__ = ["PolicyEngine", "PolicyDecision"]
