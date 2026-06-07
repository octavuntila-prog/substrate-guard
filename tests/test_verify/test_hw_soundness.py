"""Soundness regression for the RISC-V HardwareVerifier.

This straight-line simulator does not model control-flow branches/jumps, unknown
opcodes, or loaded memory values — it must ABSTAIN (never VERIFIED) when it
encounters them. See P0 in docs/AUDIT_COMPLEX_2026-06-07.md.
"""
from __future__ import annotations

from substrate_guard.hw_verifier import HardwareVerifier, HWSpec, HWVerifyStatus


def test_branch_does_not_verify():
    """A control-flow branch is not modeled; the verifier must not VERIFY."""
    asm = (
        "addi a0, zero, 5\n"
        "beq a0, zero, skip\n"
        "addi a0, zero, 99\n"
    )
    spec = HWSpec(postconditions={"a0": ("==", 5)}, description="a0 == 5")
    r = HardwareVerifier().verify(asm, spec)
    assert r.status != HWVerifyStatus.VERIFIED, f"branch wrongly VERIFIED ({r.status})"


def test_unknown_opcode_does_not_verify():
    """An unknown opcode that could mutate state must force an abstain."""
    asm = "frobnicate a0, a1, a2\naddi a0, zero, 0\n"
    spec = HWSpec(postconditions={"a0": ("==", 0)}, description="a0 == 0")
    r = HardwareVerifier().verify(asm, spec)
    assert r.status != HWVerifyStatus.VERIFIED, f"unknown opcode wrongly VERIFIED ({r.status})"


def test_clean_straightline_still_verifies():
    """A fully-modeled straight-line program still VERIFIES (no over-abstain)."""
    asm = "addi a0, zero, 7\n"
    spec = HWSpec(postconditions={"a0": ("==", 7)}, description="a0 == 7")
    r = HardwareVerifier().verify(asm, spec)
    assert r.status == HWVerifyStatus.VERIFIED, f"clean program failed to VERIFY ({r.status})"
