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


def test_itype_shift_masks_shamt():
    """RV32I I-type shifts use only imm[4:0]; `srli x1,x10,32` masks shamt to 0, so
    x1 == x10 (unchanged) and 'x1 == 0' must NOT be VERIFIED. The R-type path already
    masked; the I-type path did not -> false VERIFIED."""
    spec = HWSpec(postconditions={"x1": ("==", 0)}, description="x1==0")
    r = HardwareVerifier().verify("srli x1, x10, 32\n", spec)
    assert r.status != HWVerifyStatus.VERIFIED, f"unmasked srli shamt wrongly VERIFIED ({r.status})"


def test_verify_equivalence_abstains_on_branch():
    """verify_equivalence must apply the SAME abstain guard as verify(): if either
    sequence uses a control-flow branch the simulator cannot model, it must not
    return VERIFIED. asm_b branches over its body, so it is NOT equivalent to the
    straight-line asm_a under real semantics. Residual found by the adversarial
    verification of commit 10ff211."""
    asm_a = "addi a0, zero, 99\n"
    asm_b = "beq zero, zero, end\naddi a0, zero, 99\nend:\n"
    r = HardwareVerifier().verify_equivalence(asm_a, asm_b, input_regs=[], output_reg="a0")
    assert r.status != HWVerifyStatus.VERIFIED, f"branch-containing equivalence wrongly VERIFIED ({r.status})"
