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


def test_unknown_spec_register_is_parse_error_not_crash():
    """M-e: a spec referencing a non-existent register (x99) made _reg_idx raise, which
    escaped verify() and crashed the public API. It must now fail closed as PARSE_ERROR."""
    asm = "addi a0, zero, 7\n"
    spec = HWSpec(postconditions={"x99": ("==", 7)}, description="bad register")
    r = HardwareVerifier().verify(asm, spec)
    assert r.status == HWVerifyStatus.PARSE_ERROR, f"bad register not PARSE_ERROR ({r.status})"


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


def test_load_offset_sign_extends_out_of_bounds():
    """RV32I load offsets are 12-bit SIGNED: 0x800 sign-extends to -2048, NOT +2048.
    `lw x1, 0x800(x10)` with x10==0 computes addr 0xFFFFF800 on silicon, which is OUT
    of bounds [0, 0xFFFF]. Modeling 0x800 as +2048 (in-bounds) is a memory-safety
    bypass — must NOT be VERIFIED."""
    spec = HWSpec(
        preconditions={"x10": ("==", 0)},
        memory_lower=0,
        memory_upper=0xFFFF,
        description="lw 0x800(x10) in bounds",
    )
    r = HardwareVerifier().verify("lw x1, 0x800(x10)\n", spec)
    assert r.status != HWVerifyStatus.VERIFIED, f"sign-extended load offset wrongly VERIFIED ({r.status})"


def test_store_offset_sign_extends_out_of_bounds():
    """Same 12-bit signed offset bug as the load path, for `sw`: 0x800 -> -2048, so
    addr 0xFFFFF800 is OUT of bounds and the store must NOT be VERIFIED."""
    spec = HWSpec(
        preconditions={"x10": ("==", 0)},
        memory_lower=0,
        memory_upper=0xFFFF,
        description="sw 0x800(x10) in bounds",
    )
    r = HardwareVerifier().verify("sw x1, 0x800(x10)\n", spec)
    assert r.status != HWVerifyStatus.VERIFIED, f"sign-extended store offset wrongly VERIFIED ({r.status})"


def test_itype_immediate_sign_extends():
    """RV32I I-type immediates are 12-bit SIGNED: `addi x1, x10, 0xFFF` with x10==0
    yields x1 == 0xFFFFFFFF (-1), NOT 4095. The verifier must NOT prove x1 == 4095."""
    spec = HWSpec(
        preconditions={"x10": ("==", 0)},
        postconditions={"x1": ("==", 4095)},
        description="addi 0xFFF == 4095",
    )
    r = HardwareVerifier().verify("addi x1, x10, 0xFFF\n", spec)
    assert r.status != HWVerifyStatus.VERIFIED, f"non-sign-extended addi wrongly VERIFIED x1==4095 ({r.status})"


def test_itype_immediate_sign_extends_correct_value_verifies():
    """The flip side of sign-extension: `addi x1, x10, 0xFFF` with x10==0 really does
    equal 0xFFFFFFFF, so asserting that exact value MUST still VERIFY (no over-abstain
    on a perfectly representable 12-bit immediate)."""
    spec = HWSpec(
        preconditions={"x10": ("==", 0)},
        postconditions={"x1": ("==", 0xFFFFFFFF)},
        description="addi 0xFFF == -1",
    )
    r = HardwareVerifier().verify("addi x1, x10, 0xFFF\n", spec)
    assert r.status == HWVerifyStatus.VERIFIED, f"sign-extended addi failed to VERIFY x1==-1 ({r.status})"


def test_in_bounds_load_still_verifies():
    """A small in-range offset must still VERIFY memory-safe — the fix must not
    over-abstain on representable offsets. `lw x1, 4(x10)` with x10==0 -> addr 4,
    inside [0, 0xFFFF]."""
    spec = HWSpec(
        preconditions={"x10": ("==", 0)},
        memory_lower=0,
        memory_upper=0xFFFF,
        description="lw 4(x10) in bounds",
    )
    r = HardwareVerifier().verify("lw x1, 4(x10)\n", spec)
    assert r.status == HWVerifyStatus.VERIFIED, f"in-bounds load failed to VERIFY ({r.status})"
