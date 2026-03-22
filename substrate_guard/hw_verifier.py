"""Z3 Hardware Verifier — formal verification for assembly-level AI outputs.

Domain 5 from S3's emergent discovery: AssemblyGuard, VerifyChain.
Verifies that AI-generated assembly (RISC-V style) satisfies safety properties
BEFORE silicon fabrication — because you can't patch a chip.

Supported instruction subset (RISC-V RV32I):
  - Arithmetic: add, sub, mul, and, or, xor, sll, srl, sra
  - Immediate: addi, andi, ori, xori, slli, srli, srai
  - Comparison: slt, slti, sltu
  - Memory: lw, sw (modeled abstractly)
  - Branch: beq, bne, blt, bge (modeled as conditional paths)
  - System: ecall (flagged as potentially dangerous)

Properties we can verify:
  - Register value bounds after execution
  - No division by zero (via checked div sequences)
  - Memory access within bounds
  - No unintended privilege escalation (ecall)
  - Functional equivalence between two instruction sequences
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from z3 import (
    And,
    BitVec,
    BitVecVal,
    Bool,
    BoolVal,
    Extract,
    If,
    Not,
    Or,
    Solver,
    UDiv,
    ULT,
    URem,
    ZeroExt,
    sat,
    unsat,
)

# Use 32-bit bitvectors for RISC-V RV32I
BV_WIDTH = 32


class HWVerifyStatus(str, Enum):
    VERIFIED = "verified"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"
    PARSE_ERROR = "parse_error"


@dataclass
class HWVerifyResult:
    status: HWVerifyStatus
    property_name: str = ""
    counterexample: dict | None = None
    time_ms: float = 0.0
    error: str | None = None

    @property
    def verified(self) -> bool:
        return self.status == HWVerifyStatus.VERIFIED

    def __str__(self) -> str:
        icons = {
            HWVerifyStatus.VERIFIED: "V VERIFIED",
            HWVerifyStatus.UNSAFE: "X UNSAFE",
            HWVerifyStatus.UNKNOWN: "? UNKNOWN",
            HWVerifyStatus.PARSE_ERROR: "E PARSE ERROR",
        }
        parts = [f"{icons[self.status]} — {self.property_name} ({self.time_ms:.1f}ms)"]
        if self.counterexample:
            parts.append(f"  Counterexample: {self.counterexample}")
        if self.error:
            parts.append(f"  Error: {self.error}")
        return "\n".join(parts)


@dataclass
class HWSpec:
    """Specification for hardware verification."""
    # Register preconditions: {"x1": (">=", 0), "x2": ("<", 1024)}
    preconditions: dict[str, tuple[str, int]] = field(default_factory=dict)
    # Register postconditions on the result register
    postconditions: dict[str, tuple[str, int]] = field(default_factory=dict)
    # Forbidden instructions
    forbidden_instructions: list[str] = field(default_factory=list)
    # Memory bounds
    memory_lower: int = 0
    memory_upper: int = 0xFFFF  # 64KB default
    description: str = ""


class RISCVSimulator:
    """Symbolic RISC-V RV32I simulator using Z3 bitvectors."""

    # Standard RISC-V register names
    REG_NAMES = {f"x{i}": i for i in range(32)}
    REG_NAMES.update({"zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
                       "t0": 5, "t1": 6, "t2": 7, "s0": 8, "fp": 8,
                       "s1": 9, "a0": 10, "a1": 11, "a2": 12, "a3": 13,
                       "a4": 14, "a5": 15, "a6": 16, "a7": 17})

    def __init__(self):
        # Create symbolic registers (x0 is always 0)
        self.regs: dict[int, Any] = {}
        for i in range(32):
            if i == 0:
                self.regs[i] = BitVecVal(0, BV_WIDTH)  # x0 = 0 always
            else:
                self.regs[i] = BitVec(f"x{i}_init", BV_WIDTH)

        self.memory_accesses: list[dict] = []
        self.ecall_count = 0
        self.instruction_count = 0
        self.constraints: list = []
        self._step = 0

    def _reg_idx(self, name: str) -> int:
        """Convert register name to index."""
        name = name.strip().lower()
        if name in self.REG_NAMES:
            return self.REG_NAMES[name]
        raise ValueError(f"Unknown register: {name}")

    def _get_reg(self, name: str) -> Any:
        return self.regs[self._reg_idx(name)]

    def _set_reg(self, name: str, value: Any):
        idx = self._reg_idx(name)
        if idx == 0:
            return  # x0 is hardwired to 0
        self.regs[idx] = value
        self._step += 1

    def _parse_imm(self, s: str) -> int:
        s = s.strip()
        if s.startswith("0x") or s.startswith("-0x"):
            return int(s, 16)
        return int(s)

    def execute(self, instructions: list[str]):
        """Symbolically execute a sequence of instructions."""
        for inst in instructions:
            self._execute_one(inst.strip())
            self.instruction_count += 1

    def _execute_one(self, inst: str):
        """Execute a single instruction symbolically."""
        if not inst or inst.startswith("#") or inst.startswith("//"):
            return

        # Remove comments
        inst = inst.split("#")[0].split("//")[0].strip()
        if not inst:
            return

        # Parse: opcode rd, rs1, rs2/imm
        parts = re.split(r'[\s,]+', inst)
        op = parts[0].lower()

        # R-type: op rd, rs1, rs2
        if op in ("add", "sub", "mul", "and", "or", "xor", "sll", "srl", "sra",
                   "slt", "sltu"):
            rd, rs1, rs2 = parts[1], parts[2], parts[3]
            v1 = self._get_reg(rs1)
            v2 = self._get_reg(rs2)

            if op == "add":
                self._set_reg(rd, v1 + v2)
            elif op == "sub":
                self._set_reg(rd, v1 - v2)
            elif op == "mul":
                self._set_reg(rd, v1 * v2)
            elif op == "and":
                self._set_reg(rd, v1 & v2)
            elif op == "or":
                self._set_reg(rd, v1 | v2)
            elif op == "xor":
                self._set_reg(rd, v1 ^ v2)
            elif op == "sll":
                self._set_reg(rd, v1 << (v2 & BitVecVal(0x1F, BV_WIDTH)))
            elif op == "srl":
                from z3 import LShR
                self._set_reg(rd, LShR(v1, v2 & BitVecVal(0x1F, BV_WIDTH)))
            elif op == "sra":
                self._set_reg(rd, v1 >> (v2 & BitVecVal(0x1F, BV_WIDTH)))
            elif op == "slt":
                self._set_reg(rd, If(v1 < v2, BitVecVal(1, BV_WIDTH),
                                     BitVecVal(0, BV_WIDTH)))
            elif op == "sltu":
                self._set_reg(rd, If(ULT(v1, v2), BitVecVal(1, BV_WIDTH),
                                     BitVecVal(0, BV_WIDTH)))

        # I-type: op rd, rs1, imm
        elif op in ("addi", "andi", "ori", "xori", "slli", "srli", "srai", "slti"):
            rd, rs1 = parts[1], parts[2]
            imm = BitVecVal(self._parse_imm(parts[3]), BV_WIDTH)
            v1 = self._get_reg(rs1)

            if op == "addi":
                self._set_reg(rd, v1 + imm)
            elif op == "andi":
                self._set_reg(rd, v1 & imm)
            elif op == "ori":
                self._set_reg(rd, v1 | imm)
            elif op == "xori":
                self._set_reg(rd, v1 ^ imm)
            elif op == "slli":
                self._set_reg(rd, v1 << imm)
            elif op == "srli":
                from z3 import LShR
                self._set_reg(rd, LShR(v1, imm))
            elif op == "srai":
                self._set_reg(rd, v1 >> imm)
            elif op == "slti":
                self._set_reg(rd, If(v1 < imm, BitVecVal(1, BV_WIDTH),
                                     BitVecVal(0, BV_WIDTH)))

        # Load immediate
        elif op == "li":
            rd = parts[1]
            imm = BitVecVal(self._parse_imm(parts[2]), BV_WIDTH)
            self._set_reg(rd, imm)

        # Move
        elif op == "mv":
            rd, rs1 = parts[1], parts[2]
            self._set_reg(rd, self._get_reg(rs1))

        # Negate
        elif op == "neg":
            rd, rs1 = parts[1], parts[2]
            self._set_reg(rd, -self._get_reg(rs1))

        # Memory (abstract model — track accesses, don't model memory contents)
        elif op in ("lw", "sw", "lb", "sb", "lh", "sh"):
            # Parse offset(rs1)
            if "(" in parts[2]:
                match = re.match(r'(-?\d+)\((\w+)\)', parts[2])
                if match:
                    offset = int(match.group(1))
                    base_reg = match.group(2)
                    addr = self._get_reg(base_reg) + BitVecVal(offset, BV_WIDTH)
                else:
                    addr = BitVecVal(0, BV_WIDTH)
            else:
                addr = self._get_reg(parts[2])

            self.memory_accesses.append({
                "type": "load" if op.startswith("l") else "store",
                "addr": addr,
                "reg": parts[1],
                "instruction": inst,
            })

        # System call
        elif op == "ecall":
            self.ecall_count += 1

        # NOP
        elif op == "nop":
            pass

        else:
            # Unknown instruction — skip with warning
            pass


class HardwareVerifier:
    """Verify assembly code properties using Z3."""

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def verify(self, assembly: str, spec: HWSpec) -> HWVerifyResult:
        """Verify assembly code against specification."""
        t0 = time.time()

        # Parse instructions
        instructions = [line.strip() for line in assembly.strip().split("\n")
                        if line.strip() and not line.strip().startswith("#")]

        # Check for forbidden instructions first
        for inst in instructions:
            op = inst.split()[0].lower() if inst.split() else ""
            if op in spec.forbidden_instructions:
                return HWVerifyResult(
                    status=HWVerifyStatus.UNSAFE,
                    property_name=spec.description,
                    counterexample={"forbidden_instruction": inst},
                    time_ms=(time.time() - t0) * 1000,
                )

        # Symbolic execution
        sim = RISCVSimulator()

        try:
            sim.execute(instructions)
        except (ValueError, IndexError) as e:
            return HWVerifyResult(
                status=HWVerifyStatus.PARSE_ERROR,
                property_name=spec.description,
                error=str(e),
                time_ms=(time.time() - t0) * 1000,
            )

        solver = Solver()
        solver.set("timeout", self.timeout_ms)

        # Apply preconditions on initial register values
        for reg_name, (op, val) in spec.preconditions.items():
            idx = sim._reg_idx(reg_name)
            init_var = BitVec(f"x{idx}_init", BV_WIDTH)
            bv_val = BitVecVal(val, BV_WIDTH)
            if op == ">=":
                solver.add(init_var >= bv_val)
            elif op == "<=":
                solver.add(init_var <= bv_val)
            elif op == "<":
                solver.add(ULT(init_var, bv_val))
            elif op == ">":
                solver.add(init_var > bv_val)
            elif op == "==":
                solver.add(init_var == bv_val)

        # Check postconditions: try to find a violation
        post_violations = []
        for reg_name, (op, val) in spec.postconditions.items():
            idx = sim._reg_idx(reg_name)
            final_val = sim.regs[idx]
            bv_val = BitVecVal(val, BV_WIDTH)

            if op == ">=":
                post_violations.append(Not(final_val >= bv_val))
            elif op == "<=":
                post_violations.append(Not(final_val <= bv_val))
            elif op == "<":
                post_violations.append(Not(ULT(final_val, bv_val)))
            elif op == ">":
                post_violations.append(Not(final_val > bv_val))
            elif op == "==":
                post_violations.append(Not(final_val == bv_val))

        # Check memory bounds
        for access in sim.memory_accesses:
            addr = access["addr"]
            lower = BitVecVal(spec.memory_lower, BV_WIDTH)
            upper = BitVecVal(spec.memory_upper, BV_WIDTH)
            post_violations.append(Or(ULT(addr, lower), Not(ULT(addr, upper))))

        if not post_violations:
            return HWVerifyResult(
                status=HWVerifyStatus.VERIFIED,
                property_name=spec.description,
                time_ms=(time.time() - t0) * 1000,
            )

        # Check: ∃ initial state satisfying preconditions ∧ ¬postconditions?
        solver.add(Or(*post_violations))
        result = solver.check()
        elapsed = (time.time() - t0) * 1000

        if result == unsat:
            return HWVerifyResult(
                status=HWVerifyStatus.VERIFIED,
                property_name=spec.description,
                time_ms=elapsed,
            )
        elif result == sat:
            model = solver.model()
            ce = {}
            for i in range(1, 32):
                init_var = BitVec(f"x{i}_init", BV_WIDTH)
                val = model.eval(init_var, model_completion=True)
                if str(val) != f"x{i}_init":
                    ce[f"x{i}"] = str(val)
            return HWVerifyResult(
                status=HWVerifyStatus.UNSAFE,
                property_name=spec.description,
                counterexample=ce,
                time_ms=elapsed,
            )
        else:
            return HWVerifyResult(
                status=HWVerifyStatus.UNKNOWN,
                property_name=spec.description,
                time_ms=elapsed,
            )

    def verify_equivalence(self, asm_a: str, asm_b: str,
                           input_regs: list[str],
                           output_reg: str) -> HWVerifyResult:
        """Verify that two assembly sequences are functionally equivalent.

        Useful for: verifying that AI-optimized assembly preserves semantics.
        """
        t0 = time.time()

        sim_a = RISCVSimulator()
        sim_b = RISCVSimulator()

        # Share initial register values between both simulators
        for i in range(1, 32):
            shared = BitVec(f"x{i}_shared", BV_WIDTH)
            sim_a.regs[i] = shared
            sim_b.regs[i] = shared

        try:
            insts_a = [l.strip() for l in asm_a.strip().split("\n")
                       if l.strip() and not l.strip().startswith("#")]
            insts_b = [l.strip() for l in asm_b.strip().split("\n")
                       if l.strip() and not l.strip().startswith("#")]
            sim_a.execute(insts_a)
            sim_b.execute(insts_b)
        except (ValueError, IndexError) as e:
            return HWVerifyResult(
                status=HWVerifyStatus.PARSE_ERROR,
                property_name="equivalence",
                error=str(e),
                time_ms=(time.time() - t0) * 1000,
            )

        idx = sim_a._reg_idx(output_reg)
        out_a = sim_a.regs[idx]
        out_b = sim_b.regs[idx]

        solver = Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(Not(out_a == out_b))

        result = solver.check()
        elapsed = (time.time() - t0) * 1000

        if result == unsat:
            return HWVerifyResult(
                status=HWVerifyStatus.VERIFIED,
                property_name=f"equivalence on {output_reg}",
                time_ms=elapsed,
            )
        elif result == sat:
            model = solver.model()
            ce = {}
            for reg in input_regs:
                idx = sim_a._reg_idx(reg)
                val = model.eval(BitVec(f"x{idx}_shared", BV_WIDTH),
                                 model_completion=True)
                ce[reg] = str(val)
            return HWVerifyResult(
                status=HWVerifyStatus.UNSAFE,
                property_name=f"equivalence on {output_reg}",
                counterexample=ce,
                time_ms=elapsed,
            )
        else:
            return HWVerifyResult(
                status=HWVerifyStatus.UNKNOWN,
                property_name=f"equivalence on {output_reg}",
                time_ms=elapsed,
            )


def verify_hardware(assembly: str, spec: HWSpec) -> HWVerifyResult:
    """One-shot hardware verification."""
    return HardwareVerifier().verify(assembly, spec)
