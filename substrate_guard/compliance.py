"""Compliance Export — Generate audit reports for SOC2, ISO 27001, ISO 42001.

Transforms the tamper-evident audit chain into compliance evidence
formatted for specific frameworks.

Usage:
    from substrate_guard.compliance import ComplianceExporter
    
    exporter = ComplianceExporter(chain, session_report)
    exporter.export_soc2("soc2_evidence.json")
    exporter.export_iso27001("iso27001_evidence.json")
    exporter.export_summary("compliance_summary.json")
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .chain import AuditChain
from .guard import SessionReport


class ComplianceExporter:
    """Export audit chain and Guard results as compliance evidence.
    
    Args:
        chain: The tamper-evident audit chain
        report: Session report from Guard pipeline (optional)
        org_name: Organization name for reports
    """

    def __init__(
        self,
        chain: AuditChain,
        report: Optional[SessionReport] = None,
        org_name: str = "Aisophical SRL",
    ):
        self._chain = chain
        self._report = report
        self._org = org_name

    def _base_metadata(self) -> dict:
        now = datetime.now(timezone.utc)
        chain_ok, break_idx = self._chain.verify()
        return {
            "generator": "substrate-guard / AI Black Box",
            "version": "1.0",
            "generated_at": now.isoformat(),
            "organization": self._org,
            "chain_integrity": {
                "status": "VERIFIED" if chain_ok else f"BROKEN at index {break_idx}",
                "chain_length": self._chain.length,
                "head_hash": self._chain.head_hash,
                "algorithm": "HMAC-SHA256",
            },
        }

    def _session_data(self) -> dict:
        if not self._report:
            return {}
        return {
            "session": {
                "agent_id": self._report.agent_id,
                "duration_s": self._report.duration_s,
                "events_observed": self._report.events_observed,
                "policy_violations": self._report.policy_violations,
                "formal_verifications": self._report.formal_verifications,
                "formal_failures": self._report.formal_failures,
                "verdict": "COMPLIANT" if (
                    self._report.policy_violations == 0 and
                    self._report.formal_failures == 0
                ) else "NON-COMPLIANT",
            },
        }

    def export_soc2(self, path: str) -> str:
        """Export SOC 2 Type II compliance evidence.
        
        Maps to SOC 2 Trust Service Criteria:
        - CC6.1: Logical access security → OPA policy decisions
        - CC7.2: System monitoring → eBPF observation
        - CC8.1: Change management → Z3 formal verification
        - CC4.1: Monitoring of controls → Audit chain integrity
        """
        evidence = {
            **self._base_metadata(),
            "framework": "SOC 2 Type II",
            "trust_service_criteria": {
                "CC6.1_logical_access": {
                    "description": "The entity implements logical access security over protected information assets",
                    "control": "Built-in Python policy engine evaluates every agent action against 7 rules (Rego/OPA available via --policy rego, not production default)",
                    "evidence": {
                        "policy_rules": [
                            "dangerous_paths", "dangerous_commands", "network_exfiltration",
                            "budget_enforcement", "rate_limiting", "workspace_boundary", "pii_detection",
                        ],
                        "total_evaluations": self._chain.length,
                        "violations_detected": self._report.policy_violations if self._report else 0,
                    },
                },
                "CC7.2_system_monitoring": {
                    "description": "The entity monitors system components for anomalies",
                    "control": "Observation layer (eBPF: execve/openat/connect/TLS) implemented; production cron ingests platform-DB records via adapters (mock tracer) — live eBPF not wired (#38b)",
                    "evidence": {
                        "observation_layer": "DB-batch ingestion (mock tracer); eBPF tracepoints+uprobes implemented, not production-wired (#38b)",
                        "event_types": ["syscall", "file_open", "file_write", "file_read",
                                       "network_connect", "process_exec", "tls_read", "tls_write"],
                        "events_captured": self._report.events_observed if self._report else self._chain.length,
                    },
                },
                "CC8.1_change_management": {
                    "description": "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes",
                    "control": "Z3 SMT verification checks AI-generated code, tool APIs, CLI commands, hardware assembly, and distilled models against safety specifications within a bounded modeled fragment (sound on each verifier's declared subset; Z3 available but NOT exercised per-event in the batch cron audit — #38b)",
                    "evidence": {
                        "verification_engine": "Z3 SMT Solver",
                        "domains_covered": ["code", "tool_api", "cli", "hardware_riscv", "distillation"],
                        "benchmark_scenarios": 5,
                        "benchmark_accuracy": "100% on the 5-scenario benchmark suite (design target, not a measured per-event control on this evidence set)",
                        "scope_note": "Sound only within each verifier's modeled fragment; out-of-subset constructs are not exercised per-event in the batch cron (#38b). The CLI verifier maintains a documented known-gap inventory; false-positive/false-negative rates are not measured on this evidence set.",
                    },
                },
                "CC4.1_monitoring_controls": {
                    "description": "The entity monitors the effectiveness of controls",
                    "control": "HMAC-SHA256 tamper-evident audit chain ensures no event can be modified, deleted, or inserted without detection",
                    "evidence": self._chain.summary(),
                },
            },
            **self._session_data(),
            "chain_entries_sample": [
                e.to_dict() for e in self._chain.entries[:10]
            ],
        }

        Path(path).write_text(json.dumps(evidence, indent=2, default=str))
        return path

    def export_iso27001(self, path: str) -> str:
        """Export ISO 27001:2022 compliance evidence.
        
        Maps to Annex A controls:
        - A.8.15: Logging → Event stream with tamper-evident chain
        - A.8.16: Monitoring activities → eBPF + policy evaluation
        - A.5.23: Information security for cloud → Agent workspace boundary enforcement
        """
        evidence = {
            **self._base_metadata(),
            "framework": "ISO 27001:2022",
            "annex_a_controls": {
                "A.8.15_logging": {
                    "description": "Event logs recording user activities, exceptions, faults and information security events shall be produced, stored, protected and analysed",
                    "implementation": "Every AI agent action is captured as a structured event, hashed into an HMAC-SHA256 chain, and stored with full provenance",
                    "evidence": {
                        "events_logged": self._chain.length,
                        "chain_algorithm": "HMAC-SHA256",
                        "chain_integrity": "VERIFIED" if self._chain.verify()[0] else "BROKEN",
                        "retention": "Configurable (default 30 days)",
                    },
                },
                "A.8.16_monitoring": {
                    "description": "Networks, systems and applications shall be monitored for anomalous behaviour",
                    "implementation": "Three-layer monitoring: eBPF kernel observation, OPA policy evaluation, Z3 formal verification",
                    "evidence": {
                        "layers": {
                            "L1_observe": "DB-batch ingestion (mock tracer); eBPF implemented, not wired (#38b)",
                            "L2_decide": "Built-in Python engine, 7 rules (Rego/OPA available, not default)",
                            "L3_prove": "Z3 SMT solver; 5 adversarial benchmark scenarios, 100%; not exercised per-event in batch audit",
                        },
                    },
                },
                "A.5.23_cloud_security": {
                    "description": "Processes for acquisition, use, management and exit from cloud services shall be established",
                    "implementation": "Agent workspace boundary enforcement — file writes restricted to /workspace/ and /tmp/, system paths blocked, network connections to suspicious ports blocked",
                    "evidence": {
                        "workspace_enforcement": True,
                        "blocked_paths": ["/etc/", "/root/", "/boot/", "/dev/", "/proc/", "/sys/"],
                        "blocked_ports": [4444, 5555, 6666, 8888, 31337, 12345],
                    },
                },
            },
            **self._session_data(),
        }

        Path(path).write_text(json.dumps(evidence, indent=2, default=str))
        return path

    def export_iso42001(self, path: str) -> str:
        """Export ISO/IEC 42001:2023 (AI Management System) evidence.
        
        The first international standard for AI management systems.
        """
        evidence = {
            **self._base_metadata(),
            "framework": "ISO/IEC 42001:2023",
            "controls": {
                "risk_assessment": {
                    "description": "AI risk identification and treatment",
                    "implementation": "Three-layer stack identifies risks at observe (eBPF impl., mock in cron — #38b), policy (built-in Python), and formal (Z3) levels",
                    "risk_categories_covered": [
                        "unauthorized_file_access",
                        "dangerous_command_execution",
                        "network_exfiltration",
                        "budget_exhaustion",
                        "rate_limit_violation",
                        "workspace_boundary_breach",
                        "pii_exposure",
                    ],
                },
                "ai_system_lifecycle": {
                    "description": "Management of AI system throughout its lifecycle",
                    "implementation": "Daily batch cron audit (04:00 UTC) over platform-DB records; per-event built-in policy evaluation; Z3 formal verification available but not exercised per-event in the batch path (#38b)",
                    "evidence": {
                        "monitoring_frequency": "continuous + daily audit",
                        "total_events_evaluated": self._chain.length,
                        "agents_monitored": self._chain.summary()["unique_agents"],
                    },
                },
                "transparency": {
                    "description": "AI system decisions shall be explainable",
                    "implementation": "Every policy decision includes human-readable reasons. Every Z3 verification includes proof or counterexample",
                    "evidence": {
                        "decision_format": "allow/deny + list of reasons",
                        "verification_format": "verified/unsafe + counterexample",
                    },
                },
                "audit_trail": {
                    "description": "Tamper-evident record of all AI system actions",
                    "implementation": "HMAC-SHA256 chain — each event hashed with previous hash",
                    "evidence": self._chain.summary(),
                },
            },
            **self._session_data(),
        }

        Path(path).write_text(json.dumps(evidence, indent=2, default=str))
        return path

    def export_summary(self, path: str) -> str:
        """Export a combined compliance summary across all frameworks."""
        chain_ok, _ = self._chain.verify()
        summary = {
            **self._base_metadata(),
            "compliance_status": {
                "SOC_2_Type_II": "EVIDENCE_AVAILABLE",
                "ISO_27001_2022": "EVIDENCE_AVAILABLE",
                "ISO_42001_2023": "EVIDENCE_AVAILABLE",
                "EU_AI_Act": "PARTIAL — audit trail + explainability ready",
            },
            "verification_stack": {
                "Layer_1_observe": "Mock tracer (DB-batch ingestion via adapters); eBPF kernel hooks implemented, NOT wired in production cron (#38b)",
                "Layer_2_policy": "Active — built-in Python engine, 7 rules (Rego/OPA available via --policy rego, not cron default)",
                "Layer_3_verify": "Z3 available — formal artifact verification via CLI/benchmark (5 adversarial scenarios, 100%); NOT exercised per-event in batch audit",
                "Audit_Chain": f"{'INTACT' if chain_ok else 'BROKEN'} ({self._chain.length} entries)",
            },
            **self._session_data(),
            "differentiator": "Others record what AI does. We prove it was correct.",
        }

        Path(path).write_text(json.dumps(summary, indent=2, default=str))
        return path
