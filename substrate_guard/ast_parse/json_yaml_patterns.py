"""Structural checks on parsed JSON and YAML (prototype-style keys, unsafe YAML tags)."""

from __future__ import annotations

import json
from typing import Any

import yaml

from substrate_guard.ast_parse.patterns import StructuralViolation

# Keys associated with prototype-pollution / JS gadget chains when data is merged into objects.
_RISK_KEYS = frozenset({"__proto__", "constructor", "prototype"})
_MAX_DEPTH = 64


def _walk_object(obj: Any, lang: str, depth: int = 0) -> list[StructuralViolation]:
    out: list[StructuralViolation] = []
    if depth > _MAX_DEPTH:
        out.append(
            StructuralViolation(
                rule=f"ast_{lang}_depth_limit",
                description=f"Nested structure deeper than {_MAX_DEPTH} (structural)",
                matched_text="",
            )
        )
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            if ks in _RISK_KEYS:
                out.append(
                    StructuralViolation(
                        rule=f"ast_{lang}_risk_key",
                        description=f"Key {ks!r} (prototype / merge gadget risk)",
                        matched_text=ks,
                    )
                )
            out.extend(_walk_object(v, lang, depth + 1))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_object(v, lang, depth + 1))
    return out


def json_structural_issues(text: str) -> list[StructuralViolation]:
    """Parse JSON and flag risky keys anywhere in the tree."""
    t = text.strip()
    if not t:
        return []
    try:
        data = json.loads(t)
    except json.JSONDecodeError:
        return []
    return _walk_object(data, "json")


def yaml_structural_issues(text: str) -> list[StructuralViolation]:
    """``yaml.safe_load`` only; flag ``!!python`` tags in source and risky keys in data."""
    out: list[StructuralViolation] = []
    if "!!python" in text or "!!python/" in text:
        out.append(
            StructuralViolation(
                rule="ast_yaml_unsafe_python_tag",
                description="YAML unsafe Python constructor tag (!!python/...) in source",
                matched_text=text[:500],
            )
        )
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return out
    if data is None:
        return out
    out.extend(_walk_object(data, "yaml"))
    return out
