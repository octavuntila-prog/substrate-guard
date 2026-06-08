"""Soundness regression for ToolVerifier.

The verdict must reflect the CONSTRUCTED operation (operation_template with params
substituted), not isolated parameter values. The original code certified a
dangerous literal template SAFE and flagged every free-string tool UNSAFE. See the
ToolVerifier critical in docs/AUDIT_COMPLEX_2026-06-07.md.
"""
from __future__ import annotations

from substrate_guard.tool_verifier import (
    ForbiddenPattern,
    ToolDefinition,
    ToolParam,
    ToolSafetyStatus,
    verify_tool,
)

DELETE = [
    ForbiddenPattern(
        "destructive_delete",
        "recursive deletion",
        "operation contains 'rm -rf' or 'rmdir'",
    )
]


def test_dangerous_template_is_unsafe():
    """operation_template hardcodes 'rm -rf' -> UNSAFE even with a constrained enum
    param. The old code certified this SAFE (the keyword was in the template, not a
    parameter value)."""
    tool = ToolDefinition(
        name="cleanup", description="cleanup",
        params=[ToolParam(name="mode", type="enum", enum_values=["read", "list"])],
        operation_template="rm -rf /{mode}",
    )
    assert verify_tool(tool, forbidden=DELETE).status == ToolSafetyStatus.UNSAFE


def test_enum_can_inject_forbidden_keyword_is_unsafe():
    """An enum value that injects a forbidden keyword into the operation -> UNSAFE."""
    tool = ToolDefinition(
        name="runner", description="run",
        params=[ToolParam(name="cmd", type="enum", enum_values=["ls", "rmdir tmp"])],
        operation_template="exec {cmd}",
    )
    assert verify_tool(tool, forbidden=DELETE).status == ToolSafetyStatus.UNSAFE


def test_enum_tool_with_safe_template_is_safe():
    """A tool whose constructed operation can never contain a forbidden keyword is
    SAFE -- the verdict is now a real guarantee for constrained params."""
    tool = ToolDefinition(
        name="lister", description="list a dir",
        params=[ToolParam(name="dir", type="enum", enum_values=["docs", "src"])],
        operation_template="list {dir}",
    )
    assert verify_tool(tool, forbidden=DELETE).status == ToolSafetyStatus.SAFE


def test_no_template_is_unknown():
    """Without an operation_template the operation cannot be modeled -> abstain."""
    tool = ToolDefinition(
        name="search", description="search",
        params=[ToolParam(name="query", type="string")],
        operation_template=None,
    )
    assert verify_tool(tool, forbidden=DELETE).status == ToolSafetyStatus.UNKNOWN


def test_pattern_without_keywords_is_not_falsely_safe():
    """A forbidden pattern whose condition yields no checkable keyword must not certify
    a dangerous template SAFE -- _check_pattern fails closed. Residual of f5c1b9e."""
    tool = ToolDefinition(
        name="cleanup", description="cleanup",
        params=[ToolParam(name="mode", type="enum", enum_values=["a", "b"])],
        operation_template="rm -rf /{mode}",
    )
    nokw = [ForbiddenPattern("destructive", "no recursive delete", "operation must not be destructive")]
    assert verify_tool(tool, forbidden=nokw).status != ToolSafetyStatus.SAFE
