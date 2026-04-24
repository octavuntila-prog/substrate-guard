"""Tests for M1.2 policy mode resolution.

Tests cover resolve_policy_mode() precedence chain (CLI > env > default)
and resolve_policy_path() mode-to-path mapping.

Refs: docs/M1.2-design.md §5.1
"""

import logging
import pytest
from argparse import Namespace

from substrate_guard.audit import resolve_policy_mode, resolve_policy_path
from substrate_guard.constants import (
    BUILTIN_POLICY_PATH,
    POLICY_ENV_VAR,
    VALID_POLICY_MODES,
)


# ============================================================
# TestPolicyModeResolution — precedence chain CLI > env > default
# ============================================================

class TestPolicyModeResolution:
    """Tests for resolve_policy_mode() precedence chain."""

    def test_cli_flag_wins_over_env(self, monkeypatch):
        """CLI --policy=builtin overrides SUBSTRATE_GUARD_POLICY=rego."""
        monkeypatch.setenv(POLICY_ENV_VAR, 'rego')
        args = Namespace(policy='builtin')
        mode, source = resolve_policy_mode(args)
        assert mode == 'builtin'
        assert source == 'cli'

    def test_cli_rego_wins_over_env_builtin(self, monkeypatch):
        """Symmetric: CLI --policy=rego overrides env=builtin."""
        monkeypatch.setenv(POLICY_ENV_VAR, 'builtin')
        args = Namespace(policy='rego')
        mode, source = resolve_policy_mode(args)
        assert mode == 'rego'
        assert source == 'cli'

    def test_env_var_used_when_cli_absent(self, monkeypatch):
        """Env var SUBSTRATE_GUARD_POLICY=rego activates without CLI flag."""
        monkeypatch.setenv(POLICY_ENV_VAR, 'rego')
        args = Namespace(policy=None)
        mode, source = resolve_policy_mode(args)
        assert mode == 'rego'
        assert source == 'env'

    def test_default_when_neither_set(self, monkeypatch):
        """No CLI, no env -> ('builtin', 'default')."""
        monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
        args = Namespace(policy=None)
        mode, source = resolve_policy_mode(args)
        assert mode == 'builtin'
        assert source == 'default'

    def test_invalid_env_falls_back_to_default(self, monkeypatch, caplog):
        """Invalid env var value logs warning and uses default."""
        monkeypatch.setenv(POLICY_ENV_VAR, 'invalid_value')
        args = Namespace(policy=None)
        with caplog.at_level(logging.WARNING):
            mode, source = resolve_policy_mode(args)
        assert mode == 'builtin'
        assert source == 'default'
        assert 'Invalid SUBSTRATE_GUARD_POLICY' in caplog.text
        assert 'invalid_value' in caplog.text

    def test_invalid_cli_raises(self):
        """Invalid --policy value raises ValueError (early validation)."""
        args = Namespace(policy='invalid_value')
        with pytest.raises(ValueError, match='Invalid --policy'):
            resolve_policy_mode(args)

    def test_missing_policy_attribute(self, monkeypatch):
        """Namespace without 'policy' attribute falls back to env/default gracefully.

        Defensive test for getattr() pattern in resolve_policy_mode.
        """
        monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
        args = Namespace()  # no 'policy' attribute at all
        mode, source = resolve_policy_mode(args)
        assert mode == 'builtin'
        assert source == 'default'


# ============================================================
# TestPolicyPathResolution — mode -> path mapping
# ============================================================

class TestPolicyPathResolution:
    """Tests for resolve_policy_path() mode-to-path mapping."""

    def test_builtin_maps_to_sentinel(self):
        """'builtin' mode returns BUILTIN_POLICY_PATH sentinel."""
        assert resolve_policy_path('builtin') == BUILTIN_POLICY_PATH
        assert resolve_policy_path('builtin') == '__builtin_fallback__'

    def test_rego_maps_to_real_path(self):
        """'rego' mode returns path ending in policy/policies."""
        path = resolve_policy_path('rego')
        # Platform-agnostic: accept both POSIX / and Windows \
        assert path.endswith('policy/policies') or path.endswith('policy\\policies')

    def test_unknown_mode_raises(self):
        """Unknown mode raises ValueError with 'Unknown policy mode'."""
        with pytest.raises(ValueError, match='Unknown policy mode'):
            resolve_policy_path('unknown_mode')

    def test_empty_string_raises(self):
        """Empty string is not a valid mode."""
        with pytest.raises(ValueError, match='Unknown policy mode'):
            resolve_policy_path('')


# ============================================================
# TestValidPolicyModes — contract on VALID_POLICY_MODES frozen
# ============================================================

class TestValidPolicyModes:
    """Tests verifying the VALID_POLICY_MODES contract."""

    def test_valid_modes_frozen(self):
        """VALID_POLICY_MODES is immutable (frozenset)."""
        assert isinstance(VALID_POLICY_MODES, frozenset)
        with pytest.raises(AttributeError):
            VALID_POLICY_MODES.add('new_mode')  # type: ignore[attr-defined]

    def test_valid_modes_content(self):
        """VALID_POLICY_MODES contains exactly 'rego' and 'builtin'."""
        assert VALID_POLICY_MODES == frozenset({'rego', 'builtin'})
