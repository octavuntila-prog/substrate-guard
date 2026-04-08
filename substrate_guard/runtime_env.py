"""Environment-driven defaults (12-factor style).

``SUBSTRATE_GUARD_VERIFY_PROCESS_CLI`` — enable/disable CLI regex checks on
``ProcessEvent`` when not overridden by explicit CLI flags or constructor args.
"""

from __future__ import annotations

import os
from typing import Any, Optional

VERIFY_PROCESS_CLI_ENV = "SUBSTRATE_GUARD_VERIFY_PROCESS_CLI"


def env_verify_process_cli_enabled() -> bool:
    v = os.environ.get(VERIFY_PROCESS_CLI_ENV, "").strip().lower()
    return v in ("1", "true", "yes", "on")


def env_verify_process_cli_disabled() -> bool:
    v = os.environ.get(VERIFY_PROCESS_CLI_ENV, "").strip().lower()
    return v in ("0", "false", "no", "off")


def resolve_verify_process_cli(
    explicit: Optional[bool],
    config_value: bool = False,
) -> bool:
    """SubstrateGuard / integrations: explicit ctor > env > JSON config.

    If ``explicit`` is ``True`` or ``False``, it wins. Otherwise ``1``/``on`` in
    env enables; ``0``/``off`` does not disable an explicit ``True`` — use
    ``explicit=False`` for that. When env is unset, ``config_value`` applies.
    """
    if explicit is not None:
        return bool(explicit)
    if env_verify_process_cli_enabled():
        return True
    if env_verify_process_cli_disabled():
        return False
    return bool(config_value)


def pipeline_verify_process_cli(args: Any, *, default: bool = True) -> bool:
    """``demo`` / ``export`` / ``stack-benchmark``: ``--no-verify-process-cli``
    wins; ``SUBSTRATE_GUARD_VERIFY_PROCESS_CLI=0|off|...`` disables the
    pipeline default without changing the command line (e.g. CI).
    """
    if getattr(args, "no_verify_process_cli", False):
        return False
    if env_verify_process_cli_disabled():
        return False
    return bool(default)


def monitor_verify_process_cli(args: Any) -> bool:
    """``monitor``: ``--no-verify-process-cli`` forces off; else ``--verify-process-cli``
    or ``SUBSTRATE_GUARD_VERIFY_PROCESS_CLI=1`` turns checks on.
    """
    if getattr(args, "no_verify_process_cli", False):
        return False
    if getattr(args, "verify_process_cli", False):
        return True
    return env_verify_process_cli_enabled()
