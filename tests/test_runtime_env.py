"""runtime_env: env and resolution helpers for verify_process_cli."""

from types import SimpleNamespace

from substrate_guard.runtime_env import (
    VERIFY_PROCESS_CLI_ENV,
    monitor_verify_process_cli,
    pipeline_verify_process_cli,
    resolve_verify_process_cli,
)


class TestResolveVerifyProcessCLI:
    def test_explicit_wins_over_config_and_env(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "1")
        assert resolve_verify_process_cli(False, True) is False
        assert resolve_verify_process_cli(True, False) is True

    def test_env_enable_over_config_false(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "1")
        assert resolve_verify_process_cli(None, False) is True

    def test_env_disable_before_config(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "0")
        assert resolve_verify_process_cli(None, True) is False

    def test_config_when_env_unset(self, monkeypatch):
        monkeypatch.delenv(VERIFY_PROCESS_CLI_ENV, raising=False)
        assert resolve_verify_process_cli(None, True) is True
        assert resolve_verify_process_cli(None, False) is False


class TestPipelineVerifyProcessCLI:
    def test_default_true_unless_no_flag_or_env_off(self, monkeypatch):
        monkeypatch.delenv(VERIFY_PROCESS_CLI_ENV, raising=False)
        args = SimpleNamespace(no_verify_process_cli=False)
        assert pipeline_verify_process_cli(args, default=True) is True

    def test_no_verify_wins(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "1")
        args = SimpleNamespace(no_verify_process_cli=True)
        assert pipeline_verify_process_cli(args, default=True) is False

    def test_env_off_disables_without_flag(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "off")
        args = SimpleNamespace(no_verify_process_cli=False)
        assert pipeline_verify_process_cli(args, default=True) is False


class TestMonitorVerifyProcessCLI:
    def test_flag_enables(self, monkeypatch):
        monkeypatch.delenv(VERIFY_PROCESS_CLI_ENV, raising=False)
        args = SimpleNamespace(verify_process_cli=True, no_verify_process_cli=False)
        assert monitor_verify_process_cli(args) is True

    def test_no_verify_wins(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "1")
        args = SimpleNamespace(verify_process_cli=False, no_verify_process_cli=True)
        assert monitor_verify_process_cli(args) is False

    def test_env_enables(self, monkeypatch):
        monkeypatch.setenv(VERIFY_PROCESS_CLI_ENV, "on")
        args = SimpleNamespace(verify_process_cli=False, no_verify_process_cli=False)
        assert monitor_verify_process_cli(args) is True
