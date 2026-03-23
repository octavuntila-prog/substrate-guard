"""Tests for Layer 2: OPA/Rego Policy — 50 test cases (25 allow, 25 deny)."""

import pytest
from substrate_guard.policy.engine import PolicyEngine, PolicyDecision
from substrate_guard.observe.events import (
    EventType, FileEvent, NetworkEvent, ProcessEvent,
)


@pytest.fixture
def engine():
    return PolicyEngine(policy_path="nonexistent/", use_opa_binary=False)


# ============================================
# DENY tests — 25 actions that must be blocked
# ============================================

class TestPolicyDeny:
    def test_deny_write_etc_passwd(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/etc/passwd"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_etc_shadow(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/etc/shadow"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_etc_sudoers(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/etc/sudoers"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_etc_crontab(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/etc/crontab"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_boot(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/boot/vmlinuz"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_dev(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/dev/sda"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_proc(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_open", "path": "/proc/kcore"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_root(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/root/.bashrc"},
            "context": {}
        })
        assert d.denied

    def test_deny_rm_rf(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "rm -rf /", "filename": "rm"},
            "context": {}
        })
        assert d.denied

    def test_deny_drop_table(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "psql -c 'DROP TABLE users'", "filename": "psql"},
            "context": {}
        })
        assert d.denied

    def test_deny_chmod_777(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "chmod 777 /etc/passwd", "filename": "chmod"},
            "context": {}
        })
        assert d.denied

    def test_deny_disk_wipe(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "echo x > /dev/sda", "filename": "echo"},
            "context": {}
        })
        assert d.denied

    def test_deny_fork_bomb(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": ":(){ :|:& };:", "filename": "bash"},
            "context": {}
        })
        assert d.denied

    def test_deny_suspicious_port_4444(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "1.2.3.4", "remote_port": 4444},
            "context": {}
        })
        assert d.denied

    def test_deny_suspicious_port_31337(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "5.6.7.8", "remote_port": 31337},
            "context": {}
        })
        assert d.denied

    def test_deny_budget_exhausted(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "1.1.1.1", "remote_port": 443},
            "context": {"budget_remaining": 0}
        })
        assert d.denied

    def test_deny_budget_negative(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/out.py"},
            "context": {"budget_remaining": -5.0}
        })
        assert d.denied

    def test_deny_rate_limit_exceeded(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "1.1.1.1", "remote_port": 443},
            "context": {"api_calls_last_minute": 200, "rate_limit": 100}
        })
        assert d.denied

    def test_deny_sudo_non_admin(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "sudo rm /tmp/x", "filename": "/usr/bin/sudo"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_outside_workspace(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/home/user/secret.txt"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_usr_bin(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/usr/bin/python3"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_sbin(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/sbin/init"},
            "context": {}
        })
        assert d.denied

    def test_deny_write_var_log(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/var/log/auth.log"},
            "context": {}
        })
        assert d.denied

    def test_deny_mkfs(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "mkfs.ext4 /dev/sda1", "filename": "mkfs.ext4"},
            "context": {}
        })
        assert d.denied

    def test_deny_suspicious_port_12345(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "10.0.0.1", "remote_port": 12345},
            "context": {}
        })
        assert d.denied


# ============================================
# ALLOW tests — 25 actions that must be permitted
# ============================================

class TestPolicyAllow:
    def test_allow_workspace_write(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/output.py"},
            "context": {}
        })
        assert d.allowed

    def test_allow_workspace_read(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_read", "path": "/workspace/data.csv"},
            "context": {}
        })
        assert d.allowed

    def test_allow_workspace_subdir(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/src/main.py"},
            "context": {}
        })
        assert d.allowed

    def test_allow_tmp_write(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/tmp/scratch.txt"},
            "context": {}
        })
        assert d.allowed

    def test_allow_https_443(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "1.2.3.4",
                       "remote_port": 443, "domain": "api.openai.com"},
            "context": {}
        })
        assert d.allowed

    def test_allow_normal_command(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "python3 /workspace/run.py",
                       "filename": "/usr/bin/python3"},
            "context": {}
        })
        assert d.allowed

    def test_allow_ls(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "ls -la /workspace/",
                       "filename": "/usr/bin/ls"},
            "context": {}
        })
        assert d.allowed

    def test_allow_cat_workspace(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "cat /workspace/readme.md",
                       "filename": "/usr/bin/cat"},
            "context": {}
        })
        assert d.allowed

    def test_allow_with_budget(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/out.py"},
            "context": {"budget_remaining": 50.0}
        })
        assert d.allowed

    def test_allow_within_rate_limit(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "1.1.1.1",
                       "remote_port": 443, "domain": "example.com"},
            "context": {"api_calls_last_minute": 50, "rate_limit": 100}
        })
        assert d.allowed

    def test_allow_grep(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "grep -r 'def ' /workspace/",
                       "filename": "/usr/bin/grep"},
            "context": {}
        })
        assert d.allowed

    def test_allow_pip_install(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "pip install pandas",
                       "filename": "/usr/bin/pip"},
            "context": {}
        })
        assert d.allowed

    def test_allow_workspace_deep_path(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/a/b/c/d/e.py"},
            "context": {}
        })
        assert d.allowed

    def test_allow_tmp_nested(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/tmp/substrate-guard/cache.json"},
            "context": {}
        })
        assert d.allowed

    def test_allow_standard_port_80(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "93.184.216.34",
                       "remote_port": 80, "domain": "example.com"},
            "context": {}
        })
        assert d.allowed

    def test_allow_dns_53(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "web-search"},
            "action": {"type": "network_connect", "remote_ip": "8.8.8.8",
                       "remote_port": 53, "domain": ""},
            "context": {}
        })
        assert d.allowed

    def test_allow_workspace_json(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "data-processor"},
            "action": {"type": "file_write", "path": "/workspace/results.json"},
            "context": {}
        })
        assert d.allowed

    def test_allow_wc(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "wc -l /workspace/data.csv",
                       "filename": "/usr/bin/wc"},
            "context": {}
        })
        assert d.allowed

    def test_allow_head(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "head -20 /workspace/log.txt",
                       "filename": "/usr/bin/head"},
            "context": {}
        })
        assert d.allowed

    def test_allow_node(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "node /workspace/app.js",
                       "filename": "/usr/bin/node"},
            "context": {}
        })
        assert d.allowed

    def test_allow_workspace_md(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "researcher"},
            "action": {"type": "file_write", "path": "/workspace/notes.md"},
            "context": {}
        })
        assert d.allowed

    def test_allow_network_443_github(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "network_connect", "remote_ip": "140.82.121.4",
                       "remote_port": 443, "domain": "github.com"},
            "context": {}
        })
        assert d.allowed

    def test_allow_file_read_workspace(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_read", "path": "/workspace/config.yaml"},
            "context": {}
        })
        assert d.allowed

    def test_allow_sort(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "sort /workspace/names.txt",
                       "filename": "/usr/bin/sort"},
            "context": {}
        })
        assert d.allowed

    def test_allow_touch_workspace(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "process_exec", "command": "touch /workspace/new_file.txt",
                       "filename": "/usr/bin/touch"},
            "context": {}
        })
        assert d.allowed


# ============================================
# Event-based evaluation tests
# ============================================

class TestPolicyEventEval:
    def test_file_event_deny(self, engine):
        event = FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd",
                         agent_id="a1", pid=100)
        d = engine.evaluate_event(event)
        assert d.denied

    def test_file_event_allow(self, engine):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/out.py",
                         agent_id="a1", pid=100)
        d = engine.evaluate_event(event)
        assert d.allowed

    def test_network_event_deny(self, engine):
        event = NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=4444,
                           remote_ip="1.2.3.4", agent_id="a1", pid=100)
        d = engine.evaluate_event(event)
        assert d.denied

    def test_network_event_allow(self, engine):
        event = NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=443,
                           remote_ip="1.1.1.1", domain="example.com",
                           agent_id="a1", pid=100)
        d = engine.evaluate_event(event)
        assert d.allowed

    def test_process_event_deny(self, engine):
        event = ProcessEvent(type=EventType.PROCESS_EXEC, filename="/bin/rm",
                           args=["rm", "-rf", "/"], agent_id="a1", pid=100)
        d = engine.evaluate_event(event)
        assert d.denied


# ============================================
# Policy engine stats
# ============================================

class TestPolicyStats:
    def test_stats_after_evaluations(self, engine):
        for i in range(10):
            engine.evaluate({
                "agent": {"id": "a1", "role": "code-gen"},
                "action": {"type": "file_write", "path": f"/workspace/{i}.py"},
                "context": {}
            })
        stats = engine.stats
        assert stats["decisions"] == 10
        assert stats["avg_latency_ms"] > 0
        assert stats["using_opa_binary"] is False

    def test_batch_evaluate(self, engine):
        events = [
            FileEvent(type=EventType.FILE_WRITE, path="/workspace/a.py", agent_id="a1"),
            FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="a1"),
            NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=443, agent_id="a1"),
        ]
        decisions = engine.batch_evaluate(events)
        assert len(decisions) == 3
        assert decisions[0].allowed  # workspace write
        assert decisions[1].denied   # /etc/passwd
        assert decisions[2].allowed  # port 443


# ============================================
# PII detection tests
# ============================================

class TestPIIDetection:
    def test_ssn_detected(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/data.txt",
                       "content": "SSN: 123-45-6789"},
            "context": {}
        })
        assert d.denied
        assert any("SSN" in r for r in d.reasons)

    def test_credit_card_detected(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/data.txt",
                       "content": "Card: 4111-1111-1111-1111"},
            "context": {}
        })
        assert d.denied
        assert any("credit card" in r for r in d.reasons)

    def test_no_false_positive_pii(self, engine):
        d = engine.evaluate({
            "agent": {"id": "a1", "role": "code-gen"},
            "action": {"type": "file_write", "path": "/workspace/data.txt",
                       "content": "Temperature: 72.5 degrees"},
            "context": {}
        })
        assert d.allowed
