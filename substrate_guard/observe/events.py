"""Structured event types from kernel-level observation.

Each event represents a single observable action by an AI agent at the
kernel boundary — syscalls, file operations, network connections, process
spawns. These are the atoms of the observe layer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import json


class EventType(str, Enum):
    SYSCALL = "syscall"
    FILE_OPEN = "file_open"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    NETWORK_CONNECT = "network_connect"
    NETWORK_SEND = "network_send"
    NETWORK_RECV = "network_recv"
    PROCESS_EXEC = "process_exec"
    PROCESS_FORK = "process_fork"
    TLS_READ = "tls_read"
    TLS_WRITE = "tls_write"
    MEMORY_ALLOC = "memory_alloc"


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


@dataclass
class Event:
    """Base event from kernel observation."""
    type: EventType
    timestamp: float = field(default_factory=time.time)
    agent_id: str = "unknown"
    pid: int = 0
    tid: int = 0
    uid: int = 0
    comm: str = ""  # process name (16 char max in kernel)
    severity: Severity = Severity.INFO
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "Event":
        data = data.copy()
        data["type"] = EventType(data["type"])
        data["severity"] = Severity(data.get("severity", "info"))
        # Dispatch to subclass
        event_type = data["type"]
        subclass_map = {
            EventType.SYSCALL: SyscallEvent,
            EventType.FILE_OPEN: FileEvent,
            EventType.FILE_WRITE: FileEvent,
            EventType.FILE_READ: FileEvent,
            EventType.NETWORK_CONNECT: NetworkEvent,
            EventType.NETWORK_SEND: NetworkEvent,
            EventType.NETWORK_RECV: NetworkEvent,
            EventType.PROCESS_EXEC: ProcessEvent,
            EventType.PROCESS_FORK: ProcessEvent,
            EventType.TLS_READ: TLSEvent,
            EventType.TLS_WRITE: TLSEvent,
        }
        target_cls = subclass_map.get(event_type, cls)
        # Filter to known fields
        known = {f.name for f in target_cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return target_cls(**filtered)


@dataclass
class SyscallEvent(Event):
    """Raw syscall event."""
    syscall_name: str = ""
    syscall_nr: int = -1
    args: list = field(default_factory=list)
    ret: int = 0


@dataclass
class FileEvent(Event):
    """File operation event (open, read, write)."""
    path: str = ""
    flags: int = 0
    mode: int = 0
    bytes_count: int = 0

    def __post_init__(self):
        # Auto-classify severity
        dangerous_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/dev/sda", "/dev/mem", "/proc/kcore",
        ]
        sensitive_prefixes = [
            "/etc/", "/root/", "/var/log/", "/boot/",
            "/proc/", "/sys/", "/dev/",
        ]
        if any(self.path == p for p in dangerous_paths):
            self.severity = Severity.CRITICAL
        elif any(self.path.startswith(p) for p in sensitive_prefixes):
            self.severity = Severity.WARN


@dataclass
class NetworkEvent(Event):
    """Network connection/send/recv event."""
    remote_ip: str = ""
    remote_port: int = 0
    local_port: int = 0
    protocol: str = "tcp"
    bytes_count: int = 0
    domain: str = ""  # resolved if available

    def __post_init__(self):
        # Classify known-bad ports/IPs
        suspicious_ports = {4444, 5555, 6666, 8888, 31337, 12345}
        if self.remote_port in suspicious_ports:
            self.severity = Severity.CRITICAL
        elif self.remote_port in {22, 23, 3389}:  # ssh/telnet/rdp
            self.severity = Severity.WARN


@dataclass
class ProcessEvent(Event):
    """Process execution/fork event."""
    filename: str = ""
    args: list = field(default_factory=list)
    parent_pid: int = 0
    parent_comm: str = ""

    def __post_init__(self):
        dangerous_commands = [
            "rm", "chmod", "chown", "mkfs", "dd",
            "curl", "wget", "nc", "ncat", "socat",
            "python", "perl", "ruby", "bash", "sh",
        ]
        if self.filename:
            base = self.filename.rsplit("/", 1)[-1]
            if base in dangerous_commands:
                self.severity = Severity.WARN
            # Check for specific dangerous arg patterns
            args_str = " ".join(str(a) for a in self.args)
            if "rm -rf /" in args_str or "chmod 777" in args_str:
                self.severity = Severity.CRITICAL


@dataclass
class TLSEvent(Event):
    """TLS read/write event (decrypted payload from uprobe)."""
    remote_ip: str = ""
    remote_port: int = 0
    payload_size: int = 0
    payload_preview: str = ""  # first 256 bytes, sanitized
    is_llm_api: bool = False  # detected OpenAI/Anthropic/etc endpoint

    def __post_init__(self):
        llm_indicators = [
            "api.openai.com", "api.anthropic.com",
            "api.cohere.ai", "generativelanguage.googleapis.com",
        ]
        if any(ind in self.payload_preview for ind in llm_indicators):
            self.is_llm_api = True


@dataclass  
class MemoryEvent(Event):
    """Memory allocation event for resource tracking."""
    bytes_allocated: int = 0
    total_rss: int = 0  # resident set size
    cgroup: str = ""


# --- Event Stream ---

class EventStream:
    """Collects and indexes events from observation."""

    def __init__(self):
        self._events: list[Event] = []
        self._by_agent: dict[str, list[Event]] = {}
        self._by_type: dict[EventType, list[Event]] = {}

    def add(self, event: Event) -> None:
        self._events.append(event)
        self._by_agent.setdefault(event.agent_id, []).append(event)
        self._by_type.setdefault(event.type, []).append(event)

    def for_agent(self, agent_id: str) -> list[Event]:
        return self._by_agent.get(agent_id, [])

    def of_type(self, event_type: EventType) -> list[Event]:
        return self._by_type.get(event_type, [])

    def critical(self) -> list[Event]:
        return [e for e in self._events if e.severity == Severity.CRITICAL]

    def warnings(self) -> list[Event]:
        return [e for e in self._events if e.severity == Severity.WARN]

    @property
    def count(self) -> int:
        return len(self._events)

    @property
    def agents(self) -> set[str]:
        return set(self._by_agent.keys())

    def summary(self) -> dict:
        return {
            "total_events": self.count,
            "agents": list(self.agents),
            "by_type": {t.value: len(evts) for t, evts in self._by_type.items()},
            "critical": len(self.critical()),
            "warnings": len(self.warnings()),
        }

    def to_json_lines(self) -> str:
        return "\n".join(e.to_json() for e in self._events)

    def __iter__(self):
        return iter(self._events)

    def __len__(self):
        return len(self._events)
