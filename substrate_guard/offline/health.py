"""Health Check — Detects PostgreSQL and network availability.

Determines whether the system should operate in online or offline mode.
Checks are non-blocking and cached for a configurable interval.

Usage:
    health = HealthCheck(db_url="postgresql://...", check_interval=30)
    if health.is_online():
        # store in PostgreSQL
    else:
        # store in SQLite
"""

from __future__ import annotations

import socket
import time
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("substrate_guard.offline.health")


class HealthCheck:
    """Non-blocking health check for PostgreSQL and network.
    
    Caches results for `check_interval` seconds to avoid
    hammering a potentially-down service.
    
    Args:
        db_url: PostgreSQL connection URL.
        check_interval: Seconds between actual checks.
        connect_timeout: TCP connect timeout in seconds.
    """

    def __init__(
        self,
        db_url: Optional[str] = None,
        check_interval: float = 30.0,
        connect_timeout: float = 3.0,
    ):
        self._db_url = db_url
        self._check_interval = check_interval
        self._connect_timeout = connect_timeout
        
        # Parse DB host/port from URL
        self._db_host = "localhost"
        self._db_port = 5432
        if db_url:
            parsed = urlparse(db_url.replace("+asyncpg", ""))
            self._db_host = parsed.hostname or "localhost"
            self._db_port = parsed.port or 5432
        
        # Cached state
        self._pg_up: bool = False
        self._net_up: bool = True
        self._last_check: float = 0.0
        self._consecutive_failures: int = 0
        self._consecutive_successes: int = 0

    def _check_tcp(self, host: str, port: int) -> bool:
        """Try a TCP connection to host:port. Returns True if reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._connect_timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _do_check(self):
        """Perform actual health checks."""
        now = time.time()
        if now - self._last_check < self._check_interval:
            return  # Use cached result
        
        self._last_check = now
        
        # Check PostgreSQL
        pg_reachable = self._check_tcp(self._db_host, self._db_port)
        
        if pg_reachable:
            self._consecutive_successes += 1
            self._consecutive_failures = 0
            if not self._pg_up:
                logger.info(f"PostgreSQL is BACK at {self._db_host}:{self._db_port}")
            self._pg_up = True
        else:
            self._consecutive_failures += 1
            self._consecutive_successes = 0
            if self._pg_up:
                logger.warning(f"PostgreSQL is DOWN at {self._db_host}:{self._db_port}")
            self._pg_up = False
        
        # Check general network (DNS resolution as proxy)
        try:
            socket.setdefaulttimeout(self._connect_timeout)
            socket.getaddrinfo("1.1.1.1", 53, socket.AF_INET, socket.SOCK_STREAM)
            self._net_up = True
        except (socket.error, OSError):
            if self._net_up:
                logger.warning("Network appears DOWN")
            self._net_up = False

    def is_pg_up(self) -> bool:
        """Is PostgreSQL reachable?"""
        self._do_check()
        return self._pg_up

    def is_online(self) -> bool:
        """Is the system online? (PostgreSQL reachable)"""
        return self.is_pg_up()

    def is_network_up(self) -> bool:
        """Is general network connectivity available?"""
        self._do_check()
        return self._net_up

    def force_check(self) -> dict:
        """Force an immediate check regardless of interval."""
        self._last_check = 0
        self._do_check()
        return self.status()

    def status(self) -> dict:
        """Current health status."""
        self._do_check()
        return {
            "postgresql": "UP" if self._pg_up else "DOWN",
            "network": "UP" if self._net_up else "DOWN",
            "mode": "ONLINE" if self._pg_up else "OFFLINE",
            "db_host": self._db_host,
            "db_port": self._db_port,
            "consecutive_failures": self._consecutive_failures,
            "consecutive_successes": self._consecutive_successes,
        }
