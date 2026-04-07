"""Reachability probes (PostgreSQL, rough internet) — best-effort, timeout-bound."""

from __future__ import annotations

import socket
from contextlib import closing


class ConnectivityChecker:
    """Cheap socket checks; ``mode`` is ``online`` only if PostgreSQL port accepts TCP."""

    def __init__(
        self,
        pg_host: str = "127.0.0.1",
        pg_port: int = 5432,
        timeout: float = 2.0,
    ) -> None:
        self.pg_host = pg_host
        self.pg_port = pg_port
        self.timeout = timeout

    def check_postgres(self) -> bool:
        try:
            with closing(
                socket.create_connection(
                    (self.pg_host, self.pg_port),
                    timeout=self.timeout,
                )
            ):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def check_internet(self) -> bool:
        for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53)):
            try:
                with closing(
                    socket.create_connection((host, port), timeout=self.timeout)
                ):
                    return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        return False

    def status(self) -> dict[str, bool | str]:
        pg = self.check_postgres()
        inet = self.check_internet()
        return {
            "postgres": pg,
            "internet": inet,
            "mode": "online" if pg else "offline",
            "alerts": inet,
        }
