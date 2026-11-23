"""SQLite query index over the disposable capture store.

One row per captured exchange. The blob itself lives in the capture store,
content-addressed by its SHA-256; the index carries the query surface the
operator and the activities need (URL template, status code, time range, host,
canary flag, hunt task).

Canary-callback rows are written by the worker-side consumer of the B10
``sandbox-exec`` return value, not by the canary listener: they carry no blob
(``sha256`` is NULL) and expose only the listener's safe fields.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_SCHEMA = """
CREATE TABLE IF NOT EXISTS exchanges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL DEFAULT '',
    sha256 TEXT,
    url_template TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    status_code INTEGER,
    timestamp TEXT NOT NULL,
    byte_count INTEGER NOT NULL DEFAULT 0,
    canary_callback INTEGER NOT NULL DEFAULT 0,
    hunt_task_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_exchanges_sha ON exchanges(sha256);
CREATE INDEX IF NOT EXISTS idx_exchanges_template ON exchanges(url_template);
CREATE INDEX IF NOT EXISTS idx_exchanges_status ON exchanges(status_code);
CREATE INDEX IF NOT EXISTS idx_exchanges_timestamp ON exchanges(timestamp);
CREATE INDEX IF NOT EXISTS idx_exchanges_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_exchanges_canary ON exchanges(canary_callback);
CREATE INDEX IF NOT EXISTS idx_exchanges_hunt ON exchanges(hunt_task_id);
"""


def capture_index_path(capture_root: Path | str) -> Path:
    """The capture index database path inside *capture_root*."""
    return Path(capture_root) / "index.db"


@dataclass(frozen=True)
class CaptureRow:
    """One capture-index row."""

    id: int
    host: str
    sha256: str | None
    url_template: str
    method: str
    status_code: int | None
    timestamp: str
    byte_count: int
    canary_callback: bool
    hunt_task_id: str | None


def _int(value: object) -> int:
    return int(cast(int, value))


def _opt_int(value: object) -> int | None:
    return None if value is None else int(cast(int, value))


def _str(value: object) -> str:
    return str(value)


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)


def _row_to_capture(row: sqlite3.Row) -> CaptureRow:
    return CaptureRow(
        id=_int(row["id"]),
        host=_str(row["host"]),
        sha256=_opt_str(row["sha256"]),
        url_template=_str(row["url_template"]),
        method=_str(row["method"]),
        status_code=_opt_int(row["status_code"]),
        timestamp=_str(row["timestamp"]),
        byte_count=_int(row["byte_count"]),
        canary_callback=bool(_int(row["canary_callback"])),
        hunt_task_id=_opt_str(row["hunt_task_id"]),
    )


class CaptureIndex:
    """SQLite-backed query surface over captured exchanges.

    Timestamps are ISO-8601 strings in a single fixed format, so range queries
    are lexicographic and stable.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> CaptureIndex:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- writes ---------------------------------------------------------

    def add_exchange(
        self,
        *,
        host: str,
        sha256: str,
        url_template: str,
        method: str,
        status_code: int,
        timestamp: str,
        byte_count: int,
    ) -> int:
        """Insert one captured exchange; return the new row id.

        Each capture gets its own row: the blob is deduplicated by content (the
        redirect/retry that produced identical bytes reuses the existing blob)
        while the index still records that the exchange happened again.
        """
        cursor = self._conn.execute(
            """
            INSERT INTO exchanges
                (host, sha256, url_template, method, status_code, timestamp,
                 byte_count, canary_callback, hunt_task_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)
            """,
            (host, sha256, url_template, method, status_code, timestamp, byte_count),
        )
        self._conn.commit()
        return _int(cursor.lastrowid)

    def add_canary_callback(
        self,
        *,
        method: str,
        path: str,
        source_ip: str,
        timestamp: str,
        hunt_task_id: str | None,
    ) -> int:
        """Insert one canary callback row; return the new row id.

        The callback carries no exchange body, so ``sha256`` stays NULL and the
        caller's address is recorded as the row host.
        """
        cursor = self._conn.execute(
            """
            INSERT INTO exchanges
                (host, sha256, url_template, method, status_code, timestamp,
                 byte_count, canary_callback, hunt_task_id)
            VALUES (?, NULL, ?, ?, NULL, ?, 0, 1, ?)
            """,
            (source_ip, path, method, timestamp, hunt_task_id),
        )
        self._conn.commit()
        return _int(cursor.lastrowid)

    def delete_by_sha256(self, shas: Iterable[str]) -> int:
        """Delete every row referencing one of *shas*; return the row count."""
        count = 0
        for sha in shas:
            cursor = self._conn.execute("DELETE FROM exchanges WHERE sha256 = ?", (sha,))
            count += _int(cursor.rowcount)
        self._conn.commit()
        return count

    # -- queries --------------------------------------------------------

    def _select(self, where: str, params: tuple[object, ...]) -> list[CaptureRow]:
        cursor = self._conn.execute(
            f"SELECT * FROM exchanges WHERE {where} ORDER BY timestamp, id", params
        )
        return [_row_to_capture(row) for row in cursor.fetchall()]

    def by_url_template(self, url_template: str) -> list[CaptureRow]:
        return self._select("url_template = ?", (url_template,))

    def by_status_code(self, status_code: int) -> list[CaptureRow]:
        return self._select("status_code = ?", (status_code,))

    def by_time_range(self, start: str, end: str) -> list[CaptureRow]:
        """Rows with ``start <= timestamp <= end`` (ISO-8601 strings)."""
        return self._select("timestamp >= ? AND timestamp <= ?", (start, end))

    def by_host(self, host: str) -> list[CaptureRow]:
        return self._select("host = ?", (host,))

    def by_canary_callback(self, flag: bool = True) -> list[CaptureRow]:
        return self._select("canary_callback = ?", (1 if flag else 0,))

    def by_hunt_task_id(self, hunt_task_id: str) -> list[CaptureRow]:
        return self._select("hunt_task_id = ?", (hunt_task_id,))

    def rows(self) -> list[CaptureRow]:
        return self._select("1 = 1", ())

    def distinct_blob_shas(self) -> list[str]:
        """Every blob digest the index references (canary rows excluded)."""
        cursor = self._conn.execute(
            "SELECT DISTINCT sha256 FROM exchanges WHERE sha256 IS NOT NULL ORDER BY sha256"
        )
        return [_str(row["sha256"]) for row in cursor.fetchall()]
