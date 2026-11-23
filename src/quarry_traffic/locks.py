"""Advisory file lock shared by evidence snapshots and capture reclamation.

A finding-binding snapshot holds ``LOCK_EX`` while it copies blobs out of the
disposable capture store. Capture reclamation tries ``LOCK_EX | LOCK_NB`` and
skips its cycle when a snapshot is in progress, so a referenced blob can never
be deleted between the index lookup and the copy.
"""

from __future__ import annotations

import fcntl
from pathlib import Path
from types import TracebackType
from typing import BinaryIO


class SnapshotLock:
    """Exclusive advisory lock over one lock file."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._handle: BinaryIO | None = None

    def acquire(self) -> None:
        """Block until the lock is held."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        self._handle = handle

    def try_acquire(self) -> bool:
        """Take the lock if free; return False (without blocking) when held."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        if self._handle is None:
            return
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None

    def __enter__(self) -> SnapshotLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()
