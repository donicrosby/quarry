"""Executable launch verification for the planted-regression target (bench 2.3).

``quarry target start examples/vulnerable-planted`` must actually launch the
target and serve it. This module proves that with real execution: it starts the
target through the same launcher the CLI uses (``start_local_target``), waits on
``/health``, and then exercises every planted sink over real HTTP — including the
``data/welcome.txt`` seed the ``/files`` route reads and a ``../`` traversal that
escapes the data directory. A missing data fixture or a reverted sink fails here.
"""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path
from typing import Any, cast
from urllib.request import Request, urlopen

import pytest

from quarry_activities.target import start_local_target, terminate_local_target

REPO_ROOT = Path(__file__).resolve().parents[2]
PLANTED_REPO = REPO_ROOT / "examples/vulnerable-planted"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _get_json(base: str, path: str) -> dict[str, Any]:
    with urlopen(f"{base}{path}", timeout=5) as response:  # noqa: S310 — loopback only
        return cast("dict[str, Any]", json.loads(response.read().decode("utf-8")))


def _post_json(base: str, path: str) -> dict[str, Any]:
    request = Request(f"{base}{path}", data=b"", method="POST")
    with urlopen(request, timeout=5) as response:  # noqa: S310 — loopback only
        return cast("dict[str, Any]", json.loads(response.read().decode("utf-8")))


@pytest.mark.skipif(
    not (PLANTED_REPO / "app.py").exists(),
    reason="vulnerable-planted example not available",
)
def test_planted_target_launches_and_serves_every_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UV_NO_SYNC", "1")  # don't resync the project env mid-test
    port = _free_port()
    process = start_local_target(PLANTED_REPO, host="127.0.0.1", port=port, timeout_seconds=60.0)
    base = f"http://127.0.0.1:{port}"
    try:
        assert _get_json(base, "/health") == {"status": "ok"}

        # B2: /files reads a committed seed instead of 500ing on an absent data dir.
        seed = _get_json(base, "/files?name=welcome.txt")
        assert "planted-regression target" in seed["content"].lower()
        # ...and the same route escapes DATA_DIR with ../ (the planted traversal).
        escaped = _get_json(base, "/files?name=../app.py")
        assert "Planted-regression target" in escaped["content"]

        executed = _get_json(base, "/exec?command=qrmark%3B%20echo%20QRYINJECTED")
        assert "QRYINJECTED" in executed["stdout"]

        hashed = _get_json(base, "/password?value=qrmark")
        assert hashed["hash"] == hashlib.md5(b"qrmark", usedforsecurity=False).hexdigest()

        leaked = _get_json(base, "/admin/status?user=anon")
        assert leaked["users"] == "42"

        # /profile unpickles an attacker blob (payload is a query param on the
        # route); a benign payload round-trips.
        import pickle

        payload = pickle.dumps({"role": "admin"}).hex()
        profile = _post_json(base, f"/profile?payload={payload}")
        assert "admin" in profile["profile"]
    finally:
        terminate_local_target(process)
