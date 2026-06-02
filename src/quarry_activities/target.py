"""Local target launcher helpers."""

import os
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})


def start_local_target(
    app_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    health_path: str = "/health",
    timeout_seconds: float = 10.0,
) -> subprocess.Popen[str]:
    """Start a uvicorn target and wait until its local health endpoint responds."""
    validate_local_host(host)
    app_path = app_dir.resolve()
    if not (app_path / "app.py").exists():
        msg = f"Target app not found: {app_path / 'app.py'}"
        raise ValueError(msg)

    process = subprocess.Popen(
        [
            "uv",
            "run",
            "uvicorn",
            "app:app",
            "--app-dir",
            str(app_path),
            "--host",
            host,
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # Own process group so teardown can kill the whole tree (uv run -> uvicorn),
        # not just the immediate child.
        start_new_session=True,
    )
    try:
        wait_for_health(f"http://{host}:{port}{health_path}", timeout_seconds=timeout_seconds)
    except Exception:
        terminate_local_target(process)
        raise
    return process


def terminate_local_target(process: subprocess.Popen[str]) -> None:
    """Terminate a launched target and its whole process group, then close pipes."""
    try:
        if process.poll() is None:
            _signal_process_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _signal_process_group(process, signal.SIGKILL)
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=2)
    finally:
        if process.stdout is not None:
            process.stdout.close()


def _signal_process_group(process: subprocess.Popen[str], sig: int) -> None:
    try:
        os.killpg(os.getpgid(process.pid), sig)
    except (ProcessLookupError, PermissionError):
        with suppress(ProcessLookupError, PermissionError):
            process.send_signal(sig)


def wait_for_health(url: str, *, timeout_seconds: float = 10.0) -> None:
    """Wait for a local health endpoint to return any successful response."""
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                if 200 <= response.status < 300:
                    return
        except URLError as error:
            last_error = error
        time.sleep(0.1)
    msg = f"Target health check failed: {url}"
    if last_error is not None:
        raise TimeoutError(msg) from last_error
    raise TimeoutError(msg)


def validate_local_host(host: str) -> None:
    if host not in LOCAL_HOSTS:
        msg = f"Only localhost targets are allowed, got: {host}"
        raise ValueError(msg)
