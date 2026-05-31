"""Local target launcher helpers."""

import subprocess
import time
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
    )
    try:
        wait_for_health(f"http://{host}:{port}{health_path}", timeout_seconds=timeout_seconds)
    except Exception:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        raise
    return process


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
