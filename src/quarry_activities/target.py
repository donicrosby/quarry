"""Local target launcher helpers."""

import os
import signal
import subprocess
import time
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})


class TargetKind(StrEnum):
    """Detectable target runtime, from repo contents."""

    FASTAPI = "fastapi"
    EXPRESS = "express"
    GO = "go"
    RUST = "rust"
    COMPOSE = "compose"


def detect_target_kind(app_dir: Path | str) -> TargetKind:
    """Detect a target's runtime from manifest/entry files at the repo root.

    Detection is manifest-only (filenames), not command-based, so it works
    without any toolchain installed. Raises ValueError when no known target
    type matches so the CLI fails explicitly rather than guessing.
    """
    root = Path(app_dir)

    def has(*names: str) -> bool:
        return any((root / n).exists() for n in names)

    if has("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        return TargetKind.COMPOSE
    if has("go.mod"):
        return TargetKind.GO
    if has("Cargo.toml"):
        return TargetKind.RUST
    if has("package.json"):
        return TargetKind.EXPRESS
    if has("app.py", "pyproject.toml", "requirements.txt", "setup.py"):
        return TargetKind.FASTAPI
    msg = f"Unable to detect target type under {root}: no recognized manifest"
    raise ValueError(msg)


def _npm_start_command(root: Path) -> list[str]:
    """Resolve a Node target's start command from package.json.

    Prefers the declared ``scripts.start`` (the project's own entry contract),
    then the ``main`` file, then a conventional entry file. This honors the
    target's own definition rather than assuming a filename.
    """
    pkg = root / "package.json"
    if pkg.exists():
        import json

        with suppress(OSError, ValueError):
            data = json.loads(pkg.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {})
            if isinstance(scripts, dict) and scripts.get("start"):
                return ["npm", "start"]
            main = data.get("main")
            if isinstance(main, str) and main:
                return ["node", main]
    for entry in ("app.js", "index.js", "server.js", "main.js"):
        if (root / entry).exists():
            return ["node", entry]
    return ["npm", "start"]


def _go_run_command(root: Path) -> list[str]:
    """Prefer the conventional cmd/ layout when present, else module root."""
    import shutil

    go = shutil.which("go") or "go"
    cmd_dir = root / "cmd"
    if cmd_dir.is_dir():
        subs = [d for d in cmd_dir.iterdir() if d.is_dir()]
        if len(subs) == 1:
            return [go, "run", f"./cmd/{subs[0].name}"]
    return [go, "run", "."]


def _rust_run_command(root: Path) -> list[str]:
    """Build once then run the binary, so the launched process is the target."""
    import shutil

    cargo = shutil.which("cargo") or "cargo"
    return ["sh", "-c", f"{cargo} build --release && {cargo} run --release"]


def _fastapi_command(root: Path, host: str, port: int) -> list[str]:
    """uvicorn via the project venv (uv) when available, else python -m."""
    import shutil

    app = "app:app" if (root / "app.py").exists() else "main:app"
    base = ["uv", "run"] if shutil.which("uv") else ["python", "-m"]
    return [*base, "uvicorn", app, "--app-dir", str(root), "--host", host, "--port", str(port)]


def _compose_command(root: Path) -> list[str]:
    compose_file = next(
        (
            n
            for n in ("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")
            if (root / n).exists()
        ),
        "docker-compose.yml",
    )
    return ["docker", "compose", "-f", compose_file, "up"]


def launch_command(app_dir: Path | str, *, host: str, port: int) -> list[str]:
    """Build the launch command for the detected target kind.

    Commands are derived from the target's own manifests (package.json scripts,
    go cmd/ layout) with a toolchain-availability fallback, rather than a fixed
    per-kind constant.
    """
    root = Path(app_dir).resolve()
    kind = detect_target_kind(root)
    if kind == TargetKind.FASTAPI:
        return _fastapi_command(root, host, port)
    if kind == TargetKind.EXPRESS:
        return _npm_start_command(root)
    if kind == TargetKind.GO:
        return _go_run_command(root)
    if kind == TargetKind.RUST:
        return _rust_run_command(root)
    return _compose_command(root)


def serves_http(kind: TargetKind) -> bool:
    """True if the launched process serves the app over HTTP on the launch port.

    Rust binaries and compose stacks do not serve the app on the CLI's port;
    only the web frameworks get an HTTP health check on the launch port.
    """
    return kind in (TargetKind.FASTAPI, TargetKind.EXPRESS, TargetKind.GO)


def start_local_target(
    app_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    health_path: str = "/health",
    timeout_seconds: float = 10.0,
) -> subprocess.Popen[str]:
    """Start a local target (any supported kind) and wait for its health endpoint."""
    validate_local_host(host)
    app_path = app_dir.resolve()
    # Raises ValueError for unsupported targets — surfaced as a CLI error.
    kind = detect_target_kind(app_path)
    cmd = launch_command(app_path, host=host, port=port)

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # Own process group so teardown can kill the whole tree (e.g. uv run ->
        # uvicorn, or cargo run -> binary), not just the immediate child.
        start_new_session=True,
    )
    # Only web frameworks serve the app over HTTP on the launch port; binary and
    # compose targets are started and returned without an HTTP readiness wait.
    if not serves_http(kind):
        return process
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
