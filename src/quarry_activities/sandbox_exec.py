"""sandbox_exec_activity — transport-agnostic sandbox execution (ADR-017 §5).

This activity is the sandbox counterpart to http_request_activity.  It:
  1. Validates the SandboxExecSpec (command allowlist, path restrictions).
  2. Resolves credentials worker-side (ADR-018); registers secrets in the Scrubber.
  3. Materializes ProveCorpus and input_files into the sandbox working dir.
  4. Runs the command via the configured SandboxBackend.
  5. Caps stdout/stderr, scrubs them (Scrubber.scrub()), wraps in <target_content>.
  6. Stores stdout/stderr as TOOL_STDOUT/TOOL_STDERR artifacts.
  7. Returns a SandboxExecCapture.

Non-idempotent operations must be dispatched with RetryPolicy(maximum_attempts=1)
by the workflow.

The agent (prove role) NEVER sees raw credential values — only profile names.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import subprocess
import tempfile
import textwrap
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from temporalio import activity

from quarry.config import QuarrySettings
from quarry.egress import TARGET_HOST, EgressPolicyError, resolve_egress_policy
from quarry.schemas import (
    CANARY_PATH_MAX_CHARS,
    ArtifactKind,
    CanaryCallback,
    EgressPolicy,
    RedactionStatus,
    ResolvedEgressPolicy,
    SandboxExecCapture,
    SandboxExecSpec,
)
from quarry_activities.inputs import SandboxExecActivityInput
from quarry_activities.sandbox import (
    ContainerSandbox,
    K8sJobSandbox,
    LocalSubprocessSandbox,
    SandboxBackend,
    SandboxResult,
)
from quarry_artifacts.quarantine import put_quarantined_artifact
from quarry_artifacts.store import build_artifact_store
from quarry_models.redaction import Scrubber

# Maximum bytes for stdout/stderr before truncation (mirrors http_utils).
MAX_OUTPUT_BYTES = 10 * 1024  # 10 KB

# ---------------------------------------------------------------------------
# Canary listener constants (SSRF/XXE out-of-band proof, ADR-017)
# ---------------------------------------------------------------------------

#: Env var the activity sets to the listener's tier-specific URL.  The prove
#: agent references this variable in crafted commands; the workflow never sees
#: a literal URL.
CANARY_URL_ENV = "QUARRY_CANARY_URL"
#: Env var carrying the token into the Tier-2 sidecar listener process.
CANARY_TOKEN_ENV = "QUARRY_CANARY_TOKEN"
#: Env var carrying the listener's self-terminate TTL (seconds).
CANARY_TTL_ENV = "QUARRY_CANARY_TTL"
#: Default listener lifetime; it self-terminates after this without a stop.
CANARY_TTL_SECONDS = 300
#: Container-internal port the Tier-2 sidecar listens on.
CANARY_CONTAINER_PORT = 9999
#: Default runtime image for the Tier-2 canary sidecar.
CANARY_DEFAULT_IMAGE = "python:3.12-slim"
#: stdout marker the sidecar prints once its listener is accepting connections.
CANARY_READY_MARKER = "CANARY_READY"
#: How long to wait for the Tier-2 sidecar to report readiness.
CANARY_READY_TIMEOUT_SECONDS = 30.0

#: A Tier-1 stop callable: shuts the listener down and returns its callbacks.
CanaryStop = Callable[[], list[CanaryCallback]]


# ---------------------------------------------------------------------------
# Public helpers (testable independently, mirroring dynamic_http)
# ---------------------------------------------------------------------------


def scrub_and_wrap_output(text: str, *, scrubber: Scrubber | None = None) -> str:
    """Scrub *text* and wrap in ``<target_content>`` tags.

    Sandbox stdout/stderr is attacker-controlled content.  Mandatory scrub +
    wrap before re-entering any model prompt — no fallback.
    """
    s = scrubber or Scrubber()
    result = s.scrub(text)
    return f"<target_content>{result.text}</target_content>"


def build_scrubber_with_creds(resolved_env: dict[str, str]) -> Scrubber:
    """Return a Scrubber with all resolved credential VALUES pre-registered.

    The agent only ever sees the credential PROFILE NAME.  The actual secret
    value lives in resolved_env (QUARRY_INJECTED_CRED_*) and is registered here
    so any echo/leak in stdout/stderr is automatically redacted before the
    capture ever touches a prompt.
    """
    scrubber = Scrubber()
    for value in resolved_env.values():
        if value:
            scrubber.register_secret(value)
    return scrubber


def _resolve_credentials(auth_profile_set_json: str | None) -> dict[str, str]:
    """Resolve named auth profiles to QUARRY_INJECTED_CRED_* env vars.

    Returns a dict of env-var-name -> raw-secret-value.  This dict is passed to
    the sandbox as resolved_env AND registered in the Scrubber BEFORE exec.

    Env var names follow the convention QUARRY_INJECTED_CRED_<PROFILE_NAME_UPPER>
    where hyphens and spaces in the profile name are replaced with underscores.

    Raw secret values (not formatted header strings like "Bearer tok") are used
    so build_scrubber_with_creds registers the minimal substring that the
    scrubber must catch.
    """
    if not auth_profile_set_json:
        return {}

    import os as _os

    from quarry.schemas import AuthProfileKind, AuthProfileSet
    from quarry_activities.credentials import CredentialCache, resolve_credentials

    auth_set = AuthProfileSet.model_validate_json(auth_profile_set_json)
    cache = CredentialCache("sandbox-exec")
    scrubber = Scrubber()
    env: dict[str, str] = {}

    for profile in auth_set.profiles:
        cred = resolve_credentials(
            profile,
            cache,
            scrubber,
            allowed_hosts=(),
            target_host="localhost",
            target_port=80,
        )
        if cred is None:
            continue
        env_key = f"QUARRY_INJECTED_CRED_{profile.name.upper().replace('-', '_').replace(' ', '_')}"
        if profile.kind != AuthProfileKind.LOGIN_FLOW and profile.secret_ref is not None:
            # Raw secret so the scrubber catches bare leakage in stdout/stderr.
            # resolve_credentials already validated the env var is present.
            env[env_key] = _os.environ[profile.secret_ref.env]
        else:
            # LOGIN_FLOW has no simple secret_ref; use the resolved header_value.
            env[env_key] = cred.header_value

    return env


def build_sandbox_backend() -> SandboxBackend:
    """Return the configured SandboxBackend.

    Reads QUARRY_SANDBOX_BACKEND (via QuarrySettings):
      ""  / "local"     — LocalSubprocessSandbox (default; dev/test, no Docker)
      "container"       — ContainerSandbox Tier 2 (Docker/Podman; production default)
      "k8s_job"         — K8sJobSandbox Tier 3 (deferred; raises NotImplementedError)

    QUARRY_SANDBOX_IMAGE overrides the default container image for the container tier.
    QUARRY_SANDBOX_MEMORY overrides the container memory cap (Docker ``--memory``
    value, e.g. "2g"); empty => the ``ContainerSandbox`` default.
    """
    settings = QuarrySettings()
    backend = (settings.sandbox_backend or "").lower().strip()
    if backend in ("", "local"):
        return LocalSubprocessSandbox()
    if backend == "container":
        image = settings.sandbox_image or ContainerSandbox.DEFAULT_IMAGE
        memory_limit = settings.sandbox_memory or None
        return ContainerSandbox(image=image, memory_limit=memory_limit)
    if backend == "k8s_job":
        return K8sJobSandbox()
    msg = (
        f"Unknown QUARRY_SANDBOX_BACKEND='{backend}'. "
        "Valid values: '' (or 'local'), 'container', 'k8s_job' (deferred)."
    )
    raise ValueError(msg)


def _resolve_policy_json(policy_json: str | None) -> ResolvedEgressPolicy | None:
    """Reconstruct and resolve an ``EgressPolicy`` from its serialized form.

    Domains are resolved to IPs exactly once here (the enforcement boundary),
    so every tier receives a frozen :class:`ResolvedEgressPolicy`.  Returns
    None when there is no policy or it declares no destinations (no egress).
    """
    if not policy_json:
        return None
    policy = EgressPolicy.model_validate_json(policy_json)
    if policy.is_empty():
        return None
    return resolve_egress_policy(policy)


def _target_host_ips(policy: ResolvedEgressPolicy | None) -> list[str]:
    """Return the pinned ``target-host`` IPs from *policy* (empty when absent)."""
    if policy is None:
        return []
    for ds in policy.destination_sets:
        if ds.name == TARGET_HOST:
            return list(ds.allowed_ips)
    return []


# ---------------------------------------------------------------------------
# Canary listener (Tier 1 in-process, Tier 2 sidecar)
# ---------------------------------------------------------------------------


class _CanaryHTTPServer(http.server.HTTPServer):
    """Loopback-only canary listener used by Tier 1 (logging-only).

    Records one :class:`CanaryCallback` per request and answers a fixed JSON
    body.  It never stores request headers or body content.
    """

    def __init__(self, addr: tuple[str, int], token: str) -> None:
        self.token = token
        self.callbacks: list[CanaryCallback] = []
        self._lock = threading.Lock()
        super().__init__(addr, _CanaryRequestHandler)

    def record(self, *, method: str, path: str, source_ip: str) -> None:
        callback = CanaryCallback(
            timestamp=datetime.now(UTC).isoformat(),
            method=method,
            path=path,
            source_ip=source_ip,
        )
        with self._lock:
            self.callbacks.append(callback)

    def snapshot(self) -> list[CanaryCallback]:
        with self._lock:
            return list(self.callbacks)


class _CanaryRequestHandler(http.server.BaseHTTPRequestHandler):
    """Logs only method/path/source_ip/timestamp; never echoes request content."""

    @property
    def _canary_server(self) -> _CanaryHTTPServer:
        return cast("_CanaryHTTPServer", self.server)

    def _handle(self) -> None:
        # Length-cap the request-controlled path before it is stored.
        self._canary_server.record(
            method=self.command,
            path=self.path[:CANARY_PATH_MAX_CHARS],
            source_ip=self.client_address[0],
        )
        # Drain any body WITHOUT storing it (no echo, no proxy).
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(length)

        body = json.dumps({"token": self._canary_server.token}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_PATCH = _handle

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence the default stderr access log (it would echo request lines)."""


def _start_canary_local(
    token: str,
    *,
    bind_host: str = "127.0.0.1",
) -> tuple[int, CanaryStop]:
    """Start a Tier-1 loopback canary listener; return ``(port, stop_fn)``.

    Binds ``127.0.0.1`` on an ephemeral port in the worker process and logs every
    request (logging-only — loopback callbacks never corroborate).  A bind to any
    address other than ``127.0.0.1`` fails closed with :class:`EgressPolicyError`
    before the listener is left running.  The returned stop callable shuts the
    listener down and returns the callbacks collected so far.
    """
    if bind_host != "127.0.0.1":
        msg = (
            f"Tier-1 canary listener must bind 127.0.0.1 only, got '{bind_host}'. "
            "Refusing to start a listener on a non-loopback interface."
        )
        raise EgressPolicyError(msg)

    try:
        server = _CanaryHTTPServer((bind_host, 0), token)
    except OSError as exc:
        msg = f"failed to start Tier-1 canary listener on 127.0.0.1: {exc}"
        raise EgressPolicyError(msg) from exc

    bound_host = str(server.server_address[0])
    if bound_host != "127.0.0.1":
        with contextlib.suppress(Exception):
            server.server_close()
        msg = (
            f"Tier-1 canary listener bound '{bound_host}', expected '127.0.0.1'. "
            "Failing closed and leaving no listener running."
        )
        raise EgressPolicyError(msg)

    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    timer = threading.Timer(CANARY_TTL_SECONDS, server.shutdown)
    timer.daemon = True
    timer.start()

    def stop() -> list[CanaryCallback]:
        timer.cancel()
        with contextlib.suppress(Exception):
            server.shutdown()
        with contextlib.suppress(Exception):
            server.server_close()
        thread.join(timeout=5)
        return server.snapshot()

    return port, stop


def _canary_listener_script() -> str:
    """Return the Tier-2 sidecar's minimal HTTP listener source.

    The script logs every request as one ``{"method","path","source_ip",
    "timestamp"}`` JSON line to stdout (path capped), answers
    ``{"token": "<TOKEN>"}`` (200 OK), never logs headers or body, and
    self-terminates after ``QUARRY_CANARY_TTL`` seconds.
    """
    return textwrap.dedent(
        """
        import datetime
        import http.server
        import json
        import os
        import signal
        import sys
        import threading

        TOKEN = os.environ["QUARRY_CANARY_TOKEN"]
        TTL = int(os.environ.get("QUARRY_CANARY_TTL", "300"))
        MAX_PATH = 2048


        class Handler(http.server.BaseHTTPRequestHandler):
            def _respond(self):
                record = {
                    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                    "method": self.command,
                    "path": self.path[:MAX_PATH],
                    "source_ip": self.client_address[0],
                }
                sys.stdout.write(json.dumps(record) + "\\n")
                sys.stdout.flush()
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                if length > 0:
                    self.rfile.read(length)
                body = json.dumps({"token": TOKEN}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _respond
            do_POST = _respond
            do_PUT = _respond
            do_DELETE = _respond
            do_HEAD = _respond
            do_PATCH = _respond

            def log_message(self, *args):
                pass


        server = http.server.HTTPServer(("0.0.0.0", 9999), Handler)


        def _handle_stop(*_args):
            # PID 1 in a container ignores default-action signals, so install a
            # handler that exits promptly on `docker stop` (SIGTERM).
            raise SystemExit(0)


        signal.signal(signal.SIGTERM, _handle_stop)
        threading.Timer(TTL, server.shutdown).start()
        sys.stdout.write("CANARY_READY\\n")
        sys.stdout.flush()
        server.serve_forever()
        """
    ).strip()


def _canary_host_address() -> str:
    """Return the pinned host interface the Tier-2 sidecar publishes on.

    Read from ``QUARRY_CANARY_HOST``; empty (or a wildcard) means no single
    pinned interface is configured, which fails closed — the canary must never
    be published on ``0.0.0.0``.
    """
    from quarry.config import QuarrySettings

    return (QuarrySettings().canary_host or "").strip()


def _published_canary_port(container_id: str) -> int:
    """Read back the OS-assigned host port Docker mapped for the sidecar."""
    proc = subprocess.run(
        ["docker", "port", container_id, str(CANARY_CONTAINER_PORT)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        msg = f"could not read the published canary port for container '{container_id}'"
        raise EgressPolicyError(msg)
    first_line = proc.stdout.strip().splitlines()[0]
    try:
        return int(first_line.rsplit(":", 1)[-1])
    except (ValueError, IndexError) as exc:
        msg = f"unexpected `docker port` output for canary sidecar: {first_line!r}"
        raise EgressPolicyError(msg) from exc


def _wait_for_canary_ready(
    container_id: str,
    *,
    timeout: float = CANARY_READY_TIMEOUT_SECONDS,
) -> None:
    """Poll the sidecar's stdout until it reports its listener is accepting.

    ``docker run -d`` returns before the in-container python has bound its
    socket, so a request sent immediately after start can be connection-reset.
    Waiting for the marker makes the published URL usable when returned.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if CANARY_READY_MARKER in (logs.stdout + logs.stderr):
                return
        time.sleep(0.2)
    msg = f"canary sidecar '{container_id}' did not become ready within {timeout:.0f}s"
    raise EgressPolicyError(msg)


def _start_canary_host(token: str) -> tuple[str, str]:
    """Start the Tier-2 canary sidecar; return ``(container_id, url)``.

    Publishes the listener on a single pinned host interface (not ``0.0.0.0``) on
    a race-free ephemeral port (Docker assigns the host port; the activity reads
    it back).  The external target reaches it at ``http://<host>:<port>/<token>``.
    """
    host = _canary_host_address()
    if not host or host in {"0.0.0.0", "::"}:
        msg = (
            "Tier-2 canary listener requires a single pinned host interface "
            "(QUARRY_CANARY_HOST); refusing to publish the canary on a wildcard "
            "address."
        )
        raise EgressPolicyError(msg)

    from quarry.config import QuarrySettings

    image = QuarrySettings().canary_image or CANARY_DEFAULT_IMAGE
    container_name = f"quarry-canary-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "--stop-timeout",
        str(CANARY_TTL_SECONDS),
        "-e",
        f"{CANARY_TOKEN_ENV}={token}",
        "-e",
        f"{CANARY_TTL_ENV}={CANARY_TTL_SECONDS}",
        "-p",
        f"{host}::{CANARY_CONTAINER_PORT}",
        image,
        "python",
        "-c",
        _canary_listener_script(),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        msg = f"failed to start Tier-2 canary sidecar: {proc.stderr.strip()}"
        raise EgressPolicyError(msg)
    container_id = proc.stdout.strip()
    # No --rm: the sidecar is stopped explicitly so its stdout log survives to be
    # collected (`docker logs` on an auto-removed container returns nothing).
    try:
        _wait_for_canary_ready(container_id)
        port = _published_canary_port(container_id)
    except Exception:
        with contextlib.suppress(Exception):
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                text=True,
                timeout=15,
            )
        raise
    return container_id, f"http://{host}:{port}/{token}"


def _parse_canary_logs(text: str) -> list[CanaryCallback]:
    """Parse the listener's JSON-line stdout into :class:`CanaryCallback` entries."""
    callbacks: list[CanaryCallback] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        record = cast("dict[str, Any]", data)
        callbacks.append(
            CanaryCallback(
                timestamp=str(record.get("timestamp", "")),
                method=str(record.get("method", "")),
                path=str(record.get("path", "")),
                source_ip=str(record.get("source_ip", "")),
            )
        )
    return callbacks


def _collect_canary_logs(listener: CanaryStop | str) -> list[CanaryCallback]:
    """Stop the listener and return the callbacks it logged.

    *listener* is the Tier-1 stop callable or the Tier-2 container id whose
    stdout log is parsed.
    """
    if isinstance(listener, str):
        return _collect_canary_logs_container(listener)
    return listener()


def _collect_canary_logs_container(container_id: str) -> list[CanaryCallback]:
    """Stop a Tier-2 sidecar, parse its stdout log, then remove it."""
    # -t bounds the graceful-stop wait so a wedged sidecar cannot stall teardown.
    with contextlib.suppress(Exception):
        subprocess.run(
            ["docker", "stop", "-t", "10", container_id],
            capture_output=True,
            text=True,
            timeout=30,
        )
    logs = subprocess.run(
        ["docker", "logs", container_id],
        capture_output=True,
        text=True,
        timeout=30,
    )
    with contextlib.suppress(Exception):
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True,
            text=True,
            timeout=15,
        )
    return _parse_canary_logs(logs.stdout)


def _start_canary_listener(
    sandbox: SandboxBackend,
    token: str,
) -> tuple[CanaryStop | str, dict[str, str]]:
    """Start the tier-appropriate canary listener and return (source, env).

    The returned env carries ``QUARRY_CANARY_URL`` for the sandbox command.  The
    source is a stop callable (Tier 1) or a container id (Tier 2) for
    :func:`_collect_canary_logs`.
    """
    if isinstance(sandbox, LocalSubprocessSandbox):
        port, stop = _start_canary_local(token)
        return stop, {CANARY_URL_ENV: f"http://127.0.0.1:{port}/{token}"}
    if isinstance(sandbox, ContainerSandbox):
        container_id, url = _start_canary_host(token)
        return container_id, {CANARY_URL_ENV: url}
    msg = "canary listener is unsupported on this sandbox tier"
    raise EgressPolicyError(msg)


def _run_sandbox(
    spec: SandboxExecSpec,
    *,
    sandbox: SandboxBackend,
    work_dir: Path,
    resolved_env: dict[str, str],
    egress_policy: ResolvedEgressPolicy | None,
    canary_active: bool = False,
) -> SandboxResult:
    """Thin shim — lets tests patch at a single point without mocking subprocess."""
    return sandbox.run(
        spec,
        work_dir=work_dir,
        resolved_env=resolved_env,
        egress_policy=egress_policy,
        canary_active=canary_active,
    )


# ---------------------------------------------------------------------------
# Activity (sync — runs in the thread-pool worker, not async)
# ---------------------------------------------------------------------------


@activity.defn(name="sandbox-exec")
def sandbox_exec_activity(inp: SandboxExecActivityInput) -> SandboxExecCapture:
    """Execute a sandboxed command and return a scrubbed SandboxExecCapture."""
    spec = SandboxExecSpec.model_validate_json(inp.spec_json)

    # Resolve credentials worker-side; register values in Scrubber BEFORE exec.
    resolved_env = _resolve_credentials(inp.auth_profile_set_json)
    run_scrubber = build_scrubber_with_creds(resolved_env)

    egress_policy = _resolve_policy_json(inp.egress_policy_json)

    store = build_artifact_store(inp.artifact_store_path)
    sandbox = build_sandbox_backend()

    # Tier 1 is CLI-only: it cannot enforce a destination-set policy (no
    # kernel-enforced network namespace), so a live-target dispatch is scoped to
    # no egress (fail-closed) instead of raising EgressPolicyError.  The
    # resolved target IPs then stay empty for Tier 1, which structurally keeps
    # canary corroboration Tier-2-only (a loopback callback presents
    # 127.0.0.1 and can never match a resolved target IP).
    if isinstance(sandbox, LocalSubprocessSandbox):
        egress_policy = None
    resolved_target_ips = _target_host_ips(egress_policy)

    # SSRF/XXE canary: start the listener before the sandbox command, set
    # QUARRY_CANARY_URL in its environment, and collect callbacks afterwards.
    canary_token = inp.canary_token or None
    canary_source: CanaryStop | str | None = None
    sandbox_env = dict(resolved_env)
    if canary_token:
        canary_source, canary_env = _start_canary_listener(sandbox, canary_token)
        sandbox_env.update(canary_env)

    with tempfile.TemporaryDirectory(prefix="quarry-sandbox-") as _work_dir:
        work_dir = Path(_work_dir)

        try:
            result = _run_sandbox(
                spec,
                sandbox=sandbox,
                work_dir=work_dir,
                resolved_env=sandbox_env,
                egress_policy=egress_policy,
                canary_active=canary_token is not None,
            )
        finally:
            # Stop the listener (or TTL-expired sidecar) and collect its log —
            # including on sandbox timeout, so pre-timeout callbacks survive.
            canary_callbacks = (
                _collect_canary_logs(canary_source) if canary_source is not None else []
            )

    # Cap then scrub then wrap each stream.
    raw_stdout = _cap(result.stdout, MAX_OUTPUT_BYTES)
    raw_stderr = _cap(result.stderr, MAX_OUTPUT_BYTES)

    stdout_scrub = run_scrubber.scrub(raw_stdout)
    stderr_scrub = run_scrubber.scrub(raw_stderr)

    scrubber_hits = stdout_scrub.hits + stderr_scrub.hits
    redaction_status = (
        RedactionStatus.REDACTED if scrubber_hits > 0 else RedactionStatus.NOT_REQUIRED
    )

    wrapped_stdout = f"<target_content>{stdout_scrub.text}</target_content>"
    wrapped_stderr = f"<target_content>{stderr_scrub.text}</target_content>"

    stdout_outcome = put_quarantined_artifact(
        store,
        f"{inp.scan_id}/{inp.candidate_finding_id}/stdout",
        wrapped_stdout.encode("utf-8"),
        kind=ArtifactKind.TOOL_STDOUT,
        content_type="text/plain",
        redaction_status=redaction_status,
        scan_id=inp.scan_id,
    )
    stderr_outcome = put_quarantined_artifact(
        store,
        f"{inp.scan_id}/{inp.candidate_finding_id}/stderr",
        wrapped_stderr.encode("utf-8"),
        kind=ArtifactKind.TOOL_STDERR,
        content_type="text/plain",
        redaction_status=redaction_status,
        scan_id=inp.scan_id,
    )
    stdout_ref = stdout_outcome.artifact_ref
    stderr_ref = stderr_outcome.artifact_ref

    return SandboxExecCapture(
        exit_code=result.exit_code,
        stdout_artifact_ref=stdout_ref.id,
        stderr_artifact_ref=stderr_ref.id,
        elapsed_ms=result.elapsed_ms,
        scrubber_hits=scrubber_hits,
        redaction_status=redaction_status,
        timed_out=result.timed_out,
        canary_callbacks=canary_callbacks,
        resolved_target_ips=resolved_target_ips,
        artifact_refs=[stdout_ref, stderr_ref],
    )


def _cap(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")
