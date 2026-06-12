"""SandboxBackend Protocol and local-dev implementation (ADR-017 §5).

Three tiers are defined here; only Tier 1 is implemented:

  Tier 1  LocalSubprocessSandbox  — subprocess + POSIX rlimits (this file, build now)
  Tier 2  ContainerSandbox        — throwaway container per invocation  (deferred, stub)
  Tier 3  K8sJobSandbox           — K8s Job + NetworkPolicy (deferred, stub)

**Isolation caveat (Tier 1):**
LocalSubprocessSandbox provides *resource* containment (RLIMIT_CPU / RLIMIT_AS / RLIMIT_NPROC)
and *no-network-by-convention* (scrubbed env, no proxy vars, target_endpoint=None means no
egress is intended), but it does NOT provide a kernel-enforced network namespace on
macOS/Colima.  Use it for wiring/correctness tests only.  Production network containment is
ContainerSandbox (``--network none``) or K8sJobSandbox + NetworkPolicy.

See ADR-017 §5 and ADR-022 for the full tier rationale.
"""

from __future__ import annotations

import contextlib
import subprocess
import time
import uuid
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from quarry.schemas import SandboxExecSpec, TargetEndpoint

# ---------------------------------------------------------------------------
# Security error
# ---------------------------------------------------------------------------


class ToolSecurityError(Exception):
    """Raised when a sandbox request violates a security boundary.

    Caught by sandbox_exec_activity and returned as a refused ToolCallRecord
    (never silently dropped).
    """


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class SandboxResult(BaseModel):
    """Raw result from a SandboxBackend.run() call — pre-scrub, pre-artifact-store.

    The sandbox_exec_activity is responsible for capping, scrubbing, wrapping in
    <target_content>, and storing as TOOL_STDOUT/TOOL_STDERR artifacts before this
    result ever touches a prompt.
    """

    exit_code: int
    stdout: str  # raw, capped to MAX_OUTPUT_BYTES by the backend
    stderr: str  # raw, capped to MAX_OUTPUT_BYTES by the backend
    elapsed_ms: int
    timed_out: bool = False


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SandboxBackend(Protocol):
    """Transport-agnostic sandbox execution primitive.

    Each backend implements this single method.  The workflow, prove agent, and
    PROVE stage are backend-agnostic — they produce a SandboxExecSpec and consume
    a SandboxResult.  Swapping tiers changes no workflow/agent code.
    """

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        target_endpoint: TargetEndpoint | None,
    ) -> SandboxResult: ...


# ---------------------------------------------------------------------------
# Tier 1 — LocalSubprocessSandbox
# ---------------------------------------------------------------------------

# Commands the local sandbox is allowed to execute.  Fail-closed: anything
# not on this list raises ToolSecurityError.  Widening is the CLI follow-on's job.
_COMMAND_ALLOWLIST: frozenset[str] = frozenset(
    {
        "echo",
        "cat",
        "ls",
        "true",
        "false",
        "sh",
        "env",
        "python3",
        "python",
        "uv",
    }
)

# Maximum bytes captured from stdout or stderr before truncation.
MAX_OUTPUT_BYTES: int = 10 * 1024  # 10 KB, mirrors http_utils MAX_RESPONSE_BODY_SIZE

# Hard upper bound on execution time regardless of spec.timeout_seconds.
HARD_TIMEOUT_SECONDS: int = 60

# Env var prefixes that are NEVER inherited from the parent process.
BLOCKED_ENV_PREFIXES: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "FTP_PROXY",
    "ftp_proxy",
)


def _set_rlimits() -> None:
    """preexec_fn: apply POSIX resource limits inside the child process."""
    try:
        import resource

        # 10 s of CPU time
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        # 512 MB virtual address space
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        # 64 child processes
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except (AttributeError, ValueError):
        # resource module not available (Windows); rlimits best-effort only.
        pass


def _resolve_sandbox_cwd(cwd: str, work_dir: Path) -> Path:
    """Resolve *cwd* relative to *work_dir*; reject absolute or escaping paths.

    Shared by all sandbox tiers — the constraint is the same regardless of how
    the command is actually executed.
    """
    cwd_path = Path(cwd)
    if cwd_path.is_absolute():
        msg = (
            f"cwd '{cwd}' is absolute — only paths relative to the sandbox working "
            "dir are permitted."
        )
        raise ToolSecurityError(msg)
    resolved = (work_dir / cwd_path).resolve()
    try:
        resolved.relative_to(work_dir.resolve())
    except ValueError:
        msg = (
            f"cwd '{cwd}' resolves outside the sandbox working dir "
            f"('{work_dir}'). Path escape via '..' is not permitted."
        )
        raise ToolSecurityError(msg) from None
    return resolved


def _stage_input_files(input_files: dict[str, str], work_dir: Path) -> None:
    """Write crafted *input_files* into *work_dir*; reject paths that escape it.

    Shared by all sandbox tiers — attacker-supplied files are always staged into
    the sandbox working dir before execution, and path-escape is always rejected.
    """
    for rel_path, content in input_files.items():
        p = Path(rel_path)
        if p.is_absolute():
            msg = f"input_files path '{rel_path}' is absolute — only relative paths permitted."
            raise ToolSecurityError(msg)
        resolved = (work_dir / p).resolve()
        try:
            resolved.relative_to(work_dir.resolve())
        except ValueError:
            msg = (
                f"input_files path '{rel_path}' resolves outside the sandbox working dir. "
                "Path escape via '..' is not permitted."
            )
            raise ToolSecurityError(msg) from None
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")


def _build_safe_env(resolved_env: dict[str, str]) -> dict[str, str]:
    """Build a minimal, safe environment dict from *resolved_env*.

    Inherits nothing from the parent process.  Only resolved_env values
    (QUARRY_INJECTED_CRED_* and similar) are forwarded.  Proxy vars are
    explicitly excluded so the subprocess/container cannot make unintended
    network calls.  Shared by all sandbox tiers.
    """
    env: dict[str, str] = {}
    env.update(resolved_env)
    for key in list(env):
        if any(key.startswith(prefix) or key == prefix for prefix in BLOCKED_ENV_PREFIXES):
            del env[key]
    return env


def _decode_timeout_stream(raw: bytes | str | None) -> str:
    """Decode the partial output from a TimeoutExpired exception."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw


class LocalSubprocessSandbox:
    """Tier-1 sandbox: subprocess with POSIX rlimits.

    Provides resource containment and no-network-by-convention.
    Does NOT provide a kernel-enforced network namespace on macOS/Colima.
    Use for wiring/correctness tests only.  See module docstring for caveats.
    """

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        target_endpoint: TargetEndpoint | None,
    ) -> SandboxResult:
        """Execute spec.command inside work_dir and return captured output."""
        self._validate_command(spec.command)
        resolved_cwd = _resolve_sandbox_cwd(spec.cwd, work_dir)
        _stage_input_files(spec.input_files, work_dir)
        env = _build_safe_env(resolved_env)
        timeout = min(spec.timeout_seconds, HARD_TIMEOUT_SECONDS)

        cmd = [spec.command, *spec.args]
        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(resolved_cwd),
                env=env,
                input=spec.stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                preexec_fn=_set_rlimits,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = _decode_timeout_stream(exc.stdout)
            stderr = _decode_timeout_stream(exc.stderr)
            exit_code = 124  # conventional timeout exit code (same as GNU timeout)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Cap output before it leaves the sandbox layer.
        stdout = _cap_bytes(stdout, MAX_OUTPUT_BYTES)
        stderr = _cap_bytes(stderr, MAX_OUTPUT_BYTES)

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            elapsed_ms=elapsed_ms,
            timed_out=timed_out,
        )

    def _validate_command(self, command: str) -> None:
        if command not in _COMMAND_ALLOWLIST:
            msg = (
                f"Command '{command}' is not on the sandbox allowlist. "
                "Only explicitly permitted commands may be executed. "
                f"Permitted: {sorted(_COMMAND_ALLOWLIST)}"
            )
            raise ToolSecurityError(msg)


# ---------------------------------------------------------------------------
# Tier 2 — ContainerSandbox (deferred, production default)
# ---------------------------------------------------------------------------


def _kill_container(container_name: str) -> None:
    """Best-effort cleanup: forcibly remove a Docker container by name.

    Called after a TimeoutExpired so the container does not linger.
    Errors are swallowed — cleanup failure must never surface to callers.
    """
    with contextlib.suppress(Exception):
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            timeout=10,
        )


class ContainerSandbox:
    """Tier-2 sandbox: one throwaway container per invocation (Docker/Podman).

    Provides real kernel isolation (``--network none`` for CLI prove) without
    requiring Kubernetes.  The expected production default.

    Each ``run()`` call:
      1. Stages ``input_files`` into *work_dir*.
      2. Builds a ``docker run --rm`` command with:
         - ``--network none`` when no *target_endpoint* (CLI prove).
         - *work_dir* bind-mounted to the same path inside the container.
         - Only cleaned ``resolved_env`` forwarded (no proxy vars).
      3. Runs with a hard timeout cap and captures stdout/stderr.
      4. On timeout: kills the container then returns ``timed_out=True``.
      5. Caps and returns output as a :class:`SandboxResult`.

    Live egress (Docker network attachment when *target_endpoint* is provided)
    is deferred to the live-egress follow-on.  See ADR-022 §A.

    ``image`` defaults to ``python:3.12-slim``; override via constructor for
    language-specific minimal runtime images (ADR-022 §A).
    """

    # Default runtime image — minimal, no build toolchain.
    DEFAULT_IMAGE: str = "python:3.12-slim"

    def __init__(self, image: str = DEFAULT_IMAGE) -> None:
        self._image = image

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        target_endpoint: TargetEndpoint | None,
    ) -> SandboxResult:
        """Execute *spec* inside a throwaway Docker container."""
        _stage_input_files(spec.input_files, work_dir)
        resolved_cwd = _resolve_sandbox_cwd(spec.cwd, work_dir)
        env = _build_safe_env(resolved_env)
        timeout = min(spec.timeout_seconds, HARD_TIMEOUT_SECONDS)

        # Unique name so we can force-kill on timeout without ambiguity.
        container_name = f"quarry-prove-{uuid.uuid4().hex[:12]}"
        docker_cmd = self._build_docker_cmd(
            spec=spec,
            work_dir=work_dir,
            resolved_cwd=resolved_cwd,
            env=env,
            target_endpoint=target_endpoint,
            container_name=container_name,
        )

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                docker_cmd,
                input=spec.stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = _decode_timeout_stream(exc.stdout)
            stderr = _decode_timeout_stream(exc.stderr)
            exit_code = 124  # conventional timeout exit code (same as GNU timeout)
            _kill_container(container_name)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        stdout = _cap_bytes(stdout, MAX_OUTPUT_BYTES)
        stderr = _cap_bytes(stderr, MAX_OUTPUT_BYTES)

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            elapsed_ms=elapsed_ms,
            timed_out=timed_out,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_docker_cmd(
        self,
        *,
        spec: SandboxExecSpec,
        work_dir: Path,
        resolved_cwd: Path,
        env: dict[str, str],
        target_endpoint: TargetEndpoint | None,
        container_name: str,
    ) -> list[str]:
        cmd = ["docker", "run", "--rm", "--name", container_name]

        if target_endpoint is None:
            # CLI prove: deny all egress with kernel-enforced network namespace.
            cmd += ["--network", "none"]
        # else: live egress wiring (Docker network attachment) is deferred to
        # the live-egress follow-on.  The target_endpoint parameter is accepted
        # but not yet wired.
        # TODO(live-egress): attach container to a restricted Docker network when
        # target_endpoint is set (ref: ADR-017, ADR-022 §A).

        # Bind-mount work_dir to the same path in the container so relative
        # resolved_cwd values remain valid inside the container.
        work_dir_str = str(work_dir)
        cmd += ["-v", f"{work_dir_str}:{work_dir_str}"]
        cmd += ["-w", str(resolved_cwd)]

        # Forward cleaned env vars one by one (no proxy leakage).
        for key, val in env.items():
            cmd += ["-e", f"{key}={val}"]

        # Image + command + args
        cmd += [self._image, spec.command, *spec.args]
        return cmd


# ---------------------------------------------------------------------------
# Tier 3 — K8sJobSandbox (deferred, high-isolation/multi-tenant)
# ---------------------------------------------------------------------------


class K8sJobSandbox:
    """Tier-3 sandbox: Kubernetes Job + NetworkPolicy (deny-all egress).

    Reserved for hostile multi-tenant isolation.  Most deployments stop at
    Tier 2 (ContainerSandbox).

    Not implemented yet.  See ADR-017 §5 and ADR-022 §A.
    """

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        target_endpoint: TargetEndpoint | None,
    ) -> SandboxResult:
        raise NotImplementedError(
            "K8sJobSandbox is deferred to the CLI hunting follow-on. "
            "See ADR-017 §5, ADR-022 §A, and feat/cli-hunting-path."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cap_bytes(text: str, max_bytes: int) -> str:
    """Truncate text so its UTF-8 encoding does not exceed max_bytes."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")
