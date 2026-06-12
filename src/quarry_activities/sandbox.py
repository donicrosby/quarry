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

import subprocess
import time
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
_MAX_OUTPUT_BYTES: int = 10 * 1024  # 10 KB, mirrors http_utils MAX_RESPONSE_BODY_SIZE

# Hard upper bound on execution time regardless of spec.timeout_seconds.
_HARD_TIMEOUT_SECONDS: int = 60

# Env var prefixes that are NEVER inherited from the parent process.
_BLOCKED_ENV_PREFIXES: tuple[str, ...] = (
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
        resolved_cwd = self._resolve_cwd(spec.cwd, work_dir)
        self._stage_input_files(spec.input_files, work_dir)
        env = self._build_env(resolved_env)
        timeout = min(spec.timeout_seconds, _HARD_TIMEOUT_SECONDS)

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
            stdout = (
                (exc.stdout or b"").decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = (
                (exc.stderr or b"").decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            exit_code = 124  # conventional timeout exit code (same as GNU timeout)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Cap output before it leaves the sandbox layer.
        stdout = _cap_bytes(stdout, _MAX_OUTPUT_BYTES)
        stderr = _cap_bytes(stderr, _MAX_OUTPUT_BYTES)

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

    def _validate_command(self, command: str) -> None:
        if command not in _COMMAND_ALLOWLIST:
            msg = (
                f"Command '{command}' is not on the sandbox allowlist. "
                "Only explicitly permitted commands may be executed. "
                f"Permitted: {sorted(_COMMAND_ALLOWLIST)}"
            )
            raise ToolSecurityError(msg)

    def _resolve_cwd(self, cwd: str, work_dir: Path) -> Path:
        """Resolve cwd relative to work_dir; reject absolute or escaping paths."""
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

    def _stage_input_files(self, input_files: dict[str, str], work_dir: Path) -> None:
        """Write crafted input_files into work_dir; reject paths that escape it."""
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

    def _build_env(self, resolved_env: dict[str, str]) -> dict[str, str]:
        """Build a minimal, safe environment for the subprocess.

        Inherits nothing from the parent process.  Only resolved_env values
        (QUARRY_INJECTED_CRED_* and similar) are forwarded.  Proxy vars are
        explicitly excluded so the subprocess cannot make network calls.
        """
        env: dict[str, str] = {}
        # Forward only the explicitly-resolved credentials; no other inheritance.
        env.update(resolved_env)
        # Ensure no proxy variables leak in even if caller accidentally included them.
        for key in list(env):
            if any(key.startswith(prefix) or key == prefix for prefix in _BLOCKED_ENV_PREFIXES):
                del env[key]
        return env


# ---------------------------------------------------------------------------
# Tier 2 — ContainerSandbox (deferred, production default)
# ---------------------------------------------------------------------------


class ContainerSandbox:
    """Tier-2 sandbox: one throwaway container per invocation (Docker/Podman).

    Provides real kernel isolation (``--network none`` for CLI prove) without
    requiring Kubernetes.  The expected production default.

    Not implemented yet.  See ADR-022 §A (feat/cli-hunting-path follow-on).
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
            "ContainerSandbox is deferred to the CLI hunting follow-on. "
            "See ADR-022 §A and feat/cli-hunting-path."
        )


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
