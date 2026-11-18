"""SandboxBackend Protocol and tier implementations (ADR-017 §5, ADR-024 §A).

Three tiers are defined here; only Tier 1 runs in-process today:

  Tier 1  LocalSubprocessSandbox  — subprocess + POSIX rlimits (dev/wiring only)
  Tier 2  ContainerSandbox        — throwaway container on a restricted network
  Tier 3  K8sJobSandbox           — K8s Job + NetworkPolicy (deferred, stub)

**Egress model:** every tier takes an ``egress_policy: ResolvedEgressPolicy | None``
— a destination-set policy with deny-all-else.  A ``None`` or empty policy means
"no egress intended".  The policy is resolved (domains pinned to IPs) once before
it reaches a tier, so no tier ever re-resolves a destination (DNS-rebinding guard,
see :mod:`quarry.egress`).

**Isolation caveat (Tier 1):** LocalSubprocessSandbox provides *resource*
containment (RLIMIT_CPU / RLIMIT_AS / RLIMIT_NPROC) and no-network-by-convention,
but it does NOT provide a kernel-enforced network namespace on macOS/Colima
(ADR-024 §A: "dev/wiring only").  It therefore *refuses* any non-empty egress
policy with :class:`~quarry.egress.EgressPolicyError` rather than pretending to
enforce one.  Production network containment is ContainerSandbox (Tier 2) or
K8sJobSandbox + NetworkPolicy (Tier 3).

See ADR-017 §5 and ADR-024 §A for the full tier rationale.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

from pydantic import BaseModel

from quarry.egress import EgressPolicyError
from quarry.schemas import ResolvedEgressPolicy, SandboxExecSpec

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
        egress_policy: ResolvedEgressPolicy | None,
        canary_active: bool = False,
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

    Provides resource containment and no-network-by-convention.  Does NOT provide
    a kernel-enforced network namespace on macOS/Colima, so it cannot enforce a
    destination-set policy: any non-empty ``egress_policy`` is rejected with
    :class:`~quarry.egress.EgressPolicyError`.  Use for wiring/correctness tests
    only; production containment is Tier 2/3.  See module docstring.
    """

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        egress_policy: ResolvedEgressPolicy | None,
        canary_active: bool = False,
    ) -> SandboxResult:
        """Execute spec.command inside work_dir and return captured output.

        ``canary_active`` is accepted for Protocol conformance and ignored: Tier 1
        has no container capabilities to drop (it is CLI-only, no kernel-enforced
        egress — see the class docstring).
        """
        if egress_policy is not None and not egress_policy.is_empty():
            msg = (
                "LocalSubprocessSandbox (Tier 1) cannot enforce a destination-set "
                "egress policy — it has no kernel-enforced network namespace "
                "(ADR-024 §A: dev/wiring only). Refusing a non-empty egress policy "
                "rather than running with unrestricted egress. Use ContainerSandbox "
                "(Tier 2) or K8sJobSandbox (Tier 3)."
            )
            raise EgressPolicyError(msg)

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
# Tier 2 — ContainerSandbox (production default)
# ---------------------------------------------------------------------------

#: Env var carrying the pinned destination IPs into the container for audit.
EGRESS_ALLOWED_IPS_ENV = "QUARRY_EGRESS_ALLOWED_IPS"

#: Prefix of the per-policy restricted Docker network name.
EGRESS_NETWORK_PREFIX = "quarry-egress-"


def egress_network_name(egress_policy: ResolvedEgressPolicy | None) -> str | None:
    """Return the restricted network name for *egress_policy*, or None.

    None means "no egress": either no policy, or a policy whose destination sets
    carry no pinned IPs.  The name is content-addressed by the sorted pinned IPs
    so every run of the same policy reuses one restricted network.
    """
    if egress_policy is None or egress_policy.is_empty():
        return None
    digest = hashlib.sha256(",".join(egress_policy.all_allowed_ips()).encode("utf-8")).hexdigest()
    return f"{EGRESS_NETWORK_PREFIX}{digest[:12]}"


def _verify_internal_network(name: str, inspect_output: str) -> None:
    """Fail closed unless *inspect_output* proves *name* is an internal bridge.

    Docker network names are one global namespace, so an existing network with
    the content-addressed name we expect cannot be trusted: an actor with
    ``docker network create`` access can squat it with an externally routed
    bridge and a naive reuse would grant the sandbox full egress.  Reuse is
    therefore conditional on proof parsed from ``docker network inspect``: the
    output must be a JSON array whose first entry is an object carrying
    ``Internal: true`` (and, when present, ``Driver: "bridge"``).  Any mismatch,
    missing field, or unparseable output raises :class:`~quarry.egress.EgressPolicyError`
    rather than attaching to the network.
    """
    try:
        parsed = json.loads(inspect_output)
    except (json.JSONDecodeError, TypeError):
        msg = (
            f"refusing to reuse Docker network '{name}': `docker network inspect` "
            "output was not valid JSON, so the network could not be verified as "
            "--internal."
        )
        raise EgressPolicyError(msg) from None
    if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
        msg = (
            f"refusing to reuse Docker network '{name}': `docker network inspect` "
            "returned no inspectable network entry to verify."
        )
        raise EgressPolicyError(msg)
    entry: dict[str, Any] = cast("dict[str, Any]", parsed[0])
    if entry.get("Internal") is not True:
        msg = (
            f"refusing to reuse existing Docker network '{name}': it is not an "
            "internal network (Internal != true). A pre-existing network with "
            "the expected content-addressed name may have been squatted and "
            "would grant the sandbox unrestricted egress."
        )
        raise EgressPolicyError(msg)
    driver = entry.get("Driver")
    if driver is not None and driver != "bridge":
        msg = (
            f"refusing to reuse existing Docker network '{name}': unexpected "
            f"driver '{driver}' (expected 'bridge')."
        )
        raise EgressPolicyError(msg)


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

    Provides real kernel isolation without requiring Kubernetes.  The expected
    production default.

    Each ``run()`` call:
      1. Stages ``input_files`` into *work_dir*.
      2. Builds a ``docker run --rm`` command with:
         - ``--network none`` when the egress policy is empty (no egress);
         - otherwise ``--network <restricted>``: a dedicated **internal** Docker
           network carrying only the policy's destination services.  An internal
           network has no external route, so a compromised process can reach the
           declared destinations and nothing else — enforced by the kernel, not
           application code.  The network is created (idempotently) before the
           container starts, and an existing network with the expected name is
           reused **only after** being verified ``--internal`` (a squatted name
           fails closed); the pinned IPs ride along as
           ``QUARRY_EGRESS_ALLOWED_IPS`` for audit.
         - *work_dir* bind-mounted to the same path inside the container.
         - Only cleaned ``resolved_env`` forwarded (no proxy vars).
      3. Runs with a hard timeout cap and captures stdout/stderr.
      4. On timeout: kills the container then returns ``timed_out=True``.
      5. Caps and returns output as a :class:`SandboxResult`.

    ``image`` defaults to ``python:3.12-slim``; override via constructor for
    language-specific minimal runtime images (ADR-024 §A).

    Known residual (accepted): the restricted network is content-addressed per
    policy, so concurrent sandboxes with the *same* pinned ip-union share one
    bridge and can see each other's L2 traffic.  Containers also keep Docker's
    default caps (incl. ``NET_RAW``) because ping-based proof payloads need raw
    sockets.  Reuse is deliberate — a per-run network would diverge from the
    reviewed spec's reuse intent and break the live fixture that pre-creates the
    content-addressed network.  See impl-review F2 (t_987a8d13).
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
        egress_policy: ResolvedEgressPolicy | None,
        canary_active: bool = False,
    ) -> SandboxResult:
        """Execute *spec* inside a throwaway Docker container."""
        _stage_input_files(spec.input_files, work_dir)
        resolved_cwd = _resolve_sandbox_cwd(spec.cwd, work_dir)
        env = _build_safe_env(resolved_env)
        timeout = min(spec.timeout_seconds, HARD_TIMEOUT_SECONDS)

        # Materialize the restricted network (if any) before the container runs.
        network = egress_network_name(egress_policy)
        if network is not None:
            self._ensure_restricted_network(network)

        # Unique name so we can force-kill on timeout without ambiguity.
        container_name = f"quarry-prove-{uuid.uuid4().hex[:12]}"
        docker_cmd = self._build_docker_cmd(
            spec=spec,
            work_dir=work_dir,
            resolved_cwd=resolved_cwd,
            env=env,
            egress_policy=egress_policy,
            network=network,
            container_name=container_name,
            canary_active=canary_active,
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

    def _ensure_restricted_network(self, name: str) -> None:
        """Ensure the internal restricted network *name* exists and stays internal.

        Idempotent by design: the name is content-addressed by the policy's
        pinned IPs, so every run of the same policy reuses one restricted
        network (its membership *is* the egress allow-list, so reuse is
        intended).  Reuse is NOT blind, however.  Docker network names live in a
        single global namespace, so an actor able to run ``docker network
        create`` can pre-create the expected ``quarry-egress-*`` name as an
        *external* bridge; reusing it unverified would silently hand the sandbox
        full outbound egress, defeating the containment primitive.  A present
        network is therefore only reused after it proves it is ``--internal``
        (:func:`_verify_internal_network`); a mismatch fails closed with
        :class:`~quarry.egress.EgressPolicyError` — never a silent reuse.

        A failing ``inspect`` (absent, or Docker unavailable) is left for
        ``docker run`` to surface when it tries to attach; there is no network
        to verify in that case.
        """
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            inspect = subprocess.run(
                ["docker", "network", "inspect", name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if inspect.returncode == 0:
                _verify_internal_network(name, inspect.stdout)
                return
            # Absent — create it internal, then re-inspect and verify so a
            # network that appears in the create→attach window (a name-squat
            # race) is still checked rather than trusted.
            subprocess.run(
                ["docker", "network", "create", "--internal", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            reinspect = subprocess.run(
                ["docker", "network", "inspect", name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if reinspect.returncode == 0:
                _verify_internal_network(name, reinspect.stdout)

    def _build_docker_cmd(
        self,
        *,
        spec: SandboxExecSpec,
        work_dir: Path,
        resolved_cwd: Path,
        env: dict[str, str],
        egress_policy: ResolvedEgressPolicy | None,
        network: str | None,
        container_name: str,
        canary_active: bool = False,
    ) -> list[str]:
        cmd = ["docker", "run", "--rm", "--name", container_name]

        # While a canary is active the sandbox must not be able to raw-craft a
        # spoofed source IP toward the canary (the source-IP filter is the
        # containment invariant, so spoofing it would forge corroboration).
        # Ping-based proofs without a canary keep their raw sockets.
        if canary_active:
            cmd += ["--cap-drop", "NET_RAW", "--cap-drop", "NET_ADMIN"]

        if network is None:
            # No egress: kernel-enforced network namespace with no routes.
            cmd += ["--network", "none"]
        else:
            # Restricted internal network: only the declared destinations are
            # reachable; the network has no external route.  The pinned IPs are
            # carried into the container for audit.
            allowed = ",".join(egress_policy.all_allowed_ips()) if egress_policy else ""
            cmd += ["--network", network]
            cmd += ["-e", f"{EGRESS_ALLOWED_IPS_ENV}={allowed}"]

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


def _ip_block_cidr(ip: str) -> str:
    """Render *ip* as a single-host CIDR block for a NetworkPolicy ``ipBlock``."""
    addr = ipaddress.ip_address(ip)
    return f"{ip}/{addr.max_prefixlen}"


def build_network_policy(
    egress_policy: ResolvedEgressPolicy,
    *,
    name: str = "quarry-sandbox-egress",
    pod_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Render *egress_policy* as a Kubernetes NetworkPolicy manifest (Tier 3).

    One egress rule per destination set, each listing the set's pinned IPs as
    single-host ``ipBlock`` entries.  ``policyTypes: ["Egress"]`` with a
    ``podSelector`` makes the policy default-deny: only the listed IPs are
    reachable.  An empty policy yields an egress list with no allow rules — i.e.
    deny-all egress.
    """
    egress_rules: list[dict[str, Any]] = []
    for ds in egress_policy.destination_sets:
        if not ds.allowed_ips:
            continue
        egress_rules.append(
            {"to": [{"ipBlock": {"cidr": _ip_block_cidr(ip)}} for ip in ds.allowed_ips]}
        )
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name},
        "spec": {
            "podSelector": {"matchLabels": pod_labels or {}},
            "policyTypes": ["Egress"],
            "egress": egress_rules,
        },
    }


class K8sJobSandbox:
    """Tier-3 sandbox: Kubernetes Job + NetworkPolicy (destination-set egress).

    Reserved for hostile multi-tenant isolation.  Most deployments stop at
    Tier 2 (ContainerSandbox).

    ``run`` is not implemented yet (ADR-017 §5, ADR-024 §A) — the manifest that
    the deferred tier will apply is available now via :func:`build_network_policy`.
    """

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        egress_policy: ResolvedEgressPolicy | None,
        canary_active: bool = False,
    ) -> SandboxResult:
        raise NotImplementedError(
            "K8sJobSandbox is deferred to the CLI hunting follow-on. "
            "See ADR-017 §5, ADR-024 §A, and feat/cli-hunting-path."
        )

    def build_network_policy(
        self,
        egress_policy: ResolvedEgressPolicy,
        *,
        name: str = "quarry-sandbox-egress",
        pod_labels: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Render the tier's egress NetworkPolicy for *egress_policy*."""
        return build_network_policy(egress_policy, name=name, pod_labels=pod_labels)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cap_bytes(text: str, max_bytes: int) -> str:
    """Truncate text so its UTF-8 encoding does not exceed max_bytes."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")
