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

import tempfile
from pathlib import Path

from quarry.schemas import (
    ArtifactKind,
    RedactionStatus,
    SandboxExecCapture,
    SandboxExecSpec,
    TargetEndpoint,
)
from quarry_activities.inputs import SandboxExecActivityInput
from quarry_activities.sandbox import (
    ContainerSandbox,
    K8sJobSandbox,
    LocalSubprocessSandbox,
    SandboxBackend,
    SandboxResult,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.redaction import Scrubber

# Maximum bytes for stdout/stderr before truncation (mirrors http_utils).
MAX_OUTPUT_BYTES = 10 * 1024  # 10 KB


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

    Returns a dict of env-var-name → secret-value.  This dict is passed to
    the sandbox as resolved_env AND registered in the Scrubber BEFORE exec.

    For the current scope (no auth_profile_set configured) this returns {}.
    Full ADR-018 resolution is wired in Phase 7 panel wiring.
    """
    if not auth_profile_set_json:
        return {}
    # Full credential resolution (AuthProfileSet → CredentialCache → resolved
    # header values) is deferred to Phase 7.  For now, return empty so the
    # activity is safe and the Scrubber registration path is exercised by tests.
    return {}


def _build_sandbox_backend() -> SandboxBackend:
    """Return the configured SandboxBackend.

    Reads QUARRY_SANDBOX_BACKEND (via QuarrySettings):
      ""  / "local"     — LocalSubprocessSandbox (default; dev/test, no Docker)
      "container"       — ContainerSandbox Tier 2 (Docker/Podman; production default)
      "k8s_job"         — K8sJobSandbox Tier 3 (deferred; raises NotImplementedError)

    QUARRY_SANDBOX_IMAGE overrides the default container image for the container tier.
    """
    from quarry.config import QuarrySettings

    settings = QuarrySettings()
    backend = (settings.sandbox_backend or "").lower().strip()
    if backend in ("", "local"):
        return LocalSubprocessSandbox()
    if backend == "container":
        image = settings.sandbox_image or ContainerSandbox.DEFAULT_IMAGE
        return ContainerSandbox(image=image)
    if backend == "k8s_job":
        return K8sJobSandbox()
    msg = (
        f"Unknown QUARRY_SANDBOX_BACKEND='{backend}'. "
        "Valid values: '' (or 'local'), 'container', 'k8s_job' (deferred)."
    )
    raise ValueError(msg)


def _run_sandbox(
    spec: SandboxExecSpec,
    *,
    sandbox: SandboxBackend,
    work_dir: Path,
    resolved_env: dict[str, str],
    target_endpoint: TargetEndpoint | None,
) -> SandboxResult:
    """Thin shim — lets tests patch at a single point without mocking subprocess."""
    return sandbox.run(
        spec,
        work_dir=work_dir,
        resolved_env=resolved_env,
        target_endpoint=target_endpoint,
    )


# ---------------------------------------------------------------------------
# Activity (sync — runs in the thread-pool worker, not async)
# ---------------------------------------------------------------------------


def sandbox_exec_activity(inp: SandboxExecActivityInput) -> SandboxExecCapture:
    """Execute a sandboxed command and return a scrubbed SandboxExecCapture.

    Registered as @activity.defn(name="sandbox-exec") in quarry_worker/main.py
    and quarry_server/app.py (Phase 7).  The decorator is applied at registration
    time so this function remains testable without a Temporal runtime.
    """
    spec = SandboxExecSpec.model_validate_json(inp.spec_json)

    # Resolve credentials worker-side; register values in Scrubber BEFORE exec.
    resolved_env = _resolve_credentials(inp.auth_profile_set_json)
    run_scrubber = build_scrubber_with_creds(resolved_env)

    target_endpoint = None
    if inp.target_endpoint_json:
        from quarry.schemas import TargetEndpoint

        target_endpoint = TargetEndpoint.model_validate_json(inp.target_endpoint_json)

    store = LocalArtifactStore(Path(inp.artifact_store_path) / inp.scan_id)
    sandbox = _build_sandbox_backend()

    with tempfile.TemporaryDirectory(prefix="quarry-sandbox-") as _work_dir:
        work_dir = Path(_work_dir)

        result = _run_sandbox(
            spec,
            sandbox=sandbox,
            work_dir=work_dir,
            resolved_env=resolved_env,
            target_endpoint=target_endpoint,
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

    stdout_ref = store.put_bytes(
        f"{inp.candidate_finding_id}/stdout",
        wrapped_stdout.encode("utf-8"),
        kind=ArtifactKind.TOOL_STDOUT,
        content_type="text/plain",
        redaction_status=redaction_status,
    )
    stderr_ref = store.put_bytes(
        f"{inp.candidate_finding_id}/stderr",
        wrapped_stderr.encode("utf-8"),
        kind=ArtifactKind.TOOL_STDERR,
        content_type="text/plain",
        redaction_status=redaction_status,
    )

    return SandboxExecCapture(
        exit_code=result.exit_code,
        stdout_artifact_ref=stdout_ref.id,
        stderr_artifact_ref=stderr_ref.id,
        elapsed_ms=result.elapsed_ms,
        scrubber_hits=scrubber_hits,
        redaction_status=redaction_status,
        timed_out=result.timed_out,
    )


def _cap(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")
