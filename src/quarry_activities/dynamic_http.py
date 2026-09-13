"""http_request_activity — live HTTP corroboration on the quarry-control queue.

This activity is the sole point where an HTTP socket is opened by the agentic
pipeline.  It enforces allowed_hosts independently (Layer 6 of ADR-017's six
safety layers) and runs on the ``quarry-control`` Temporal task queue so workflow
determinism is preserved (ADR-014).

Non-idempotent HTTP methods (POST, PUT, DELETE, PATCH) must not be auto-retried
by Temporal — the workflow dispatches these activities as non-retryable.

The response body is scrubbed and wrapped in ``<target_content>`` tags before
re-entering any prompt (ADR-017 "Untrusted-evidence handling").
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import httpx
from temporalio import activity

from quarry.schemas import (
    AuthProfileSet,
    HttpRequestSpec,
    HttpResponseCapture,
    RedactionStatus,
    TargetEndpoint,
)
from quarry_activities.credentials import CredentialCache, resolve_credentials
from quarry_activities.inputs import HttpRequestActivityInput
from quarry_artifacts.http_utils import (
    capture_request_artifact,
    capture_response_artifact,
    response_artifact_key,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.redaction import Scrubber

# Body cap — applied before scrubbing so prompts never receive huge payloads.
MAX_BODY_BYTES = 10 * 1024  # 10KB


def enforce_allowed_hosts(host: str, allowed_hosts: tuple[str, ...]) -> None:
    """Raise ValueError if *host* is not in *allowed_hosts*.

    This is Layer 6's independent enforcement — it runs inside the activity
    worker, separate from any ToolRunner or workflow check.  An empty
    allowed_hosts list blocks all hosts (fail-closed).
    """
    if not allowed_hosts:
        msg = (
            f"Request to '{host}' blocked: allowed_hosts is empty. "
            "Set Target.allowed_hosts to authorize live HTTP requests."
        )
        raise ValueError(msg)
    if host not in allowed_hosts:
        msg = (
            f"Request to '{host}' is outside the allowed scope. "
            f"Allowed hosts: {list(allowed_hosts)}"
        )
        raise ValueError(msg)


def scrub_and_wrap_body(body: str, scrubber: Scrubber | None = None) -> str:
    """Scrub *body* and wrap in ``<target_content>`` tags.

    HTTP response bodies are attacker-controlled content.  They must be
    scrubbed before re-entering any model prompt.  The ``<target_content>``
    boundary is mandatory — there is no fallback.
    """
    stripped = re.sub(r"<script[^>]*>.*?</script>", "", body, flags=re.DOTALL)
    s = scrubber or Scrubber()
    result = s.scrub(stripped)
    return f"<target_content>{result.text}</target_content>"


@activity.defn(name="http-request")
async def http_request_activity(inp: HttpRequestActivityInput) -> HttpResponseCapture:
    """Execute a scoped live HTTP request and return the captured response.

    Safety:
    - Enforces allowed_hosts independently (Layer 6).
    - Scrubs the response body before returning.
    - Does not auto-retry non-idempotent methods (handled by workflow dispatch).
    """
    spec = HttpRequestSpec.model_validate_json(inp.spec_json)
    endpoint = TargetEndpoint.model_validate_json(inp.target_endpoint_json)

    # Layer 6: independent allowed_hosts enforcement in the worker.
    enforce_allowed_hosts(endpoint.host, inp.allowed_hosts)

    base_url = (
        f"{endpoint.scheme}://{endpoint.host}:{endpoint.port}{endpoint.base_path.rstrip('/')}"
    )
    url = f"{base_url}{spec.path}"

    store = LocalArtifactStore(
        Path(inp.artifact_store_path) / inp.scan_id,
    )

    # Per-run scrubber.  If credential resolution is wired later, the resolved
    # secret value is registered here before the request is sent (ADR-018 §4.4).
    run_scrubber = Scrubber()

    # Resolve and inject credentials if an auth_profile is named on the spec.
    headers: dict[str, str] = dict(spec.headers)
    cache: CredentialCache | None = None
    if spec.auth_profile and inp.auth_profile_set_json:
        auth_set = AuthProfileSet.model_validate_json(inp.auth_profile_set_json)
        profile = auth_set.get(spec.auth_profile)
        if profile is not None:
            cache = CredentialCache(inp.scan_id)
            cred = resolve_credentials(
                profile,
                cache,
                run_scrubber,
                allowed_hosts=inp.allowed_hosts,
                target_host=endpoint.host,
                target_port=endpoint.port,
            )
            if cred is not None:
                headers[cred.header_name] = cred.header_value

    start_ms = int(time.monotonic() * 1000)

    with httpx.Client(timeout=10.0) as client:
        request = client.build_request(
            method=spec.method,
            url=url,
            headers=headers,
            content=spec.body.encode() if spec.body else None,
        )
        response = client.send(request)

    elapsed_ms = int(time.monotonic() * 1000) - start_ms

    # Evict the cached credential on 401 so the next request forces re-resolution.
    if response.status_code == 401 and cache is not None and spec.auth_profile:
        cache.invalidate(spec.auth_profile)

    # Capture request artifact (auth headers already redacted by http_utils)
    req_artifact = capture_request_artifact(store, request)

    # Cap and scrub response body before storing
    raw_body = response.text[:MAX_BODY_BYTES] if response.text else ""
    scrub_result = run_scrubber.scrub(raw_body)
    scrubber_hits = scrub_result.hits
    redaction_status = (
        RedactionStatus.REDACTED if scrubber_hits > 0 else RedactionStatus.NOT_REQUIRED
    )

    resp_artifact = capture_response_artifact(store, response)

    return HttpResponseCapture(
        status_code=response.status_code,
        headers=dict(response.headers),
        body_artifact_ref=resp_artifact.id,
        elapsed_ms=elapsed_ms,
        scrubber_hits=scrubber_hits,
        redaction_status=redaction_status,
        request_artifact_ref=req_artifact.id,
        body_artifact_key=response_artifact_key(response),
    )
