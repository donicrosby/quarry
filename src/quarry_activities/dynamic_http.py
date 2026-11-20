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
from datetime import UTC, datetime

import httpx
from httpx._types import FileTypes
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
from quarry_activities.session_analysis import analyze_session_tokens
from quarry_artifacts.http_utils import (
    capture_request_artifact,
    capture_response_artifact,
    response_artifact_key,
)
from quarry_artifacts.store import build_artifact_store
from quarry_models.redaction import Scrubber

# Body cap — applied before scrubbing so prompts never receive huge payloads.
MAX_BODY_BYTES = 10 * 1024  # 10KB

# Hard redirect-following cap (http-forging-breadth).  Exceeding it raises
# httpx.TooManyRedirects rather than silently truncating the chain.
MAX_REDIRECTS = 10

# Headers that must NOT survive a hop to a different host: credentials and
# session cookies are origin-scoped, and forwarding them leaks them to the
# redirect target.
_SENSITIVE_REDIRECT_HEADERS = frozenset({"authorization", "cookie"})

# Headers httpx recomputes per hop; forwarding them would duplicate stale state.
_HOP_LOCAL_HEADERS = frozenset({"content-length", "host"})


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


def _apply_cookies(headers: dict[str, str], cookies: dict[str, str]) -> dict[str, str]:
    """Return *headers* with *cookies* merged into a single Cookie header.

    An absent/empty cookie dict is a no-op: no Cookie header is added beyond
    whatever the credential resolver already injected.
    """
    if not cookies:
        return headers
    existing = next(
        (value for key, value in headers.items() if key.lower() == "cookie"),
        None,
    )
    merged = {key: value for key, value in headers.items() if key.lower() != "cookie"}
    jar = "; ".join(f"{name}={value}" for name, value in cookies.items())
    merged["Cookie"] = f"{existing}; {jar}" if existing else jar
    return merged


def _multipart_files(spec: HttpRequestSpec) -> list[tuple[str, FileTypes]] | None:
    """Translate ``spec.multipart_fields`` into httpx ``files`` entries.

    A part with neither filename nor content_type is a plain form field; a part
    carrying either becomes a file part so the target sees an upload.
    """
    if not spec.multipart_fields:
        return None
    files: list[tuple[str, FileTypes]] = []
    for field in spec.multipart_fields:
        if field.filename is None and field.content_type is None:
            files.append((field.name, field.value))
        else:
            files.append((field.name, (field.filename, field.value, field.content_type)))
    return files


def _redirect_url(response: httpx.Response) -> httpx.URL | None:
    """Resolve the next-hop URL for a redirect response, or None when not one."""
    if not response.is_redirect:
        return None
    location = response.headers.get("location")
    if not location:
        return None
    return response.url.join(location)


def _next_hop_headers(request: httpx.Request, *, cross_host: bool) -> dict[str, str]:
    """Headers to forward onto the next redirect hop.

    ``cross_host`` drops the origin-scoped credentials (Authorization, Cookie);
    hop-local headers (Host, Content-Length) are always recomputed.
    """
    forwarded: dict[str, str] = {}
    for key, value in request.headers.multi_items():
        lower = key.lower()
        if lower in _HOP_LOCAL_HEADERS:
            continue
        if cross_host and lower in _SENSITIVE_REDIRECT_HEADERS:
            continue
        forwarded[key] = value
    return forwarded


def _follow_redirects(
    client: httpx.Client,
    response: httpx.Response,
    *,
    allowed_hosts: tuple[str, ...],
) -> httpx.Response:
    """Follow *response*'s redirect chain, fail-closed on every hop.

    Layer 6 is re-checked per hop BEFORE any request is issued: a redirect to a
    host outside ``allowed_hosts`` is never followed and the 3xx is returned as
    the final response.  Chains longer than :data:`MAX_REDIRECTS` raise
    ``httpx.TooManyRedirects``.  Authorization/Cookie headers are stripped when
    the hop changes host.
    """
    hops = 0
    while True:
        next_url = _redirect_url(response)
        if next_url is None:
            return response
        if next_url.host not in allowed_hosts:
            return response
        if hops >= MAX_REDIRECTS:
            raise httpx.TooManyRedirects(
                f"Exceeded maximum of {MAX_REDIRECTS} redirects",
                request=response.request,
            )

        current = response.request
        method = current.method
        content: bytes | None = current.content or None
        turns_into_get = (response.status_code == 303 and method != "HEAD") or (
            response.status_code in (301, 302) and method == "POST"
        )
        if turns_into_get:
            method, content = "GET", None

        next_request = client.build_request(
            method=method,
            url=next_url,
            headers=_next_hop_headers(current, cross_host=next_url.host != current.url.host),
            content=content,
        )
        hops += 1
        response = client.send(next_request)


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

    store = build_artifact_store(inp.artifact_store_path)

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

    # Per-request cookie injection.  Values are registered with the run scrubber
    # BEFORE egress so they are redacted from response bodies and prompt context
    # (http-forging-breadth task 3.4).
    for cookie_value in spec.cookies.values():
        if cookie_value:
            run_scrubber.register_secret(cookie_value)
    headers = _apply_cookies(headers, spec.cookies)

    start_ms = int(time.monotonic() * 1000)

    files = _multipart_files(spec)
    with httpx.Client(timeout=10.0) as client:
        request = client.build_request(
            method=spec.method,
            url=url,
            headers=headers,
            content=(None if files is not None else (spec.body.encode() if spec.body else None)),
            files=files,
        )
        # Multipart bodies are streamed; materialize them so the stored request
        # artifact and any redirect hop can read ``request.content`` (httpx
        # raises RequestNotRead otherwise). Byte bodies are already materialized.
        request.read()
        response = client.send(request)
        if spec.follow_redirects:
            response = _follow_redirects(client, response, allowed_hosts=inp.allowed_hosts)
            request = response.request

    elapsed_ms = int(time.monotonic() * 1000) - start_ms

    # Evict the cached credential on 401 so the next request forces re-resolution.
    if response.status_code == 401 and cache is not None and spec.auth_profile:
        cache.invalidate(spec.auth_profile)

    # Capture request artifact (auth headers already redacted by http_utils).
    req_artifact = capture_request_artifact(store, request, key_prefix=f"{inp.scan_id}/")

    # Cap and scrub response body before storing
    raw_body = response.text[:MAX_BODY_BYTES] if response.text else ""
    scrub_result = run_scrubber.scrub(raw_body)
    scrubber_hits = scrub_result.hits
    redaction_status = (
        RedactionStatus.REDACTED if scrubber_hits > 0 else RedactionStatus.NOT_REQUIRED
    )

    resp_artifact = capture_response_artifact(
        store,
        response,
        key_prefix=f"{inp.scan_id}/",
        scan_id=inp.scan_id,
    )

    capture = HttpResponseCapture(
        status_code=response.status_code,
        headers=dict(response.headers),
        body_artifact_ref=resp_artifact.id,
        elapsed_ms=elapsed_ms,
        scrubber_hits=scrubber_hits,
        redaction_status=redaction_status,
        request_artifact_ref=req_artifact.id,
        body_artifact_key=response_artifact_key(response),
        artifact_refs=[req_artifact, resp_artifact],
    )

    # Deterministic session-token/JWT/cookie analysis (session-jwt-cookie-analysis,
    # task 7.1).  Runs synchronously, in-activity, only for auth-bearing requests.
    # It reads the raw httpx.Response (multi-value Set-Cookie via get_list, before
    # the dict collapse above) and the freshly-built capture (body_artifact_ref).
    if spec.auth_profile is not None:
        capture.session_token_analysis = analyze_session_tokens(
            response,
            capture,
            scan_id=inp.scan_id,
            target_scheme=endpoint.scheme,
            capture_time=datetime.now(UTC),
        )

    return capture
