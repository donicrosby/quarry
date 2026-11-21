"""prove_xss — browser-confirmed reflected/stored XSS proof (W8).

An LLM can claim "the payload reflects", but reflection is not execution. This
activity proves XSS the only way that counts: it drives a real browser session
(W1 ``browser_session``), injects an inert canary assignment
(``<script>window._qry_xss = 'quarry-xss-…';</script>``), and reads the
``window._qry_xss`` global back through ``execute_js``. ``grounded`` is true only
when the read-back equals the canary token — reflection alone leaves it false
(the decisive distinction from the LLM-only path).

Modes:

* **reflected** — inject the canary into ``target_url``, open it, read back.
* **stored** — two-request chain: navigate to the target origin, ``execute_js`` a
  same-origin ``fetch()`` that POSTs the canary to ``inject_spec``, settle, open
  ``read_url``, read back. A ``get_dom()`` check distinguishes "reflected but not
  executed" (a CSP/context block) from a plain miss.

W1 is imported lazily (at call time): until ``impl/browser-session-tool`` lands,
``prove_xss`` raises a ``RuntimeError`` naming the missing dependency instead of
an opaque ``ImportError``.
"""

from __future__ import annotations

import importlib
import json
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlsplit

from temporalio import activity

from quarry_activities.inputs import (
    CanaryEvidence,
    ProveXssInput,
    ProveXssMode,
    ProveXssOutput,
)
from quarry_models.redaction import Scrubber

CANARY_PREFIX = "quarry-xss-"
WINDOW_GLOBAL = "window._qry_xss"
# Design D3: the settle delay is floored so a caller cannot skip the write-landing
# wait entirely.
MIN_SETTLE_DELAY_MS = 500
_DEFAULT_REFLECTED_PARAM = "q"
_DOM_TEXT_CAP = 100_000


def _load_browser_session() -> Any:
    """Lazily import the W1 browser session tool (module ``browser_session``).

    Raises ``RuntimeError`` (never a bare ``ImportError``) when W1 is not
    deployed, naming the missing dependency so the caller can act on it.
    """
    try:
        module = importlib.import_module("quarry_activities.browser_session")
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        msg = (
            "prove_xss requires the W1 browser session tool "
            "(quarry_activities.browser_session, branch impl/browser-session-tool); "
            f"import failed: {exc}"
        )
        raise RuntimeError(msg) from exc
    return module


class _BrowserSessionClient:
    """Thin adapter over W1's ``browser_session_impl`` action surface.

    W1 dispatches one action per call via ``BrowserSessionActivityInput``; this
    adapter gives ``prove_xss`` the ``open_url`` / ``execute_js`` / ``get_dom``
    surface the design (D2) describes. The impl is called directly (it is
    documented as the direct-call entry point) so no Temporal activity context is
    required and the adapter is unit-testable.
    """

    def __init__(self, module: Any) -> None:
        self._module = module

    def _call(self, **kwargs: object) -> dict[str, object]:
        module = self._module
        input_cls = module.BrowserSessionActivityInput
        impl = module.browser_session_impl
        result: dict[str, object] = impl(input_cls(**kwargs))
        return result

    def open_url(
        self,
        *,
        url: str,
        allowed_hosts: list[str],
        target_host: str,
        target_port: int,
        timeout_ms: int | None = None,
    ) -> dict[str, object]:
        return self._call(
            action="open_url",
            url=url,
            allowed_hosts=tuple(allowed_hosts),
            target_host=target_host,
            target_port=target_port,
            timeout_ms=timeout_ms,
        )

    def execute_js(
        self, *, session_id: str, script: str, timeout_ms: int | None = None
    ) -> dict[str, object]:
        return self._call(
            action="execute_js", session_id=session_id, script=script, timeout_ms=timeout_ms
        )

    def get_dom(self, *, session_id: str, text_cap: int = _DOM_TEXT_CAP) -> dict[str, object]:
        return self._call(action="get_dom", session_id=session_id, text_cap=text_cap)


def canary_payload(canary_token: str) -> str:
    """The inert injection payload (design D2): a single benign assignment."""
    return f"<script>window._qry_xss = '{canary_token}';</script>"


def token_short(canary_token: str) -> str:
    """``quarry-xss-{first 8 hex}...`` — the token prefix recorded in provenance."""
    body = (
        canary_token[len(CANARY_PREFIX) :]
        if canary_token.startswith(CANARY_PREFIX)
        else canary_token
    )
    return f"{CANARY_PREFIX}{body[:8]}..."


def prove_xss_cascade_step(mode: ProveXssMode, canary_token: str, grounded: bool) -> str:
    """Provenance string for ``CandidateFinding.cascade_step`` (design D2).

    Browser-confirmed findings carry the ``browser-confirmed`` prefix.
    """
    label = "browser-confirmed" if grounded else "browser-unconfirmed"
    return f"{label}: {mode.value}, token={token_short(canary_token)}, grounded={grounded}"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return host, port


def _inject_reflected(target_url: str, payload: str) -> str:
    """Place the canary in the reflected parameter of ``target_url``.

    ``{CANARY}`` in the URL is substituted when present (mirroring the stored-mode
    body convention); otherwise the payload is appended as the ``q`` query param.
    (The spec does not pin the parameter name — see the card comment.)
    """
    if "{CANARY}" in target_url:
        return target_url.replace("{CANARY}", payload)
    parts = urlsplit(target_url)
    query = parts.query
    extra = urlencode({_DEFAULT_REFLECTED_PARAM: payload})
    new_query = f"{query}&{extra}" if query else extra
    return parts._replace(query=new_query).geturl()


def _read_back(client: _BrowserSessionClient, session_id: str) -> object:
    resp = client.execute_js(session_id=session_id, script=WINDOW_GLOBAL)
    if resp.get("error"):
        return None
    return resp.get("result")


def _scrub_dom(client: _BrowserSessionClient, session_id: str) -> str | None:
    resp = client.get_dom(session_id=session_id)
    if resp.get("error"):
        return None
    dom = resp.get("dom") or resp.get("result") or resp.get("html") or ""
    if not isinstance(dom, str):
        return None
    return Scrubber().scrub(dom).text


def _grounded_output(
    inp: ProveXssInput, client: _BrowserSessionClient, session_id: str, dom: str | None
) -> ProveXssOutput:
    observed = _read_back(client, session_id)
    if observed == inp.canary_token:
        return ProveXssOutput(
            grounded=True,
            canary_evidence=CanaryEvidence(
                kind="window_global",
                value=inp.canary_token,
                observation_method=f"execute_js('{WINDOW_GLOBAL}')",
                timestamp_iso=_utc_now_iso(),
            ),
            dom_snapshot=dom,
            error=None,
        )
    return ProveXssOutput(
        grounded=False,
        dom_snapshot=dom,
        error=(
            "canary not executed (possible CSP block or non-executing context); "
            f"observed={observed!r}"
        ),
    )


def _prove_reflected(inp: ProveXssInput, client: _BrowserSessionClient) -> ProveXssOutput:
    payload = canary_payload(inp.canary_token)
    canary_url = _inject_reflected(inp.target_url, payload)
    host, port = _host_port(inp.target_url)
    opened = client.open_url(
        url=canary_url,
        allowed_hosts=inp.allowed_hosts,
        target_host=host,
        target_port=port,
        timeout_ms=inp.page_load_timeout_ms,
    )
    if opened.get("error"):
        return ProveXssOutput(grounded=False, error=f"open_url failed: {opened.get('error')}")
    session_id = str(opened.get("session_id") or "")
    dom = _scrub_dom(client, session_id)
    return _grounded_output(inp, client, session_id, dom)


def _inject_url(inp: ProveXssInput) -> str:
    assert inp.inject_spec is not None
    path = inp.inject_spec.path
    if path.startswith(("http://", "https://")):
        return path
    parts = urlsplit(inp.target_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    return origin + (path if path.startswith("/") else f"/{path}")


def _stored_inject_script(inp: ProveXssInput, payload: str) -> str:
    assert inp.inject_spec is not None
    spec = inp.inject_spec
    url = _inject_url(inp)
    body = (spec.body or "").replace("{CANARY}", payload)
    headers = dict(spec.headers)
    options = {
        "method": spec.method,
        "headers": headers,
        "body": body,
    }
    options_json = json.dumps(options)
    return (
        "(async () => { const r = await fetch("
        f"{json.dumps(url)}, {options_json}); return r.status; }})()"
    )


def _prove_stored(inp: ProveXssInput, client: _BrowserSessionClient) -> ProveXssOutput:
    if inp.inject_spec is None or inp.read_url is None:
        return ProveXssOutput(grounded=False, error="stored mode requires inject_spec and read_url")
    inject_host = urlsplit(_inject_url(inp)).hostname
    read_host = urlsplit(inp.read_url).hostname
    if inject_host and read_host and inject_host != read_host:
        return ProveXssOutput(
            grounded=False,
            error=(
                f"read_url host {read_host!r} does not match inject host {inject_host!r}; "
                "cross-origin canary fetch aborted"
            ),
        )

    parts = urlsplit(inp.target_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    host, port = _host_port(origin)

    navigated = client.open_url(
        url=origin + "/",
        allowed_hosts=inp.allowed_hosts,
        target_host=host,
        target_port=port,
        timeout_ms=inp.page_load_timeout_ms,
    )
    if navigated.get("error"):
        return ProveXssOutput(grounded=False, error=f"open_url failed: {navigated.get('error')}")
    session_id = str(navigated.get("session_id") or "")

    payload = canary_payload(inp.canary_token)
    injected = client.execute_js(
        session_id=session_id,
        script=_stored_inject_script(inp, payload),
        timeout_ms=inp.session_timeout_ms,
    )
    if injected.get("error"):
        return ProveXssOutput(
            grounded=False,
            error=(
                f"canary inject fetch blocked (possible CSP connect-src): {injected.get('error')}"
            ),
        )
    status = injected.get("result")
    if isinstance(status, int) and status >= 400:
        return ProveXssOutput(grounded=False, error=f"canary inject write failed: HTTP {status}")

    time.sleep(max(inp.settle_delay_ms, MIN_SETTLE_DELAY_MS) / 1000.0)

    rhost, rport = _host_port(inp.read_url)
    read = client.open_url(
        url=inp.read_url,
        allowed_hosts=inp.allowed_hosts,
        target_host=rhost or host,
        target_port=rport,
        timeout_ms=inp.page_load_timeout_ms,
    )
    if read.get("error"):
        return ProveXssOutput(grounded=False, error=f"read_url open failed: {read.get('error')}")
    read_session = str(read.get("session_id") or session_id)

    dom = _scrub_dom(client, read_session)
    output = _grounded_output(inp, client, read_session, dom)
    if output.grounded:
        return output
    if dom is not None and inp.canary_token in dom:
        return ProveXssOutput(
            grounded=False,
            dom_snapshot=dom,
            error="canary visible in DOM but not executed (possible CSP/context block)",
        )
    return output


def prove_xss_impl(inp: ProveXssInput) -> ProveXssOutput:
    """Activity body: prove reflected or stored XSS via the W1 browser session."""
    module = _load_browser_session()
    client = _BrowserSessionClient(module)
    if inp.mode == ProveXssMode.STORED:
        return _prove_stored(inp, client)
    return _prove_reflected(inp, client)


@activity.defn(name="prove-xss")
def prove_xss_activity(inp: ProveXssInput) -> ProveXssOutput:
    """Temporal activity: browser-confirmed reflected/stored XSS proof."""
    return prove_xss_impl(inp)
