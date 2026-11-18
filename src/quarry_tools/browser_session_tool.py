"""browser_session agentic tool (ADR-017, safety Layer 5 — role gate; W1).

The tool is registered for the roles that drive live target interaction:
``live_recon``, ``exploit``, and ``dynamic_validate``.  It performs NO live I/O
in agent context — it packages a single ``action`` dispatch payload as JSON so
``ToolRunner`` can route it to the ``quarry-dynamic`` Temporal activity, where
the real headless-Chromium session lives.

Safety wiring (ADR-017 six-layer model):

- Layer 4 (scope-exclusion hard-guard): ``browser_session`` is a member of
  ``ToolRunner._DYNAMIC_TOOLS``, so a scope-excluded target is refused before
  dispatch.
- Layer 5 (role gate): ``roles`` below — any other role raises
  ``UnauthorizedToolError`` in ``ToolRunner.run()``.
- Layer 5.5 (allowed-hosts guard): ``ToolRunner._check_allowed_hosts`` extracts
  the host from the ``url`` parameter and refuses fail-closed.
- Layer 6 (network containment): the ``quarry-dynamic`` worker launches Chromium
  inside the egress-restricted sandbox; the driver additionally host-checks every
  browser request (redirects, beacons, subresources).

The tool's ``run()`` method never opens a socket, launches a browser, or spawns a
process — it returns a JSON dispatch payload only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: The core action set from the browser-session-tool spec, plus ``stop_har`` —
#: the explicit HAR finalizer the spec's HAR requirement names alongside session
#: close ("On session close (or an explicit ``stop_har`` action)").
_ACTIONS: list[str] = [
    "open_url",
    "get_dom",
    "click",
    "fill",
    "screenshot",
    "get_cookies",
    "execute_js",
    "stop_har",
]


class _BrowserSessionTool:
    """Packages a browser action for dispatch to the quarry-dynamic worker."""

    name = "browser_session"
    description = (
        "Drive a real headless browser against the authorized target for live "
        "reconnaissance and corroboration: navigate a single-page app, read its "
        "rendered DOM, click, fill forms, capture a scrubbed screenshot, list "
        "cookie metadata, evaluate JavaScript under containment, and record "
        "scrubbed HAR traffic. Only available in the live_recon, exploit, and "
        "dynamic_validate roles. Does not open a socket directly — the action is "
        "dispatched to the quarry-dynamic worker for scope-checked, "
        "network-contained execution."
    )
    roles: list[str] = ["live_recon", "exploit", "dynamic_validate"]

    input_schema: dict[str, Any] = {
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": _ACTIONS,
                "description": (
                    "Browser action. open_url starts a session (returns session_id); "
                    "get_dom/click/fill/screenshot/get_cookies/execute_js/stop_har "
                    "reference an existing session_id."
                ),
            },
            "session_id": {
                "type": ["string", "null"],
                "description": "Session handle from open_url; required by other actions",
            },
            "url": {
                "type": ["string", "null"],
                "description": "Absolute URL to navigate to (open_url); host must be allowed",
            },
            "selector": {
                "type": ["string", "null"],
                "description": "CSS selector (click/fill)",
            },
            "value": {
                "type": ["string", "null"],
                "description": "Value to type into the selector (fill only)",
            },
            "script": {
                "type": ["string", "null"],
                "description": "JavaScript source to evaluate (execute_js only)",
            },
            "text_cap": {
                "type": ["integer", "null"],
                "description": "Max page-text characters (get_dom; default 100000, max 500000)",
            },
            "timeout_ms": {
                "type": ["integer", "null"],
                "description": "Hard timeout for execute_js (default 5000 ms, max 30000 ms)",
            },
            "capture_har": {
                "type": ["boolean", "null"],
                "description": "Record scrubbed HAR traffic (open_url; default false)",
            },
            "auth_profile": {
                "type": ["string", "null"],
                "description": (
                    "Named credential profile from auth-profiles.toml. NEVER an inline token value."
                ),
            },
        },
        "additionalProperties": False,
    }

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:  # noqa: ARG002
        """Package the action as a JSON dispatch payload — no live I/O.

        The real browser session is created and driven by ``browser-session`` on
        the ``quarry-dynamic`` Temporal task queue, after the safety layers
        (ADR-017) have been verified by ``ToolRunner`` and the activity worker.
        """
        dispatch_payload: dict[str, Any] = {
            "dispatch": "quarry-dynamic",
            "tool": self.name,
            "action": inputs.get("action"),
        }
        for key in (
            "session_id",
            "url",
            "selector",
            "value",
            "script",
            "text_cap",
            "timeout_ms",
            "capture_har",
            "auth_profile",
        ):
            value = inputs.get(key)
            if value is not None:
                dispatch_payload[key] = value
        return json.dumps(dispatch_payload)


# Singleton exported for BUILTIN_REGISTRY
BROWSER_SESSION_TOOL = _BrowserSessionTool()
