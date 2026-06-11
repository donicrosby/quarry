"""http_request agentic tool (ADR-017, safety Layer 5 — role gate).

The tool is registered exclusively for the ``dynamic_validate`` and ``prove``
roles.  It performs NO live I/O in agent context — it packages the validated
``HttpRequestSpec`` as a JSON dispatch payload so ``ToolRunner`` can route it to
the ``quarry-dynamic`` Temporal activity.

Network containment (Layer 6) is enforced by the activity worker on the
``quarry-dynamic`` queue, not here.  The tool's ``run()`` method never opens a
socket.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class _HttpRequestTool:
    """Packages an HttpRequestSpec for dispatch to the quarry-dynamic activity."""

    name = "http_request"
    description = (
        "Propose an HTTP request to the authorized target for live dynamic "
        "corroboration. Only available in the dynamic_validate and prove roles. "
        "Does not send the request directly — the request is dispatched to the "
        "quarry-dynamic worker for scope-checked, network-contained execution."
    )
    roles: list[str] = ["dynamic_validate", "prove"]

    input_schema: dict[str, Any] = {
        "type": "object",
        "required": ["method", "path"],
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                "description": "HTTP method",
            },
            "path": {
                "type": "string",
                "description": "URL path relative to the target base_path",
            },
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Additional HTTP headers (no auth values inline)",
            },
            "body": {
                "type": ["string", "null"],
                "description": "Request body for POST/PUT/PATCH",
            },
            "auth_profile": {
                "type": ["string", "null"],
                "description": (
                    "Named credential profile from auth-profiles.toml. NEVER an inline token value."
                ),
            },
            "vuln_class": {
                "type": ["string", "null"],
                "description": "Vulnerability class context for scope checks",
            },
            "functional_area": {
                "type": ["string", "null"],
                "description": "Functional area context for scope checks",
            },
        },
        "additionalProperties": False,
    }

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:  # noqa: ARG002
        """Package the spec as a JSON dispatch payload — no live I/O.

        The actual HTTP request is sent by the ``http_request_activity`` on the
        ``quarry-dynamic`` Temporal task queue, after all six safety layers
        (ADR-017) have been verified by the activity worker.
        """
        dispatch_payload: dict[str, Any] = {
            "dispatch": "quarry-dynamic",
            "tool": self.name,
            "method": inputs.get("method"),
            "path": inputs.get("path"),
            "headers": inputs.get("headers", {}),
            "body": inputs.get("body"),
            "auth_profile": inputs.get("auth_profile"),
            "vuln_class": inputs.get("vuln_class"),
            "functional_area": inputs.get("functional_area"),
        }
        return json.dumps(dispatch_payload)


# Singleton exported for BUILTIN_REGISTRY
HTTP_REQUEST_TOOL = _HttpRequestTool()
