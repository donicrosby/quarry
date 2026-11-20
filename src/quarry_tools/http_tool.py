"""http_request agentic tool (ADR-017, safety Layer 5 — role gate).

The tool is registered exclusively for the ``dynamic_validate`` and ``prove``
roles.  It performs NO live I/O in agent context — it packages the validated
``HttpRequestSpec`` as a JSON dispatch payload so ``ToolRunner`` can route it to
the ``quarry-control`` Temporal activity.

Network containment (Layer 6) is enforced by the activity worker on the
``quarry-control`` queue, not here.  The tool's ``run()`` method never opens a
socket.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class _HttpRequestTool:
    """Packages an HttpRequestSpec for dispatch to the quarry-control worker."""

    name = "http_request"
    description = (
        "Propose an HTTP request to the authorized target for live dynamic "
        "corroboration or exploitation. Only available in the dynamic_validate, "
        "prove, live_recon, and exploit roles. Does not send the request directly "
        "— the request is dispatched to the quarry-control worker for "
        "scope-checked, network-contained execution."
    )
    roles: list[str] = ["dynamic_validate", "prove", "live_recon", "exploit"]

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
            "multipart_fields": {
                "type": ["array", "null"],
                "description": (
                    "multipart/form-data parts. When non-empty the request is sent as "
                    "multipart and the raw body is ignored. Use filename/content_type "
                    "to send a file part (file-upload probing)."
                ),
                "items": {
                    "type": "object",
                    "required": ["name", "value"],
                    "additionalProperties": False,
                    "properties": {
                        "name": {"type": "string", "description": "Form field name"},
                        "value": {"type": "string", "description": "Field value / file content"},
                        "filename": {
                            "type": ["string", "null"],
                            "description": "Filename for a file part",
                        },
                        "content_type": {
                            "type": ["string", "null"],
                            "description": "Content-Type for a file part",
                        },
                    },
                },
            },
            "follow_redirects": {
                "type": "boolean",
                "default": False,
                "description": (
                    "Follow 3xx redirects (max 10 hops). Every hop is re-checked "
                    "against allowed_hosts; off-scope hops are not followed."
                ),
            },
            "cookies": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Per-request cookies sent as the Cookie header",
            },
        },
        "additionalProperties": False,
    }

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:  # noqa: ARG002
        """Package the spec as a JSON dispatch payload — no live I/O.

        The actual HTTP request is sent by the ``http_request_activity`` on the
        ``quarry-control`` Temporal task queue, after all six safety layers
        (ADR-017) have been verified by the activity worker.
        """
        dispatch_payload: dict[str, Any] = {
            "dispatch": "quarry-control",
            "tool": self.name,
            "method": inputs.get("method"),
            "path": inputs.get("path"),
            "headers": inputs.get("headers", {}),
            "body": inputs.get("body"),
            "auth_profile": inputs.get("auth_profile"),
            "vuln_class": inputs.get("vuln_class"),
            "functional_area": inputs.get("functional_area"),
            "multipart_fields": inputs.get("multipart_fields"),
            "follow_redirects": inputs.get("follow_redirects", False),
            "cookies": inputs.get("cookies", {}),
        }
        return json.dumps(dispatch_payload)


# Singleton exported for BUILTIN_REGISTRY
HTTP_REQUEST_TOOL = _HttpRequestTool()
