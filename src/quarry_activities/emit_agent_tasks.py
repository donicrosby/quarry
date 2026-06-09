"""Emit AgentTask objects from an ArchitectureDoc for the hunt stage.

One AgentTask is emitted per (vuln_class, scope) pair where scope is a
subsystem root path from the ArchitectureDoc.  The task_prompt is class-keyed
but carried entirely in data — no class-specific Python branching here.
"""

from __future__ import annotations

import uuid
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from temporalio import activity

from quarry.schemas import AgentTask, ArchitectureDoc, VulnerabilityClass

_TASK_PROMPTS: dict[str, str] = {
    VulnerabilityClass.SECRETS.value: (
        "Search for hardcoded secrets, API keys, tokens, passwords, and credentials. "
        "Look for assignment patterns like `api_key = '...'`, environment-variable "
        "bypasses, and configuration files with plaintext secrets."
    ),
    VulnerabilityClass.IDOR.value: (
        "Search for insecure direct object references. Look for endpoints that accept "
        "user-controlled object IDs (path params, query params, request body) and fetch "
        "objects without checking that the requesting user owns or is authorized to access them."
    ),
    VulnerabilityClass.COMMAND_INJECTION.value: (
        "Search for sinks where user-controlled input reaches OS command execution. "
        "Look for subprocess calls, shell=True, exec/spawn/popen functions, and "
        "`os/exec.Command` in Go. Trace from HTTP handler parameters to the sink."
    ),
    VulnerabilityClass.SSRF.value: (
        "Search for server-side request forgery. Look for HTTP client calls that "
        "accept user-controlled URLs without allowlist validation."
    ),
    VulnerabilityClass.SQL_INJECTION.value: (
        "Search for SQL injection. Look for string-concatenated queries and "
        "ORM raw() / execute() calls with user-controlled input."
    ),
    VulnerabilityClass.XSS.value: (
        "Search for cross-site scripting. Look for user-controlled content "
        "rendered into HTML without escaping."
    ),
}

_DEFAULT_TASK_PROMPT = (
    "Search for vulnerabilities of the requested class in this scope. "
    "Use generic tools (grep, search_code, opengrep, treesitter_query) to "
    "enumerate potential sinks and trace data flow from user-controlled inputs."
)


@activity.defn(name="emit-agent-tasks")
def emit_agent_tasks(
    scan_id: str | dict[str, Any],
    arch_doc_json: str | None = None,
    vuln_classes: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Produce one AgentTask per (vuln_class, scope) from the ArchitectureDoc.

    Temporal passes args as a dict when called with keyword args from the
    workflow; this activity handles both forms.
    """
    with suppress(RuntimeError):
        activity.heartbeat()

    # Handle dict-style invocation from workflow
    if isinstance(scan_id, dict):
        d = scan_id
        scan_id = str(d.get("scan_id", ""))
        arch_doc_json = str(d.get("arch_doc_json", ""))
        vuln_classes = list(d.get("vuln_classes", []))

    if not arch_doc_json:
        return []

    arch_doc = ArchitectureDoc.model_validate_json(arch_doc_json)
    requested_classes = [VulnerabilityClass(vc) for vc in (vuln_classes or [])]

    now = datetime.now(UTC)
    tasks: list[AgentTask] = []

    scopes: list[str] = []
    if arch_doc.subsystems:
        for sub in arch_doc.subsystems:
            scope = sub.root_paths[0] if sub.root_paths else sub.name
            scopes.append(scope)
    if not scopes:
        scopes = ["."]

    for vc in requested_classes:
        for scope in scopes:
            task_prompt = _TASK_PROMPTS.get(vc.value, _DEFAULT_TASK_PROMPT)
            task = AgentTask(
                id=str(uuid.uuid4()),
                scan_id=str(scan_id),
                role="hunt",
                task_name=f"hunt-{vc.value}-{scope.replace('/', '_')}",
                task_prompt=task_prompt,
                vuln_class=vc,
                scope=scope,
                source="recon",
                status="pending",
                created_at=now,
            )
            tasks.append(task)

    return [t.model_dump(mode="json") for t in tasks]
