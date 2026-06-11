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
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import TemplateNotFoundError

_TASK_PROMPT_ROLE = "task"
_TASK_PROMPT_VERSION = "1.0.0"


def task_prompt_for(vuln_class: VulnerabilityClass) -> str:
    """Render the per-class hunt task-prompt stub from the prompt registry.

    Stubs live in ``prompts/task/<vuln_class>.1.0.0.j2`` (ADR-019 — prompt text is
    editable in the registry by the end user, never hardcoded). Falls back to
    ``prompts/task/default.1.0.0.j2`` for classes without a dedicated stub.
    """
    registry = get_registry()
    for name in (vuln_class.value, "default"):
        try:
            prompt = build_prompt(
                registry=registry,
                role=_TASK_PROMPT_ROLE,
                name=name,
                version=_TASK_PROMPT_VERSION,
                variables={},
            )
        except TemplateNotFoundError:
            continue
        # Developer-only stub template: the text lands in the user message.
        return prompt.messages[1].content.strip() if len(prompt.messages) > 1 else ""
    return ""


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

    # Each subsystem's entry points and notes belong to its own scope, so carry
    # them onto every task for that scope — the hunter uses the entry points as
    # concrete leads and the notes (per-class sink/source buckets) to seed its
    # backward-taint analysis.
    scoped: list[tuple[str, list[Any], str]] = []
    if arch_doc.subsystems:
        for sub in arch_doc.subsystems:
            scope = sub.root_paths[0] if sub.root_paths else sub.name
            scoped.append((scope, list(sub.entry_points), sub.notes))
    if not scoped:
        scoped = [(".", [], "")]

    for vc in requested_classes:
        task_prompt = task_prompt_for(vc)
        for scope, entry_points, recon_notes in scoped:
            task = AgentTask(
                id=str(uuid.uuid4()),
                scan_id=str(scan_id),
                role="hunt",
                task_name=f"hunt-{vc.value}-{scope.replace('/', '_')}",
                task_prompt=task_prompt,
                vuln_class=vc,
                scope=scope,
                entry_points=entry_points,
                recon_notes=recon_notes,
                source="recon",
                status="pending",
                created_at=now,
            )
            tasks.append(task)

    return [t.model_dump(mode="json") for t in tasks]
