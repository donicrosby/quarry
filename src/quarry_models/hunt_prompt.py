"""Hunt agent prompt construction.

Each hunter receives a class-keyed prompt built from generic templates — no
class-specific branching in Python. The class identity and task-specific guidance
live in ``vuln_class`` and ``task_prompt`` respectively.
"""

from __future__ import annotations

from quarry.schemas import EntryPoint, ScopeExclusion, VulnerabilityClass
from quarry_models.prompting import BuiltPrompt, build_exclusion_block, build_prompt

_SYSTEM_INSTRUCTIONS = """\
You are a security researcher hunting for vulnerabilities in source code.
You have access to tools that let you read files, search code, run static \
analysis rules, and query the syntax tree. Use them to reason about the \
target systematically.

Rules:
- Only emit findings you have evidence for. Do not speculate.
- Use the provided tools. Do not invent file contents.
- When you have exhausted your investigation, emit your final answer.
- Respect the out-of-scope list below — do not investigate or emit \
findings for excluded items."""

_SCHEMA_NOTE = """\
Return a JSON object with a single key "findings" containing a list of \
CandidateFinding objects. Each object must include:
  - vuln_class: string (the vulnerability class you were asked to hunt)
  - title: short descriptive title
  - hypothesis: one sentence explaining why this location is suspicious
  - affected_component: file path and function/line
  - confidence: "low", "medium", or "high"
  - severity: "low", "medium", "high", or "critical"
  - source_refs: list of {repo, file, start_line, end_line, snippet} objects

If you found no evidence, return {"findings": []}."""


def _format_entry_points(entry_points: list[EntryPoint]) -> str:
    if not entry_points:
        return "(none identified)"
    lines = []
    for ep in entry_points:
        lines.append(f"  - {ep.file}::{ep.function} [{ep.kind}]")
    return "\n".join(lines)


def _focus_advisory(focused_classes: list[VulnerabilityClass] | None) -> str:
    if not focused_classes:
        return ""
    names = ", ".join(vc.value for vc in focused_classes)
    return f"\nFocus only on: {names}\n"


def build_hunt_prompt(
    *,
    vuln_class: VulnerabilityClass,
    scope: str | None,
    entry_points: list[EntryPoint],
    task_prompt: str,
    scope_exclusions: list[ScopeExclusion],
    focused_classes: list[VulnerabilityClass] | None = None,
) -> BuiltPrompt:
    """Build a hunt prompt for a single (vuln_class, scope) task.

    The focus advisory is placed in the system message (trusted instruction
    envelope) so target-controlled content cannot override it. Enforcement of
    the focus list is structural (workflow drops tasks before fan-out); the
    advisory steers the hunter's reasoning.
    """
    focus_line = _focus_advisory(focused_classes)
    exclusion_block = build_exclusion_block(scope_exclusions)
    exclusion_section = f"\n\n{exclusion_block}" if exclusion_block else ""

    system_instructions = (
        f"{_SYSTEM_INSTRUCTIONS}{focus_line}{exclusion_section}"
    )

    entry_point_text = _format_entry_points(entry_points)
    scope_text = scope or "(entire repository)"

    task_instructions = (
        f"Hunt for **{vuln_class.value}** vulnerabilities in scope: {scope_text}\n\n"
        f"Known entry points in this scope:\n{entry_point_text}\n\n"
        f"{task_prompt}"
    )

    evidence = f"scope: {scope_text}\nentry_points:\n{entry_point_text}"

    return build_prompt(
        system_instructions=system_instructions,
        task_instructions=task_instructions,
        evidence=evidence,
        output_schema_note=_SCHEMA_NOTE,
        prompt_version="hunt-v1",
        scope_exclusions=[],  # already embedded above; don't double-inject
    )
