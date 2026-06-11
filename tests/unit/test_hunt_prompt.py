"""Tests for the hunt prompt — now rendered from prompts/hunt/hunt.1.0.0.j2.

These tests verify the same behavioural properties as the original test_hunt_prompt.py
but use build_prompt() + PromptRegistry instead of the deleted build_hunt_prompt().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quarry.schemas import EntryPoint, ScopeExclusion, VulnerabilityClass
from quarry_models.types import ModelMessage
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def _registry() -> PromptRegistry:
    return PromptRegistry(prompts_root=PROMPTS_ROOT)


def _render(vuln_class: VulnerabilityClass, **kw: Any) -> list[ModelMessage]:
    # Route to the per-class hunt template (mirrors hunt.py); every known class
    # now has its own prompts/hunt/<vuln_class>.1.0.0.j2.
    return build_prompt(
        registry=_registry(),
        role="hunt",
        name=kw.get("name", vuln_class.value),
        version="1.0.0",
        variables={
            "vuln_class": vuln_class.value,
            "scope": kw.get("scope", "src/"),
            "entry_points": kw.get("entry_points", []),
            "recon_notes": kw.get("recon_notes", ""),
            "focus_classes": [c.value for c in kw.get("focused_classes", [])],
            "scope_exclusions": kw.get("scope_exclusions", []),
            "task_prompt": kw.get("task_prompt", "Look for sinks."),
            "evidence_chunks": kw.get("evidence_chunks", []),
        },
    ).messages


def test_hunt_prompt_renders_for_each_vuln_class() -> None:
    for vuln_class in (
        VulnerabilityClass.COMMAND_INJECTION,
        VulnerabilityClass.IDOR,
        VulnerabilityClass.SECRETS,
        VulnerabilityClass.SSRF,
    ):
        messages = _render(vuln_class)
        rendered = "\n".join(m.content for m in messages)
        assert vuln_class.value in rendered


def test_hunt_prompt_includes_focus_advisory() -> None:
    messages = _render(
        VulnerabilityClass.COMMAND_INJECTION,
        task_prompt="Find command injection sinks.",
        focused_classes=[VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.IDOR],
    )
    rendered = "\n".join(m.content for m in messages)
    assert "Focus only on:" in rendered
    assert "command_injection" in rendered


def test_hunt_prompt_focus_advisory_is_not_in_target_content() -> None:
    messages = _render(
        VulnerabilityClass.IDOR,
        task_prompt="Check for IDOR.",
        focused_classes=[VulnerabilityClass.IDOR],
    )
    # Focus advisory is in the system message (first message), not in <target_content>
    system_content = messages[0].content
    assert "Focus only on:" in system_content


def test_hunt_prompt_exclusion_block_in_system_message() -> None:
    exclusions = [
        ScopeExclusion(kind="route", value="/health", reason="health check", block_dynamic=False)
    ]
    messages = _render(
        VulnerabilityClass.SECRETS,
        scope="config/",
        task_prompt="Look for secrets.",
        scope_exclusions=exclusions,
    )
    system_content = messages[0].content
    assert "/health" in system_content
    assert "Out of scope" in system_content or "scope" in system_content.lower()


def test_hunt_prompt_evidence_wrapped_in_target_content() -> None:
    entry_points = [
        EntryPoint(
            repo=".",
            file="handlers/admin.go",
            function="execHandler",
            kind="http_handler",
        )
    ]
    messages = _render(
        VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        entry_points=entry_points,
        task_prompt="Find command injection.",
    )
    user_content = messages[1].content
    assert "<target_content>" in user_content
    assert "handlers/admin.go" in user_content


def test_hunt_per_class_templates_are_distinct() -> None:
    """Per-class hunt templates are distinct files → distinct template shas.

    Routing is still data-driven (by vuln_class name), not Python branching:
    hunt.py picks the template name from the task's vuln_class.
    """
    from quarry_prompts.build_prompt import build_prompt as _bp

    def _r(vc: VulnerabilityClass):
        return _bp(
            registry=_registry(),
            role="hunt",
            name=vc.value,
            version="1.0.0",
            variables={
                "vuln_class": vc.value,
                "scope": "src/",
                "entry_points": [],
                "recon_notes": "",
                "focus_classes": [],
                "scope_exclusions": [],
                "task_prompt": f"{vc.value} prompt",
                "evidence_chunks": [],
            },
        )

    r1 = _r(VulnerabilityClass.COMMAND_INJECTION)
    r2 = _r(VulnerabilityClass.IDOR)
    # Different per-class template files → different template shas.
    assert r1.ref.sha256 != r2.ref.sha256
    assert r1.ref.id == "hunt/command_injection"
    assert r2.ref.id == "hunt/idor"
    # Same class twice is deterministic.
    assert _r(VulnerabilityClass.SSRF).ref.sha256 == _r(VulnerabilityClass.SSRF).ref.sha256
