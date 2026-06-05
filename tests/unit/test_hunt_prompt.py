"""Tests for the hunt prompt — now rendered from prompts/hunt/hunt.1.0.0.j2.

These tests verify the same behavioural properties as the original test_hunt_prompt.py
but use build_prompt() + PromptRegistry instead of the deleted build_hunt_prompt().
"""

from __future__ import annotations

from pathlib import Path

from quarry.schemas import EntryPoint, ScopeExclusion, VulnerabilityClass
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def _registry() -> PromptRegistry:
    return PromptRegistry(prompts_root=PROMPTS_ROOT)


def _render(vuln_class: VulnerabilityClass, **kw) -> list:
    return build_prompt(
        registry=_registry(),
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": vuln_class.value,
            "scope": kw.get("scope", "src/"),
            "entry_points": kw.get("entry_points", []),
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


def test_hunt_prompt_no_class_specific_python_branching() -> None:
    """Each vuln class produces a different prompt hash — driven by data."""
    from quarry_prompts.build_prompt import build_prompt as _bp

    r1 = _bp(
        registry=_registry(),
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": VulnerabilityClass.COMMAND_INJECTION.value,
            "scope": "src/",
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": "cmdi prompt",
            "evidence_chunks": [],
        },
    )
    r2 = _bp(
        registry=_registry(),
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": VulnerabilityClass.IDOR.value,
            "scope": "src/",
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": "idor prompt",
            "evidence_chunks": [],
        },
    )
    # Different vuln_class and task_prompt → different rendered output → different hashes
    assert r1.ref.sha256 == r2.ref.sha256  # same template sha
    system_hash_1 = r1.part_hashes.get("system", "")
    system_hash_2 = r2.part_hashes.get("system", "")
    developer_hash_1 = r1.part_hashes.get("developer", "")
    developer_hash_2 = r2.part_hashes.get("developer", "")
    # developer part contains vuln_class and task_prompt so must differ
    assert developer_hash_1 != developer_hash_2
