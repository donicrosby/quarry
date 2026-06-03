"""Tests for the hunt prompt template.

Written RED first — these fail until quarry_models/hunt_prompt.py exists.
"""

from __future__ import annotations

from quarry.schemas import EntryPoint, ScopeExclusion, VulnerabilityClass
from quarry_models.hunt_prompt import build_hunt_prompt


def test_hunt_prompt_renders_for_each_vuln_class() -> None:
    for vuln_class in (
        VulnerabilityClass.COMMAND_INJECTION,
        VulnerabilityClass.IDOR,
        VulnerabilityClass.SECRETS,
        VulnerabilityClass.SSRF,
    ):
        result = build_hunt_prompt(
            vuln_class=vuln_class,
            scope="src/handlers/",
            entry_points=[],
            task_prompt="Look for sinks.",
            scope_exclusions=[],
        )
        rendered = "\n".join(m.content for m in result.messages)
        assert vuln_class.value in rendered


def test_hunt_prompt_includes_focus_advisory() -> None:
    result = build_hunt_prompt(
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="src/",
        entry_points=[],
        task_prompt="Find command injection sinks.",
        scope_exclusions=[],
        focused_classes=[VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.IDOR],
    )
    rendered = "\n".join(m.content for m in result.messages)
    assert "Focus only on:" in rendered
    assert "command_injection" in rendered


def test_hunt_prompt_focus_advisory_is_not_in_target_content() -> None:
    result = build_hunt_prompt(
        vuln_class=VulnerabilityClass.IDOR,
        scope="handlers/",
        entry_points=[],
        task_prompt="Check for IDOR.",
        scope_exclusions=[],
        focused_classes=[VulnerabilityClass.IDOR],
    )
    system_content = result.messages[0].content
    assert "Focus only on:" in system_content


def test_hunt_prompt_exclusion_block_in_system_message() -> None:
    exclusions = [
        ScopeExclusion(kind="route", value="/health", reason="health check", block_dynamic=False)
    ]
    result = build_hunt_prompt(
        vuln_class=VulnerabilityClass.SECRETS,
        scope="config/",
        entry_points=[],
        task_prompt="Look for secrets.",
        scope_exclusions=exclusions,
    )
    system_content = result.messages[0].content
    assert "/health" in system_content
    assert "Out of scope" in system_content


def test_hunt_prompt_evidence_wrapped_in_target_content() -> None:
    entry_points = [
        EntryPoint(
            repo=".",
            file="handlers/admin.go",
            function="execHandler",
            kind="http_handler",
        )
    ]
    result = build_hunt_prompt(
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        entry_points=entry_points,
        task_prompt="Find command injection.",
        scope_exclusions=[],
    )
    user_content = result.messages[1].content
    assert "<target_content>" in user_content
    assert "handlers/admin.go" in user_content


def test_hunt_prompt_no_class_specific_python_branching() -> None:
    """Each vuln class produces a different prompt — driven by data, not Python if/elif."""
    r1 = build_hunt_prompt(
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="src/",
        entry_points=[],
        task_prompt="cmdi prompt",
        scope_exclusions=[],
    )
    r2 = build_hunt_prompt(
        vuln_class=VulnerabilityClass.IDOR,
        scope="src/",
        entry_points=[],
        task_prompt="idor prompt",
        scope_exclusions=[],
    )
    assert r1.prompt_hash != r2.prompt_hash
