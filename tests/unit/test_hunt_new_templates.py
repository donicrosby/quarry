"""Render tests for the new per-class hunt templates (csrf, file_upload).

Written RED first (openspec per-class-dynamic-validation, tasks 3.1/3.2 —
corrected: prompts/hunt/xxe.1.0.0.j2 already existed, so the real gap is
csrf + file_upload only). Modeled on test_hunt_template_routing.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"

NEW_HUNT_TEMPLATES = ["csrf", "file_upload"]

# Class-specific methodology markers (sinks/sources each template must name).
HUNT_MARKERS: dict[str, list[str]] = {
    "csrf": ["token", "state-changing"],
    "file_upload": ["multipart", "extension"],
}


def _registry() -> PromptRegistry:
    return PromptRegistry(prompts_root=PROMPTS_ROOT)


def _variables(vuln_class: str) -> dict[str, Any]:
    return {
        "vuln_class": vuln_class,
        "scope": "src/",
        "entry_points": [{"repo": ".", "file": "app.py", "function": "h", "kind": "http_handler"}],
        "recon_notes": "candidate sinks: app.py:1",
        "focus_classes": [],
        "scope_exclusions": [],
        "task_prompt": "Look for sinks.",
        "evidence_chunks": [],
    }


@pytest.mark.parametrize("slug", NEW_HUNT_TEMPLATES)
def test_new_hunt_template_resolves_and_renders(slug: str) -> None:
    rendered = build_prompt(
        registry=_registry(),
        role="hunt",
        name=slug,
        version="1.0.0",
        variables=_variables(slug),
    )
    assert rendered.ref.id == f"hunt/{slug}"
    body = "\n".join(m.content for m in rendered.messages)
    assert "<target_content>" in body
    assert "app.py::h" in body  # entry point threaded through
    assert "candidate sinks: app.py:1" in body  # recon_notes threaded through


@pytest.mark.parametrize("slug", NEW_HUNT_TEMPLATES)
def test_new_hunt_template_contains_class_specific_guidance(slug: str) -> None:
    rendered = build_prompt(
        registry=_registry(),
        role="hunt",
        name=slug,
        version="1.0.0",
        variables=_variables(slug),
    )
    body = "\n".join(m.content for m in rendered.messages)
    for marker in HUNT_MARKERS[slug]:
        assert marker.lower() in body.lower()


@pytest.mark.parametrize("slug", NEW_HUNT_TEMPLATES)
def test_new_hunt_template_distinct_from_each_other(slug: str) -> None:
    """Two new files must be distinct templates (distinct shas)."""
    reg = _registry()
    shas = {
        s: build_prompt(
            registry=reg, role="hunt", name=s, version="1.0.0", variables=_variables(s)
        ).ref.sha256
        for s in NEW_HUNT_TEMPLATES
    }
    assert len(set(shas.values())) == len(NEW_HUNT_TEMPLATES)


def test_file_upload_no_longer_falls_back_to_generic_hunt() -> None:
    """file_upload now resolves to its dedicated template (supersedes the old
    fallback pin in test_hunt_template_routing.py)."""
    rendered = build_prompt(
        registry=_registry(),
        role="hunt",
        name=VulnerabilityClass.FILE_UPLOAD.value,
        version="1.0.0",
        variables=_variables(VulnerabilityClass.FILE_UPLOAD.value),
    )
    assert rendered.ref.id == "hunt/file_upload"
