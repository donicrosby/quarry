"""Tests for the KB recon prompt template (prompts/recon/knowledge_base.1.0.0.j2).

Written RED first for openspec change candidate-precision-and-calibration,
task 2.2: read/find/grep tools only; the agent returns structured output and
the harness writes the files; every lifted partial carries the Mantis
(Apache-2.0, via Shannon) attribution header per openspec/config.yaml's
attribution rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jinja2 import UndefinedError

from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"
KB_TEMPLATE = PROMPTS_ROOT / "recon" / "knowledge_base.1.0.0.j2"

_VARIABLES: dict[str, object] = {
    "subsystem_names": ["api", "services"],
    "languages": ["python"],
    "vuln_classes": ["command_injection", "ssrf"],
    "evidence_chunks": [],
}


def _rendered_text() -> str:
    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    rendered = build_prompt(
        registry=registry,
        role="recon",
        name="knowledge_base",
        version="1.0.0",
        variables=dict(_VARIABLES),
    )
    return "\n".join(m.content for m in rendered.messages)


def test_kb_recon_template_exists() -> None:
    assert KB_TEMPLATE.exists(), (
        "prompts/recon/knowledge_base.1.0.0.j2 must exist — the KB recon agent "
        "renders its system/developer/evidence/output_schema parts from it"
    )


def test_kb_recon_template_renders_all_parts() -> None:
    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    rendered = build_prompt(
        registry=registry,
        role="recon",
        name="knowledge_base",
        version="1.0.0",
        variables=dict(_VARIABLES),
    )
    for part in ("system", "developer", "evidence", "output_schema"):
        assert rendered.part_hashes.get(part), f"missing canonical part: {part}"
    assert rendered.messages[0].role == "system"


def test_kb_recon_template_carries_mantis_attribution_header() -> None:
    """Lifted prompt content names Mantis (Apache-2.0) via Shannon (config.yaml)."""
    raw = KB_TEMPLATE.read_text(encoding="utf-8")
    header = raw.split("<!-- QUARRY:PART:system -->")[0]
    assert "Mantis" in header
    assert "Apache-2.0" in header
    assert "Shannon" in header


def test_kb_recon_template_restricts_tools_to_read_only() -> None:
    text = _rendered_text()
    # Read/find/grep only — the agent never writes; the harness writes files.
    for tool in ("read_file", "list_dir", "grep"):
        assert tool in text
    assert "search_code" in text  # find: structural search
    for forbidden in ("write_file", "http_request", "run_in_sandbox", "run_command"):
        assert forbidden not in text, f"write/exec tool {forbidden} must not be offered"
    # The structured-output contract is stated in the template.
    assert "structured output" in text or "structured" in text


def test_kb_recon_template_requires_grounding() -> None:
    """The output schema requires cited source locations for every assertion."""
    text = _rendered_text()
    assert "source_locations" in text


def test_kb_recon_template_strict_undefined() -> None:
    """Missing render variables raise under StrictUndefined (no silent empty parts)."""
    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    with pytest.raises(UndefinedError):
        build_prompt(
            registry=registry,
            role="recon",
            name="knowledge_base",
            version="1.0.0",
            variables={},
        )
