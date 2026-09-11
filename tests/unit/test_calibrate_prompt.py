"""Render tests for the calibration rule-catalogue prompt.

Written RED first for openspec change candidate-precision-and-calibration,
task 4.2 (severity-calibration spec: "Fixed downgrade and cap rule catalogue").

The prompt lives at prompts/calibrate/calibrate.1.0.0.j2, carries the Mantis
(Apache-2.0, via Shannon) attribution header, and renders the fixed rule
catalogue plus the finding under calibration.
"""

from __future__ import annotations

from pathlib import Path

from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt

_ROLE = "calibrate"
_NAME = "calibrate"
_VERSION = "1.0.0"
_TEMPLATE = Path(__file__).parent.parent.parent / "prompts" / _ROLE / f"{_NAME}.{_VERSION}.j2"


def _variables() -> dict[str, object]:
    return {
        "vuln_class": "command_injection",
        "title": "Unsanitized exec",
        "file": "src/admin.py",
        "line_start": 42,
        "line_end": 50,
        "raw_severity": "high",
        "confidence": "high",
        "description": "User input reaches os.exec without sanitization.",
        "affected_code_snippet": "cmd = f'ping {host}'",
        "reproduced": "no",
        "blast_radius": "unknown",
        "vector": "deterministic",
    }


def test_calibrate_template_exists_and_loads() -> None:
    registry = get_registry()
    template = registry.load(_ROLE, _NAME, _VERSION)
    assert template.ref.id == "calibrate/calibrate"
    assert template.ref.version == _VERSION


def test_calibrate_prompt_renders_rule_catalogue() -> None:
    rendered = build_prompt(
        registry=get_registry(),
        role=_ROLE,
        name=_NAME,
        version=_VERSION,
        variables=_variables(),
    )
    system_text = rendered.messages[0].content

    # The fixed rule catalogue is rendered (auditable, not free-form).
    assert "static-only-no-critical" in system_text
    assert "self-contained-blast-radius-cap-medium" in system_text
    assert "probabilistic-vector-cap-high" in system_text


def test_calibrate_prompt_carries_mantis_shannon_attribution() -> None:
    """Lifted prompt content names Mantis (Apache-2.0) via Shannon (D6)."""
    source = _TEMPLATE.read_text(encoding="utf-8")

    assert "Mantis" in source
    assert "Apache-2.0" in source
    assert "Shannon" in source


def test_calibrate_prompt_renders_finding_context() -> None:
    rendered = build_prompt(
        registry=get_registry(),
        role=_ROLE,
        name=_NAME,
        version=_VERSION,
        variables=_variables(),
    )
    user_text = rendered.messages[1].content

    assert "command_injection" in user_text
    assert "src/admin.py" in user_text
    assert "raw severity: high" in user_text.lower() or "high" in user_text


def test_calibrate_prompt_declares_output_schema() -> None:
    rendered = build_prompt(
        registry=get_registry(),
        role=_ROLE,
        name=_NAME,
        version=_VERSION,
        variables=_variables(),
    )
    user_text = rendered.messages[1].content

    assert "calibrated_severity" in user_text
    assert "calibrated_priority" in user_text
    assert "firing_rule_ids" in user_text
