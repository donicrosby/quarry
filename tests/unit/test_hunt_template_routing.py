"""Per-class hunt template routing + render coverage.

hunt.py routes the hunt prompt by vuln_class (prompts/hunt/<vuln_class>.1.0.0.j2)
and falls back to the generic hunt/hunt template for classes without one
(e.g. file_upload). These tests pin both behaviours and that every per-class
template resolves and renders with the variable set hunt.py provides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry, TemplateNotFoundError

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"

PER_CLASS = [
    VulnerabilityClass.SSRF,
    VulnerabilityClass.COMMAND_INJECTION,
    VulnerabilityClass.SQL_INJECTION,
    VulnerabilityClass.XSS,
    VulnerabilityClass.IDOR,
    VulnerabilityClass.SECRETS,
    VulnerabilityClass.PATH_TRAVERSAL,
    VulnerabilityClass.OPEN_REDIRECT,
    VulnerabilityClass.SSTI,
    VulnerabilityClass.INSECURE_DESERIALIZATION,
    VulnerabilityClass.XXE,
    VulnerabilityClass.LDAP_INJECTION,
    VulnerabilityClass.MASS_ASSIGNMENT,
    VulnerabilityClass.AUTH,
    VulnerabilityClass.SECURITY_MISCONFIGURATION,
    VulnerabilityClass.INSECURE_DESIGN,
    VulnerabilityClass.WEAK_CRYPTO,
    VulnerabilityClass.FILE_UPLOAD,
]


def _registry() -> PromptRegistry:
    return PromptRegistry(prompts_root=PROMPTS_ROOT)


def _variables(vc: VulnerabilityClass) -> dict[str, Any]:
    return {
        "vuln_class": vc.value,
        "scope": "src/",
        "entry_points": [{"repo": ".", "file": "app.py", "function": "h", "kind": "http_handler"}],
        "recon_notes": "SSRF sinks: app.py:1",
        "focus_classes": [],
        "scope_exclusions": [],
        "task_prompt": "Look for sinks.",
        "evidence_chunks": [],
    }


@pytest.mark.parametrize("vc", PER_CLASS, ids=[c.value for c in PER_CLASS])
def test_per_class_template_resolves_and_renders(vc: VulnerabilityClass) -> None:
    rendered = build_prompt(
        registry=_registry(),
        role="hunt",
        name=vc.value,
        version="1.0.0",
        variables=_variables(vc),
    )
    assert rendered.ref.id == f"hunt/{vc.value}"
    body = "\n".join(m.content for m in rendered.messages)
    assert vc.value in body
    assert "<target_content>" in body
    assert "app.py::h" in body  # entry point threaded through
    assert "SSRF sinks: app.py:1" in body  # recon_notes threaded through


def test_per_class_templates_have_distinct_hashes() -> None:
    reg = _registry()
    shas = {
        build_prompt(
            registry=reg, role="hunt", name=vc.value, version="1.0.0", variables=_variables(vc)
        ).ref.sha256
        for vc in PER_CLASS
    }
    assert len(shas) == len(PER_CLASS)


def test_file_upload_resolves_to_its_dedicated_template() -> None:
    """file_upload now has its own per-class hunt template (added by the
    per-class-dynamic-validation change; previously it fell back to hunt/hunt).

    The generic fallback itself is still exercised: a name that has no template
    raises TemplateNotFoundError and the generic hunt/hunt template renders.
    """
    reg = _registry()
    vc = VulnerabilityClass.FILE_UPLOAD
    dedicated = build_prompt(
        registry=reg, role="hunt", name=vc.value, version="1.0.0", variables=_variables(vc)
    )
    assert dedicated.ref.id == "hunt/file_upload"
    assert "<target_content>" in "\n".join(m.content for m in dedicated.messages)

    with pytest.raises(TemplateNotFoundError):
        build_prompt(
            registry=reg,
            role="hunt",
            name="does_not_exist",
            version="1.0.0",
            variables=_variables(vc),
        )

    fallback = build_prompt(
        registry=reg, role="hunt", name="hunt", version="1.0.0", variables=_variables(vc)
    )
    assert fallback.ref.id == "hunt/hunt"
    assert "<target_content>" in "\n".join(m.content for m in fallback.messages)
