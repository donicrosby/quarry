"""Per-class dynamic_validate templates: render + registry completeness.

Written RED first: the eight new per-class templates (sql_injection, xss,
ssti, xxe, file_upload, auth, open_redirect, csrf) do not exist yet, so the
parametrized render tests fail until ``prompts/dynamic_validate/<slug>.1.0.0.j2``
is authored (openspec per-class-dynamic-validation, tasks 2.1-2.3).

The registry-completeness test pins the routing contract implemented in
``quarry_activities.dynamic_validate`` (per-class template preferred, generic
``dynamic_validate/dynamic_validate`` fallback) for EVERY ``VulnerabilityClass``
enum member.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry, TemplateNotFoundError

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"

# The eight new per-class templates (openspec per-class-dynamic-validation 2.x).
NEW_TEMPLATES = [
    "sql_injection",
    "xss",
    "ssti",
    "xxe",
    "file_upload",
    "auth",
    "open_redirect",
    "csrf",
]

# Class-specific verdict-guidance marker each template must carry — the
# instruction that distinguishes this class's corroborated/not_corroborated
# mapping from the generic template.
CLASS_MARKERS: dict[str, str] = {
    "sql_injection": "differential",  # boolean TRUE/FALSE probe pair
    "xss": "unescaped",  # marker reflected without encoding
    "ssti": "{{7*7}}",  # arithmetic marker evaluated to 49
    "xxe": "external entity",  # entity resolution probe
    "file_upload": "extension",  # extension/content-type validation probe
    "auth": "unauthenticated",  # protected endpoint served without auth
    "open_redirect": "Location",  # 3xx Location follows attacker input
    "csrf": "token",  # state change without a valid CSRF token
}

# Enum members expected to resolve to a DEDICATED dynamic_validate template
# after this change. csrf is deliberately absent: it is NOT a VulnerabilityClass
# enum member — its template is pinned by the render tests above, not by the
# enum completeness sweep.
EXPECTED_PER_CLASS = frozenset(
    {
        "idor",
        "command_injection",
        "ssrf",
        "sql_injection",
        "xss",
        "ssti",
        "xxe",
        "file_upload",
        "auth",
        "open_redirect",
    }
)


def _registry() -> PromptRegistry:
    return PromptRegistry(prompts_root=PROMPTS_ROOT)


def _variables(slug: str) -> dict[str, Any]:
    """The exact variable set dynamic_validate.py threads into the template."""
    return {
        "vuln_class": slug,
        "title": f"{slug} candidate on /items",
        "affected_component": "src/routes/items.py:42",
        "hypothesis": f"The {slug} sink at items.py:42 handles user input unsafely.",
        "target_summary": "http://127.0.0.1:8001",
        "prior_attempts_json": None,
        "evidence_chunks": ["src/routes/items.py:40-50\ndef handler(req):\n    sink(req.q)"],
    }


@pytest.mark.parametrize("slug", NEW_TEMPLATES)
def test_template_renders_with_standard_context(slug: str) -> None:
    rendered = build_prompt(
        registry=_registry(),
        role="dynamic_validate",
        name=slug,
        version="1.0.0",
        variables=_variables(slug),
    )
    assert rendered.ref.id == f"dynamic_validate/{slug}"
    body = "\n".join(m.content for m in rendered.messages)
    # Same output contract as the generic/idor templates.
    assert "proposed_http_specs" in body
    assert "<target_content>" in body
    # Standard context variables thread through.
    assert "The " + slug + " sink at items.py:42" in body
    assert "src/routes/items.py:40-50" in body
    assert "http://127.0.0.1:8001" in body


@pytest.mark.parametrize("slug", NEW_TEMPLATES)
def test_template_contains_class_specific_verdict_guidance(slug: str) -> None:
    rendered = build_prompt(
        registry=_registry(),
        role="dynamic_validate",
        name=slug,
        version="1.0.0",
        variables=_variables(slug),
    )
    system = rendered.messages[0].content
    assert CLASS_MARKERS[slug].lower() in system.lower()
    # Verdict vocabulary must stay intact.
    for verdict in ("corroborated", "not_corroborated", "inconclusive"):
        assert verdict in system


@pytest.mark.parametrize("slug", NEW_TEMPLATES)
def test_template_prior_attempts_block_is_conditional(slug: str) -> None:
    """target_summary/prior_attempts render only when provided (idor parity)."""
    variables = _variables(slug)
    variables["prior_attempts_json"] = '[{"attempt": 1, "outcome": "refused"}]'
    rendered = build_prompt(
        registry=_registry(),
        role="dynamic_validate",
        name=slug,
        version="1.0.0",
        variables=variables,
    )
    body = "\n".join(m.content for m in rendered.messages)
    assert "prior_attempts" in body


@pytest.mark.parametrize("vc", list(VulnerabilityClass), ids=[c.value for c in VulnerabilityClass])
def test_every_enum_member_resolves_to_class_template_or_generic(
    vc: VulnerabilityClass,
) -> None:
    """Mirror dynamic_validate.py routing: per-class first, generic fallback.

    Members with a dedicated template MUST resolve to it (no silent fallback);
    members without one MUST fall back to the generic template (routing never
    raises past the fallback).
    """
    reg = _registry()
    try:
        prompt = build_prompt(
            registry=reg,
            role="dynamic_validate",
            name=vc.value,
            version="1.0.0",
            variables=_variables(vc.value),
        )
        resolved = prompt.ref.id
    except TemplateNotFoundError:
        resolved = "dynamic_validate/dynamic_validate"

    if vc.value in EXPECTED_PER_CLASS:
        assert resolved == f"dynamic_validate/{vc.value}"
    else:
        assert resolved == "dynamic_validate/dynamic_validate"


def test_all_per_class_templates_have_distinct_hashes() -> None:
    reg = _registry()
    shas = {
        build_prompt(
            registry=reg,
            role="dynamic_validate",
            name=slug,
            version="1.0.0",
            variables=_variables(slug),
        ).ref.sha256
        for slug in sorted(EXPECTED_PER_CLASS | {"csrf"})
    }
    assert len(shas) == len(EXPECTED_PER_CLASS) + 1  # csrf included, all distinct
