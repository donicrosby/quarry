"""Tests for resolve_prompts() startup validation.

Written RED first.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def test_resolve_prompts_succeeds_on_valid_templates() -> None:
    from quarry_prompts.registry import PromptRegistry
    from quarry_prompts.resolve import RegistryManifest, resolve_prompts

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    role_templates = [
        ("hunt", "hunt", "1.0.0"),
        ("recon", "subsystem", "1.0.0"),
        ("validate", "validate", "1.0.0"),
        # Per-class hunt templates (one per known VulnerabilityClass with a prompt).
        ("hunt", "ssrf", "1.0.0"),
        ("hunt", "command_injection", "1.0.0"),
        ("hunt", "sql_injection", "1.0.0"),
        ("hunt", "xss", "1.0.0"),
        ("hunt", "idor", "1.0.0"),
        ("hunt", "secrets", "1.0.0"),
        ("hunt", "path_traversal", "1.0.0"),
        ("hunt", "open_redirect", "1.0.0"),
        ("hunt", "ssti", "1.0.0"),
        ("hunt", "insecure_deserialization", "1.0.0"),
        ("hunt", "xxe", "1.0.0"),
        ("hunt", "ldap_injection", "1.0.0"),
        ("hunt", "mass_assignment", "1.0.0"),
        ("hunt", "auth", "1.0.0"),
        ("hunt", "security_misconfiguration", "1.0.0"),
        ("hunt", "insecure_design", "1.0.0"),
        ("hunt", "weak_crypto", "1.0.0"),
        # Dynamic-validation prompt family (generic + high-value per-class).
        ("dynamic_validate", "dynamic_validate", "1.0.0"),
        ("dynamic_validate", "idor", "1.0.0"),
        ("dynamic_validate", "command_injection", "1.0.0"),
        ("dynamic_validate", "ssrf", "1.0.0"),
    ]
    manifest = resolve_prompts(registry=registry, role_templates=role_templates)

    assert isinstance(manifest, RegistryManifest)
    assert "hunt/hunt" in manifest.entries
    assert "recon/subsystem" in manifest.entries
    assert "validate/validate" in manifest.entries
    for cls in ("ssrf", "command_injection", "sql_injection", "xss", "idor", "secrets"):
        assert f"hunt/{cls}" in manifest.entries
    # The dynamic-validation family must resolve (generic + per-class).
    assert "dynamic_validate/dynamic_validate" in manifest.entries
    for cls in ("idor", "command_injection", "ssrf"):
        assert f"dynamic_validate/{cls}" in manifest.entries


def test_resolve_prompts_raises_on_missing_template() -> None:
    from quarry_prompts.registry import PromptRegistry
    from quarry_prompts.resolve import resolve_prompts

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    with pytest.raises(Exception, match="does_not_exist"):
        resolve_prompts(
            registry=registry,
            role_templates=[("hunt", "does_not_exist", "9.9.9")],
        )


def test_resolve_prompts_raises_on_jinja_syntax_error(tmp_path: Path) -> None:
    from jinja2 import TemplateSyntaxError

    from quarry_prompts.registry import PromptRegistry
    from quarry_prompts.resolve import resolve_prompts

    bad_dir = tmp_path / "myrole"
    bad_dir.mkdir()
    (bad_dir / "bad.1.0.0.j2").write_text("{% for x in %}", encoding="utf-8")

    registry = PromptRegistry(prompts_root=tmp_path)
    with pytest.raises(TemplateSyntaxError):
        resolve_prompts(
            registry=registry,
            role_templates=[("myrole", "bad", "1.0.0")],
        )
