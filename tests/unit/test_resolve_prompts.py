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
    manifest = resolve_prompts(
        registry=registry,
        role_templates=[("hunt", "hunt", "1.0.0"), ("recon", "subsystem", "1.0.0")],
    )

    assert isinstance(manifest, RegistryManifest)
    assert "hunt/hunt" in manifest.entries
    assert "recon/subsystem" in manifest.entries


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
