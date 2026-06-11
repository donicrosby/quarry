"""Tests for PromptRegistry.

Written RED first — these fail until quarry_prompts/registry.py exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def test_registry_loads_hunt_template(tmp_path: Path) -> None:
    """PromptRegistry can load the hunt/hunt template and returns a LoadedTemplate."""
    from quarry_prompts.registry import PromptRegistry

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    template = registry.load("hunt", "hunt", "1.0.0")

    assert template.ref.id == "hunt/hunt"
    assert template.ref.version == "1.0.0"
    assert len(template.ref.sha256) == 64  # hex sha256


def test_registry_sha256_is_deterministic(tmp_path: Path) -> None:
    """Loading the same template twice returns the same sha256."""
    from quarry_prompts.registry import PromptRegistry

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    t1 = registry.load("hunt", "hunt", "1.0.0")
    t2 = registry.load("hunt", "hunt", "1.0.0")
    assert t1.ref.sha256 == t2.ref.sha256


def test_registry_raises_on_missing_template() -> None:
    from quarry_prompts.registry import PromptRegistry, TemplateNotFoundError

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    with pytest.raises(TemplateNotFoundError, match="does_not_exist"):
        registry.load("hunt", "does_not_exist", "9.9.9")


def test_registry_raises_on_jinja_syntax_error(tmp_path: Path) -> None:
    """A template with a Jinja syntax error raises TemplateSyntaxError on load."""
    from jinja2 import TemplateSyntaxError

    from quarry_prompts.registry import PromptRegistry

    bad_template_dir = tmp_path / "test_role"
    bad_template_dir.mkdir()
    (bad_template_dir / "bad.1.0.0.j2").write_text("{% for x in %}", encoding="utf-8")

    registry = PromptRegistry(prompts_root=tmp_path)
    with pytest.raises(TemplateSyntaxError):
        registry.load("test_role", "bad", "1.0.0")


def test_registry_strict_undefined_raises_on_missing_variable(tmp_path: Path) -> None:
    """Rendering a template with a missing variable raises UndefinedError."""
    from jinja2 import UndefinedError

    from quarry_prompts.registry import PromptRegistry

    role_dir = tmp_path / "myrole"
    role_dir.mkdir()
    (role_dir / "mytemplate.1.0.0.j2").write_text("Hello {{ required_var }}", encoding="utf-8")

    registry = PromptRegistry(prompts_root=tmp_path)
    template = registry.load("myrole", "mytemplate", "1.0.0")

    with pytest.raises(UndefinedError):
        template.render({})  # no required_var supplied
