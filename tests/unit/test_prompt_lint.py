"""Tests for prompt_lint.py — the CI guard for prompt-text in Python.

These tests verify the heuristics catch real violations and pass on legitimate code.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add scripts/ to path so we can import prompt_lint
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import prompt_lint


def test_lint_passes_on_current_src() -> None:
    """The current src/ tree passes prompt-lint with exit code 0."""
    src = Path(__file__).parent.parent.parent / "src"
    result = prompt_lint.main(str(src))
    assert result == 0, "prompt-lint found violations in src/ — see output above"


def test_lint_detects_system_prompt_constant(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    (pkg_dir / "bad.py").write_text('_SYSTEM_PROMPT = "You are an agent."\n', encoding="utf-8")
    violations = prompt_lint.check_file(pkg_dir / "bad.py")
    assert any("_SYSTEM_PROMPT" in reason for _, reason in violations)


def test_lint_detects_prompt_phrase_in_long_string(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    long_prompt = (
        "You are a security researcher hunting for vulnerabilities.\nUse the provided tools.\n" * 5
    )
    (pkg_dir / "bad.py").write_text(f'PROMPT = """{long_prompt}"""\n', encoding="utf-8")
    violations = prompt_lint.check_file(pkg_dir / "bad.py")
    assert len(violations) >= 1


def test_lint_passes_on_short_strings(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    (pkg_dir / "ok.py").write_text('description = "You are a good person"\n', encoding="utf-8")
    violations = prompt_lint.check_file(pkg_dir / "ok.py")
    assert violations == []


def test_lint_passes_on_docstrings(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    (pkg_dir / "ok.py").write_text(
        '"""You are a recon agent — this is a docstring, not a prompt."""\n',
        encoding="utf-8",
    )
    violations = prompt_lint.check_file(pkg_dir / "ok.py")
    assert violations == []
