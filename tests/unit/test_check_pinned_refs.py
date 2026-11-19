"""Tests for check_pinned_refs.py — the supply-chain pin gate.

Spec: openspec/changes/supply-chain-hardening. The guard must fail CI on any
GitHub Actions ``uses:`` ref or remote pre-commit ``rev:`` that is not a full
40-character commit SHA, and pass on the SHA-pinned tree it ships with.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add scripts/ to path so we can import check_pinned_refs
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import check_pinned_refs

REPO_ROOT = Path(__file__).parent.parent.parent
_SHA = "11d5960a326750d5838078e36cf38b85af677262"


def test_sha_pinned_uses_accepted() -> None:
    assert check_pinned_refs.check_uses(f"actions/checkout@{_SHA}") is None


@pytest.mark.parametrize(
    "ref",
    [
        "actions/checkout@v4",
        "actions/checkout@main",
        "actions/checkout",
        "actions/checkout@abc123",  # too short to be a commit SHA
    ],
)
def test_unpinned_uses_rejected(ref: str) -> None:
    assert check_pinned_refs.check_uses(ref) is not None


def test_local_and_docker_uses_exempt() -> None:
    assert check_pinned_refs.check_uses("./.github/actions/build") is None
    assert check_pinned_refs.check_uses("docker://alpine:3.19") is None


def test_check_workflow_flags_unpinned_and_names_action() -> None:
    text = "\n".join(
        [
            "jobs:",
            "  build:",
            "    steps:",
            "      - uses: actions/checkout@v4",
            f"      - uses: actions/setup-python@{_SHA}",
        ]
    )
    problems = check_pinned_refs.check_workflow(text)
    assert len(problems) == 1
    assert "actions/checkout@v4" in problems[0]
    assert "commit SHA" in problems[0]


def test_check_workflow_passes_on_pinned() -> None:
    text = f"      - uses: actions/checkout@{_SHA} # v4\n"
    assert check_pinned_refs.check_workflow(text) == []


def test_check_precommit_flags_remote_tag_rev() -> None:
    text = "repos:\n  - repo: https://github.com/x/y\n    rev: v1.2.3\n"
    problems = check_pinned_refs.check_precommit(text)
    assert len(problems) == 1
    assert "v1.2.3" in problems[0]


def test_check_precommit_flags_missing_rev() -> None:
    text = "repos:\n  - repo: https://github.com/x/y\n    hooks:\n      - id: z\n"
    problems = check_pinned_refs.check_precommit(text)
    assert len(problems) == 1
    assert "no rev" in problems[0]


def test_check_precommit_accepts_pinned_and_exempts_local() -> None:
    text = (
        "repos:\n"
        "  - repo: local\n"
        "    hooks:\n"
        "      - id: foo\n"
        "  - repo: https://github.com/x/y\n"
        f"    rev: {_SHA} # v1.2.3\n"
    )
    assert check_pinned_refs.check_precommit(text) == []


def test_check_repository_flags_unpinned_workflow(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("      - uses: actions/checkout@v4\n", encoding="utf-8")
    problems = check_pinned_refs.check_repository(tmp_path)
    assert any("ci.yml" in p and "actions/checkout@v4" in p for p in problems)


def test_current_tree_has_no_unpinned_refs() -> None:
    """The shipped repository pins every action and remote pre-commit hook."""
    problems = check_pinned_refs.check_repository(REPO_ROOT)
    assert problems == [], "\n".join(problems)


def test_main_returns_failure_on_unpinned(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("      - uses: actions/checkout@main\n", encoding="utf-8")
    assert check_pinned_refs.main([str(tmp_path)]) == 1


def test_main_returns_success_on_pinned(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(f"      - uses: actions/checkout@{_SHA}\n", encoding="utf-8")
    assert check_pinned_refs.main([str(tmp_path)]) == 0


def test_ci_workflow_enforces_pins_and_locked_deps() -> None:
    """CI runs the pin check and installs from the lock (acceptance criteria)."""
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "scripts/check_pinned_refs.py" in ci
    assert "uv sync --group dev --frozen" in ci
    assert "uv lock --check" in ci


def test_release_workflow_signs_and_emits_sbom_before_release() -> None:
    """Releases are signed + carry an SBOM, and cannot release unsigned."""
    release = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "id-token: write" in release
    assert "cosign sign" in release
    assert "cyclonedx1.5" in release
    # Signing must happen before the GitHub Release is created, so a failed
    # signature blocks publishing rather than producing an unsigned release.
    assert release.index("cosign sign") < release.index("gh release create")
