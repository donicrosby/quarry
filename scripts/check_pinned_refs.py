#!/usr/bin/env python3
"""check_pinned_refs.py — supply-chain pin gate.

Spec: ``openspec/changes/supply-chain-hardening``. Quarry executes
model-generated payloads by design, so whatever CI executes is part of the
attack surface: a floating tag/branch ref lets a compromised or renamed
upstream mutate what Quarry builds without any Quarry-side diff.

This guard fails when either:

  * a GitHub Actions ``uses:`` reference in ``.github/workflows/*.yml`` is not a
    remote action pinned to a full 40-character commit SHA, or
  * a remote ``repo:`` entry in ``.pre-commit-config.yaml`` has a ``rev:`` that
    is not a 40-character commit SHA (or has no ``rev`` at all).

Local refs are exempt: ``./`` actions, ``docker://`` image refs, and the
``repo: local`` / ``repo: meta`` pre-commit entries, which execute from the
working tree rather than a remote revision.

Usage:
    python scripts/check_pinned_refs.py [repo_root]
    task supply-chain-pins
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# `uses: <ref>` at the start of a YAML mapping (optionally a `- item`).
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>\S+)")
# `rev: <ref>` inside `.pre-commit-config.yaml`.
_REV_RE = re.compile(r"^\s*rev:\s*(?P<value>\S+)")
# `repo: <url|local|meta>` inside `.pre-commit-config.yaml` (a list item).
_REPO_RE = re.compile(r"^\s*(?:-\s*)?repo:\s*(?P<value>\S+)")

# `uses:` values that are not remote actions (nothing remote to pin).
_LOCAL_USES_PREFIXES = ("./", "../", "docker://")
# pre-commit `repo:` values that are not remote repositories.
_LOCAL_PRECOMMIT_REPOS = frozenset({"local", "meta"})


def _clean(value: str) -> str:
    """Drop surrounding quotes and any trailing inline YAML comment."""
    return value.strip().strip("\"'").split("#", 1)[0].strip()


def check_uses(ref: str) -> str | None:
    """Return an error message when a ``uses:`` ref is not commit-SHA pinned."""
    if ref.startswith(_LOCAL_USES_PREFIXES):
        return None
    if "@" not in ref:
        return f"'{ref}' has no @ref; pin to a full commit SHA (owner/repo@<sha>)"
    rev = ref.rsplit("@", 1)[1]
    if not _SHA_RE.match(rev):
        return f"'{ref}' is pinned to '{rev}', not a 40-character commit SHA"
    return None


def check_workflow(text: str) -> list[str]:
    """Return one problem string per unpinned action in a workflow file."""
    problems: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = _USES_RE.match(line)
        if match is None:
            continue
        error = check_uses(_clean(match.group("value")))
        if error is not None:
            problems.append(f"line {lineno}: {error}")
    return problems


def _precommit_entries(text: str) -> list[tuple[int, str, str | None]]:
    """Collect ``(lineno, repo, rev)`` for every repo entry, in file order."""
    entries: list[tuple[int, str, str | None]] = []
    repo: str | None = None
    repo_line = 0
    rev: str | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        repo_match = _REPO_RE.match(line)
        if repo_match is not None:
            if repo is not None:
                entries.append((repo_line, repo, rev))
            repo = _clean(repo_match.group("value"))
            repo_line = lineno
            rev = None
            continue
        rev_match = _REV_RE.match(line)
        if rev_match is not None and repo is not None:
            rev = _clean(rev_match.group("value"))
    if repo is not None:
        entries.append((repo_line, repo, rev))
    return entries


def check_precommit(text: str) -> list[str]:
    """Return one problem string per unpinned remote pre-commit hook."""
    problems: list[str] = []
    for lineno, repo, rev in _precommit_entries(text):
        if repo in _LOCAL_PRECOMMIT_REPOS:
            continue
        if rev is None:
            problems.append(
                f"line {lineno}: repo '{repo}' has no rev; pin to a 40-character commit SHA"
            )
        elif not _SHA_RE.match(rev):
            problems.append(
                f"line {lineno}: repo '{repo}' rev '{rev}' is not a 40-character commit SHA"
            )
    return problems


def check_repository(root: Path) -> list[str]:
    """Check every workflow file and the pre-commit config under ``root``."""
    problems: list[str] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for workflow in sorted(workflows.glob("*.y*ml")):
            for problem in check_workflow(workflow.read_text(encoding="utf-8")):
                problems.append(f"{workflow.relative_to(root)}: {problem}")
    precommit = root / ".pre-commit-config.yaml"
    if precommit.is_file():
        for problem in check_precommit(precommit.read_text(encoding="utf-8")):
            problems.append(f"{precommit.relative_to(root)}: {problem}")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parent.parent
    problems = check_repository(root)
    if problems:
        print("Unpinned supply-chain references found:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nPin every action to `owner/repo@<40-char commit SHA>` and every "
            "remote pre-commit hook `rev:` to a commit SHA.",
            file=sys.stderr,
        )
        return 1
    print("All GitHub Actions and remote pre-commit hooks are pinned to commit SHAs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
