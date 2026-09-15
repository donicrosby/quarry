"""Deterministic backstop against mitigation_stretching abuse.

Run-5: the debater rejected a genuine `shell=True` cmdi (app.py:74-76) with a
mitigation_stretching FAIL citing `app.py:74-78` — where the only code is
`timeout=3`, `capture_output=True`, `check=False`. None of those are
mitigations. A future model regression must not be able to reintroduce this
silently, so quarry code — not the model — decides what evidence counts as a
real defensive primitive.
"""

from __future__ import annotations

import re
from pathlib import Path

from quarry.schemas import ChecklistConstraint, ChecklistItem, ChecklistOutcome

# Substrings that name an actual defensive primitive. A mitigation_stretching
# FAIL is only allowed to stand when its evidence cites one of these — the
# claim that a mitigation exists must name the mitigation.
_DEFENSIVE_PRIMITIVES: tuple[str, ...] = (
    "sanitiz",
    "allowlist",
    "allow-list",
    "whitelist",
    "escap",
    "encod",
    "parameteriz",
    "parametriz",
    "prepared statement",
    "shlex.quote",
    "quote(",
    "bleach",
    "validate",
    "validator",
    "pydantic",
    "regex",
    "re.fullmatch",
    "re.match",
    "int(",
    "float(",
    "ipaddress",
    "urlparse",
    "csrf",
    "auth",
    "permission",
    "is_admin",
    "require_",
    "depends(",
    "security",
    "html.escape",
    "markupsafe",
    "jinja",
    "orm",
    "sqlalchemy",
    "subprocess.run([",  # list-form argv (no shell)
    "shell=false",
    "shell=False",
)

# Arguments to subprocess/run that are explicitly NOT mitigations. Cited as
# evidence they are the tell-tale of a stretched FAIL.
_NON_MITIGATION_ARGS: tuple[str, ...] = (
    "timeout",
    "capture_output",
    "check=",
    "check =",
    "text=",
    "stdout=",
    "stderr=",
    "encoding=",
)

_CITE_RE = re.compile(r"[\w./-]+:\d+")

# A source_coherence FAIL must cite a file that does not exist, or name a
# concrete content mismatch. "app.py:74" with no explanation, on a file that
# exists, is the debater being lazy — the gate verifies the cite against the
# repo itself.
_MISMATCH_MARKERS: tuple[str, ...] = (
    "no file",
    "not found",
    "does not exist",
    "doesn't exist",
    "no such file",
    "no code at",
    "no code found",
    "mismatch",
    "does not match",
    "doesn't match",
    "not present",
    "absent",
    "different",
    "instead",
)


def _cited_paths(evidence: str) -> list[str]:
    """Extract repo-relative file paths cited in checklist evidence."""
    paths: list[str] = []
    for m in re.finditer(r"([\w./-]+\.\w+):\d+", evidence):
        p = m.group(1)
        if p not in paths:
            paths.append(p)
    return paths


def _names_primitive(evidence: str) -> bool:
    """True when the evidence text names a real defensive primitive."""
    low = evidence.lower()
    return any(p.lower() in low for p in _DEFENSIVE_PRIMITIVES)


def sanitize_checklist_fails(
    items: list[ChecklistItem],
    *,
    repo_root: str | Path | None = None,
) -> list[ChecklistItem]:
    """Downgrade unsupported FAILs to unresolved.

    mitigation_stretching: a FAIL asserts a working mitigation covers the
    claimed path; it is only credible when the evidence names the mitigation.
    Evidence citing no defensive primitive — or only non-mitigation subprocess
    arguments (timeout, capture_output, check=False) — is downgraded.

    source_coherence: a FAIL asserts a cited file/location does not exist or
    does not match. When *repo_root* is provided, the gate verifies the cite:
    if every cited path exists under the repo AND the evidence names no
    concrete mismatch marker, the FAIL is downgraded. Without *repo_root* the
    coherence FAIL is left untouched (no ground truth to check against).

    Other constraints are untouched.
    """
    out: list[ChecklistItem] = []
    for item in items:
        if item.outcome is not ChecklistOutcome.FAIL:
            out.append(item)
            continue
        if item.constraint is ChecklistConstraint.MITIGATION_STRETCHING and not _names_primitive(
            item.evidence
        ):
            out.append(_downgrade(item, "no defensive primitive named in evidence"))
        elif item.constraint is ChecklistConstraint.SOURCE_COHERENCE and repo_root is not None:
            if _coherence_fail_unsupported(item.evidence, Path(repo_root)):
                out.append(_downgrade(item, "cited file(s) exist and no mismatch named"))
            else:
                out.append(item)
        else:
            out.append(item)
    return out


def _downgrade(item: ChecklistItem, why: str) -> ChecklistItem:
    return item.model_copy(
        update={
            "outcome": ChecklistOutcome.UNRESOLVED,
            "evidence": (
                item.evidence + f" [gate: FAIL unsupported — {why}; downgraded to unresolved]"
            ),
        }
    )


def _coherence_fail_unsupported(evidence: str, repo_root: Path) -> bool:
    """True when a source_coherence FAIL is unsupported: every cited file
    exists under *repo_root* and the evidence names no concrete mismatch."""
    low = evidence.lower()
    if any(marker in low for marker in _MISMATCH_MARKERS):
        return False  # a concrete mismatch is claimed — let it stand
    paths = _cited_paths(evidence)
    if not paths:
        return False  # nothing to verify — don't touch it
    return all((repo_root / p).is_file() for p in paths)
