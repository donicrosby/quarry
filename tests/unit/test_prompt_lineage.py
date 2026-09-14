"""Template lineage invariants.

A prompt version forked from an earlier version must retain the earlier
version's structural contract. Run 5 (scan 529c9499) regressed 2/4 -> 1/4
because validate/refute 1.1.0 were authored from a stale pre-#46 copy of
1.0.0 and silently dropped the tool-calling schema and the example final
response; the debater degraded to ``refuted:true`` with empty reasons and
the reasoner's validated verdicts were downgraded. These tests make silent
section loss a red test instead of a forensic session.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts" / "validate"

# Anchors every validate/refute template version >= 1.0.0 must contain.
# They encode the agentic tool-calling protocol added in PR #46 and the
# output contract the parsers depend on.
REQUIRED_ANCHORS: dict[str, list[str]] = {
    "validate": [
        "<!-- QUARRY:PART:system -->",
        "<!-- QUARRY:PART:output_schema -->",
        '"tool_calls"',
        '"proposed_actions"',
        "hypothesis",
        "target_ref",
        "expected_evidence",
        "why_this_tool",
        "Example final response",
    ],
    "refute": [
        "<!-- QUARRY:PART:system -->",
        '"tool_calls"',
        '"proposed_actions"',
        "hypothesis",
        "target_ref",
        "expected_evidence",
        "why_this_tool",
        "Example final response",
        "trust_boundary",
        "hypothetical_misuse",
    ],
}


def _template_files(name: str) -> list[Path]:
    files = sorted(PROMPTS_DIR.glob(f"{name}.*.j2"))
    assert files, f"no {name} templates found under {PROMPTS_DIR}"
    return files


def _version(path: Path) -> tuple[int, int, int]:
    stem = path.stem  # e.g. "validate.1.1.0"
    parts = stem.split(".")[-3:]
    a, b, c = (int(x) for x in parts)
    return (a, b, c)


@pytest.mark.parametrize("name", ["validate", "refute"])
def test_every_version_carries_required_anchors(name: str) -> None:
    """No version >= 1.0.0 may drop an anchor that 1.0.0 established."""
    for path in _template_files(name):
        text = path.read_text(encoding="utf-8")
        missing = [a for a in REQUIRED_ANCHORS[name] if a not in text]
        assert not missing, (
            f"{path.name} lost required anchor(s) {missing} present in the "
            "1.0.0 lineage — regenerate the version additively from HEAD "
            "1.0.0 instead of a stale copy"
        )


@pytest.mark.parametrize("name", ["validate", "refute"])
def test_higher_versions_are_supersets_of_1_0_0(name: str) -> None:
    """Every non-whitespace line of 1.0.0 must survive into later versions.

    Version bumps are additive edits (new clauses, conditionals). Removing a
    1.0.0 line requires bumping the lineage contract explicitly — not doing
    it silently.
    """
    base = PROMPTS_DIR / f"{name}.1.0.0.j2"
    base_lines = [
        ln.strip()
        for ln in base.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    for path in _template_files(name):
        if _version(path) <= (1, 0, 0):
            continue
        text = path.read_text(encoding="utf-8")
        # Conditional j2 blocks legitimately diverge only where the version
        # adds {% if %} branches; every 1.0.0 line outside those additions
        # must still be present verbatim.
        missing = [ln for ln in base_lines if ln not in text]
        assert not missing, (
            f"{path.name} dropped line(s) present in 1.0.0: {missing[:5]} "
            f"(total {len(missing)}). Version bumps must be additive."
        )
