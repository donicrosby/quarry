"""Tests for KB assertion grounding: uncited assertions are corrected/omitted.

Written RED first for openspec change candidate-precision-and-calibration,
task 2.4 (knowledge-base spec scenario "Ungrounded assertion is corrected or
omitted"): a KB assertion lacking a cited source location, or citing a
location that does not exist in the audited repository, must never be
asserted — the harness omits it or corrects it against the source the recon
agent actually read.
"""

from __future__ import annotations

from pathlib import Path

from quarry.schemas import VulnerabilityClass
from quarry_activities.kb_recon import (
    KbReconOutput,
    ground_kb_assertions,
    synthesize_kb_records,
)


def _write_repo(repo: Path) -> None:
    (repo / "app.py").write_text(
        "def handler(request):\n    return request.args.get('name', '')\n",
        encoding="utf-8",
    )


def _uncited_output() -> KbReconOutput:
    return KbReconOutput(
        component_entities=[
            {
                "id": "app.py::handler",
                "name": "handler",
                "path": "app.py",
                "line": 1,
                "security_relevance": "Reads the user-controlled name argument.",
                # NO cited source location — must be corrected or omitted.
                "source_locations": [],
            },
            {
                "id": "app.py::authorize",
                "name": "authorize",
                "path": "app.py",
                "line": 1,
                "security_relevance": "Hallucinated authz check.",
                # Cited location does not exist in the repo — must be omitted.
                "source_locations": ["app.py:99"],
            },
        ],
        vuln_class_notes=[
            {
                "vuln_class": "command_injection",
                "relevance": "No exec usage in scope.",
                "source_locations": ["app.py:1"],
            },
            {
                "vuln_class": "ssrf",
                "relevance": "Outbound fetcher present.",
                "source_locations": [],  # uncited — must be dropped
            },
        ],
        tool_calls=[],
    )


def test_grounding_drops_uncited_assertions(tmp_path: Path) -> None:
    """Assertions with no usable cited source location are omitted."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)

    grounded = ground_kb_assertions(repo_root=repo, output=_uncited_output())

    entity_paths = {(e.path, e.name) for e in grounded.component_entities}
    note_classes = {n.vuln_class for n in grounded.vuln_class_notes}

    # The hallucinated/uncited records are gone.
    assert ("app.py", "authorize") not in entity_paths
    assert VulnerabilityClass.SSRF not in note_classes


def test_grounding_corrects_citable_assertions(tmp_path: Path) -> None:
    """An uncited assertion for code the agent actually read is corrected, not dropped."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)

    grounded = ground_kb_assertions(repo_root=repo, output=_uncited_output())

    handler = next(
        (e for e in grounded.component_entities if e.name == "handler"),
        None,
    )
    # Corrected: the cited location now points at the real symbol.
    assert handler is not None
    assert handler.source_locations, "corrected assertion must carry a citation"
    loc = handler.source_locations[0]
    assert loc.startswith("app.py:")
    line = int(loc.split(":")[1])
    assert line == 1  # `def handler` is on line 1


def test_grounded_records_cite_existing_locations(tmp_path: Path) -> None:
    """Every surviving record's citations resolve to real repo file lines."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)

    entities, notes, _graph = synthesize_kb_records(
        repo_root=repo,
        scan_id="scan-1",
        output=_uncited_output(),
    )

    lines = (repo / "app.py").read_text(encoding="utf-8").splitlines()
    for record in [*entities, *notes]:
        assert record.source_locations, (
            f"{record!r} survived grounding without any cited source location"
        )
        for loc in record.source_locations:
            path_str, _, line_str = loc.partition(":")
            cited_file = repo / path_str
            assert cited_file.is_file(), f"cited file missing: {loc}"
            line_no = int(line_str)
            assert 1 <= line_no <= len(lines), f"cited line out of range: {loc}"
