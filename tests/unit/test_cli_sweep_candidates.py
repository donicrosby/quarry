"""Unit tests: workflow-side candidate converters for the C8/C9 CLI sweeps.

The deterministic tempfile-race and terminal-escape sweeps feed the full-scan
HUNT stage through ``quarry_workflows.candidate_sources`` (workflow-pure: the
payload crosses the boundary as plain dicts).  These tests pin the converters,
their malformed-payload guards, and the parity contract — a match found by both
the plugin converter and the workflow converter must share one candidate id so
dedup collapses it.
"""

from __future__ import annotations

import pytest

from quarry.schemas import VulnerabilityClass, utc_now
from quarry_plugins.vuln_classes.tempfile_race import (
    TempfileRaceMatch,
    tempfile_match_to_candidate_finding,
)
from quarry_plugins.vuln_classes.terminal_escape import (
    TerminalEscapeMatch,
    terminal_match_to_candidate_finding,
)
from quarry_workflows.candidate_sources import (
    tempfile_race_candidates_from_activity_payload,
    terminal_escape_candidates_from_activity_payload,
)


def test_tempfile_race_candidates_build_sweep_candidate() -> None:
    now = utc_now()
    payload = [
        {
            "sink_name": "open",
            "file_path": "src/app.py",
            "line_number": 12,
            "temp_path": "/tmp/myapp.cache",
            "evidence_kind": "predictable_temp_path",
        }
    ]

    candidates = tempfile_race_candidates_from_activity_payload(
        payload, scan_id="scan-1", created_at=now
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.vuln_class is VulnerabilityClass.TEMPFILE_RACE
    assert candidate.scan_id == "scan-1"
    assert candidate.created_at == now
    assert candidate.metadata.get("source") == "tempfile-race-sweep"
    assert candidate.metadata.get("evidence_kind") == "predictable_temp_path"
    assert candidate.created_by == "tempfile-race-sweep"
    assert candidate.source_refs[0].file_path == "src/app.py"
    assert candidate.source_refs[0].start_line == 12
    assert candidate.evidence_path[0].line == 12


def test_tempfile_race_candidates_skip_malformed_and_reject_non_list() -> None:
    payload = [
        {"sink_name": "", "file_path": "a.py", "line_number": 1},
        {"sink_name": "open", "file_path": "", "line_number": 1},
        {"sink_name": "open", "file_path": "a.py", "line_number": 0},
        "not-a-dict",
        {"sink_name": "open", "file_path": "a.py", "line_number": 3},
    ]

    candidates = tempfile_race_candidates_from_activity_payload(
        payload, scan_id="s", created_at=utc_now()
    )

    assert len(candidates) == 1

    with pytest.raises(TypeError):
        tempfile_race_candidates_from_activity_payload(
            {"nope": 1}, scan_id="s", created_at=utc_now()
        )


def test_terminal_escape_candidates_build_sweep_candidate() -> None:
    now = utc_now()
    payload = [
        {
            "sink_name": "print",
            "file_path": "src/cli.py",
            "line_number": 7,
            "input_source": "sys.argv",
            "evidence_kind": "unsanitized_terminal_output",
        }
    ]

    candidates = terminal_escape_candidates_from_activity_payload(
        payload, scan_id="scan-1", created_at=now
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.vuln_class is VulnerabilityClass.TERMINAL_ESCAPE
    assert candidate.created_at == now
    assert candidate.metadata.get("source") == "terminal-escape-sweep"
    assert candidate.metadata.get("evidence_kind") == "unsanitized_terminal_output"
    assert candidate.metadata.get("input_source") == "sys.argv"
    assert candidate.created_by == "terminal-escape-sweep"
    assert candidate.source_refs[0].file_path == "src/cli.py"
    assert candidate.evidence_path[0].line == 7


def test_terminal_escape_candidates_skip_malformed_and_reject_non_list() -> None:
    payload = [
        {"sink_name": "", "file_path": "a.py", "line_number": 1},
        {"sink_name": "print", "file_path": "", "line_number": 1},
        {"sink_name": "print", "file_path": "a.py", "line_number": 0},
        "not-a-dict",
        {"sink_name": "print", "file_path": "a.py", "line_number": 3},
    ]

    candidates = terminal_escape_candidates_from_activity_payload(
        payload, scan_id="s", created_at=utc_now()
    )

    assert len(candidates) == 1

    with pytest.raises(TypeError):
        terminal_escape_candidates_from_activity_payload(
            {"nope": 1}, scan_id="s", created_at=utc_now()
        )


def test_converters_are_reexported_from_run_scan() -> None:
    from quarry_workflows.run_scan import (
        tempfile_race_candidates_from_activity_payload as reexported_tempfile,
    )
    from quarry_workflows.run_scan import (
        terminal_escape_candidates_from_activity_payload as reexported_terminal,
    )

    assert reexported_tempfile is tempfile_race_candidates_from_activity_payload
    assert reexported_terminal is terminal_escape_candidates_from_activity_payload


def test_plugin_and_workflow_converters_share_a_candidate_id() -> None:
    """Parity: the same match yields the same id from both converters (dedup)."""
    tempfile_match = TempfileRaceMatch(
        file_path="src/app.py",
        line_number=12,
        sink_name="open",
        temp_path="/tmp/myapp.cache",
        evidence_kind="predictable_temp_path",
    )
    terminal_match = TerminalEscapeMatch(
        file_path="src/cli.py",
        line_number=7,
        sink_name="print",
        input_source="sys.argv",
        evidence_kind="unsanitized_terminal_output",
    )
    now = utc_now()

    plugin_tempfile = tempfile_match_to_candidate_finding(tempfile_match, scan_id="s")
    sweep_tempfile = tempfile_race_candidates_from_activity_payload(
        [
            {
                "sink_name": tempfile_match.sink_name,
                "file_path": tempfile_match.file_path,
                "line_number": tempfile_match.line_number,
                "temp_path": tempfile_match.temp_path,
                "evidence_kind": tempfile_match.evidence_kind,
            }
        ],
        scan_id="s",
        created_at=now,
    )
    plugin_terminal = terminal_match_to_candidate_finding(terminal_match, scan_id="s")
    sweep_terminal = terminal_escape_candidates_from_activity_payload(
        [
            {
                "sink_name": terminal_match.sink_name,
                "file_path": terminal_match.file_path,
                "line_number": terminal_match.line_number,
                "input_source": terminal_match.input_source,
                "evidence_kind": terminal_match.evidence_kind,
            }
        ],
        scan_id="s",
        created_at=now,
    )

    assert plugin_tempfile.id == sweep_tempfile[0].id
    assert plugin_terminal.id == sweep_terminal[0].id
