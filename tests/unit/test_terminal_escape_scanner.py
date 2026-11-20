"""Unit tests: terminal_escape deterministic scanner.

Covers the plugin-framework spec scenarios —
unsanitized-print-of-user-input-is-detected, sanitized-output-is-not-flagged —
plus the binary-file skip, the repo-scan file_paths path, the CandidateFinding
converter, and the vulnerable-cli fixture sink (C9 acceptance target).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_plugins.vuln_classes.terminal_escape import (
    scan_file_for_terminal_escapes,
    scan_repo_for_terminal_escapes,
    terminal_match_to_candidate_finding,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "examples" / "vulnerable-cli"
FIXTURE_MAIN = FIXTURE_ROOT / "src" / "main.rs"


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_unsanitized_print_of_user_input_is_detected(tmp_path: Path) -> None:
    """Scenario: unsanitized-print-of-user-input-is-detected."""
    path = _write(
        tmp_path,
        "cli.py",
        "import sys\nprint(sys.argv[1])\n",
    )

    matches = scan_file_for_terminal_escapes(path, tmp_path)

    assert [(m.line_number, m.sink_name, m.input_source) for m in matches] == [
        (2, "print", "sys.argv")
    ]
    assert matches[0].evidence_kind == "unsanitized_terminal_output"


def test_shell_echo_of_user_input_is_detected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "run.sh",
        'echo "$stdin"\nprintf \'%s\' "$payload"\n',
    )

    matches = scan_file_for_terminal_escapes(path, tmp_path)

    assert [m.sink_name for m in matches] == ["echo", "printf"]


def test_sanitized_output_is_not_flagged(tmp_path: Path) -> None:
    """Scenario: sanitized-output-is-not-flagged."""
    path = _write(
        tmp_path,
        "safe.py",
        "import re\n"
        "import sys\n"
        'print(re.sub(r"\\x1b\\[[0-9;]*m", "", sys.argv[1]))\n'
        "print(strip_ansi(sys.argv[1]))\n"
        "print(sanitize(sys.argv[1]))\n",
    )

    assert scan_file_for_terminal_escapes(path, tmp_path) == []


def test_print_without_a_user_source_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "static.py",
        'print("hello world")\n',
    )

    assert scan_file_for_terminal_escapes(path, tmp_path) == []


def test_binary_file_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00print(argv)\x00")

    assert scan_file_for_terminal_escapes(path, tmp_path) == []


def test_repo_scan_honours_file_paths_and_skips_excluded_dirs(tmp_path: Path) -> None:
    _write(tmp_path, "src/cli.py", "print(argv)\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "t.py").write_text("print(argv)\n", encoding="utf-8")

    matches = scan_repo_for_terminal_escapes(tmp_path)

    assert {m.file_path for m in matches} == {"src/cli.py"}

    explicit = scan_repo_for_terminal_escapes({"repo_root": str(tmp_path), "file_paths": None})
    assert {m.file_path for m in explicit} == {"src/cli.py"}


def test_match_converts_to_candidate_finding(tmp_path: Path) -> None:
    path = _write(tmp_path, "cli.py", "print(argv)\n")
    matches = scan_file_for_terminal_escapes(path, tmp_path)
    assert matches

    finding = terminal_match_to_candidate_finding(matches[0], scan_id="scan-1")

    assert finding.vuln_class is VulnerabilityClass.TERMINAL_ESCAPE
    assert finding.scan_id == "scan-1"
    assert finding.source_refs[0].file_path == "cli.py"
    assert finding.source_refs[0].start_line == 1
    assert finding.evidence_path[0].path == "cli.py"
    assert finding.metadata.get("evidence_kind") == "unsanitized_terminal_output"
    assert finding.created_by == "terminal-escape-scanner"


@pytest.mark.skipif(not FIXTURE_MAIN.exists(), reason="vulnerable-cli fixture not present")
def test_vulnerable_cli_fixture_echo_input_sink_is_detected() -> None:
    """C9 acceptance: the deterministic sweep flags the vulnerable-cli sink."""
    matches = scan_file_for_terminal_escapes(FIXTURE_MAIN, REPO_ROOT)

    assert any(m.sink_name == "print" and m.input_source == "args" for m in matches)
