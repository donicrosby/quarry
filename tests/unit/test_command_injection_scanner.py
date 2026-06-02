"""Tests for the command-injection sink scanner."""

import json
import textwrap
from pathlib import Path

import pytest

from quarry.schemas import AttackSurfaceItem, Confidence, Severity, VulnerabilityClass
from quarry_plugins.vuln_classes.command_injection import (
    command_injection_match_to_candidate_finding,
    scan_handler_for_command_injection,
)

REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()
EXPECTED_PATH = Path("tests/fixtures/vulnerable-fastapi/expected_command_injection.json")


def _item(route: str, symbol: str) -> AttackSurfaceItem:
    return AttackSurfaceItem(
        id="a1",
        scan_id="scan-1",
        route=route,
        method="GET",
        handler_file="app.py",
        handler_symbol=symbol,
    )


def test_detects_subprocess_shell_true_sink() -> None:
    source = textwrap.dedent(
        """
        import subprocess

        def ping(host: str = "127.0.0.1"):
            return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
        """
    )
    matches = scan_handler_for_command_injection(_item("/debug/ping", "ping"), source)

    assert len(matches) == 1
    assert matches[0].sink == "subprocess.run"
    assert matches[0].param == "host"


def test_detects_os_system_sink() -> None:
    source = textwrap.dedent(
        """
        import os

        def run(cmd: str):
            return os.system("echo " + cmd)
        """
    )
    matches = scan_handler_for_command_injection(_item("/run", "run"), source)

    assert len(matches) == 1
    assert matches[0].sink == "os.system"
    assert matches[0].param == "cmd"


def test_no_finding_for_parameterized_call_without_shell() -> None:
    source = textwrap.dedent(
        """
        import subprocess

        def ping(host: str):
            return subprocess.run(["ping", "-c", "1", host], capture_output=True)
        """
    )
    assert scan_handler_for_command_injection(_item("/debug/ping", "ping"), source) == []


def test_no_finding_when_no_param_flows_into_sink() -> None:
    source = textwrap.dedent(
        """
        import subprocess

        def status():
            return subprocess.run("uptime", shell=True, capture_output=True)
        """
    )
    assert scan_handler_for_command_injection(_item("/status", "status"), source) == []


def test_candidate_finding_fields() -> None:
    source = textwrap.dedent(
        """
        import subprocess

        def ping(host: str = "127.0.0.1"):
            return subprocess.run(f"ping -c 1 {host}", shell=True)
        """
    )
    match = scan_handler_for_command_injection(_item("/debug/ping", "ping"), source)[0]
    candidate = command_injection_match_to_candidate_finding(match, scan_id="scan-1")

    assert candidate.vuln_class is VulnerabilityClass.COMMAND_INJECTION
    assert candidate.severity is Severity.CRITICAL
    assert candidate.confidence is Confidence.HIGH
    assert candidate.metadata["route"] == "/debug/ping"
    assert candidate.metadata["param"] == "host"
    assert candidate.metadata["sink"] == "subprocess.run"


def test_candidate_id_is_deterministic() -> None:
    source = "import subprocess\n\ndef ping(host: str):\n    subprocess.run(host, shell=True)\n"
    match = scan_handler_for_command_injection(_item("/debug/ping", "ping"), source)[0]
    first = command_injection_match_to_candidate_finding(match, scan_id="scan-1")
    second = command_injection_match_to_candidate_finding(match, scan_id="scan-2")

    assert first.id == second.id  # fingerprint excludes scan id


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
def test_golden_command_injection_on_vulnerable_fastapi() -> None:
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    source = (REPO_ROOT / "app.py").read_text(encoding="utf-8")

    for entry in expected:
        item = _item(str(entry["route"]), "ping")
        matches = scan_handler_for_command_injection(item, source)
        assert len(matches) == 1
        match = matches[0]
        assert match.param == entry["param"]
        assert match.sink == entry["sink"]
        assert match.handler_file == entry["file_path"]
        assert match.line_number == int(str(entry["line_number"]))

        candidate = command_injection_match_to_candidate_finding(match, scan_id="golden")
        assert candidate.title == entry["title"]
        assert candidate.vuln_class.value == entry["vuln_class"]
