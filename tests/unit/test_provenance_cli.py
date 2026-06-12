"""Unit tests for the quarry provenance CLI command and GC retention.

Written RED first — these fail until:
- ``quarry provenance verify`` Typer command is wired in quarry_cli/main.py
- ``quarry provenance gc-check`` command (or retention sweep helper) is added
- ``should_gc_scan`` is called correctly by the retention path

The tests use typer's CliRunner for the CLI tests, and exercise the helpers
directly for the retention/GC tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from quarry.schemas import (
    ModelInvocation,
    RedactionStatus,
    Scan,
    ScanProfile,
    ScanStatus,
    VulnerabilityClass,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)
_runner = CliRunner()


def _make_invocation(
    system_hash: str = "a" * 64,
    template_sha: str = "b" * 64,
    user_hash: str = "c" * 64,
) -> ModelInvocation:
    return ModelInvocation(
        id="inv-cli-1",
        scan_id="s-cli",
        workspace_id="ws-1",
        task_name="hunt-loop",
        role="hunt",
        provider="mock",
        model="mock-model",
        system_prompt_hash=system_hash,
        template_sha256=template_sha,
        user_prompt_hash=user_hash,
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=_NOW,
    )


def _make_scan(legal_hold: bool = False) -> Scan:
    return Scan(
        id="s-cli-gc",
        workspace_id="ws-1",
        target_id="t-1",
        requested_by="user@example.com",
        profile=ScanProfile(
            id="p-1",
            name="test",
            vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
        ),
        status=ScanStatus.COMPLETED,
        created_at=_NOW,
        legal_hold=legal_hold,
    )


# ---------------------------------------------------------------------------
# Provenance sub-app wired into main CLI
# ---------------------------------------------------------------------------


class TestProvenanceSubAppRegistered:
    def test_provenance_app_registered_in_main(self) -> None:
        from quarry_cli.main import app

        result = _runner.invoke(app, ["provenance", "--help"])
        assert result.exit_code == 0, result.output
        assert "provenance" in result.output.lower() or "verify" in result.output.lower()

    def test_provenance_verify_command_exists(self) -> None:
        from quarry_cli.main import app

        result = _runner.invoke(app, ["provenance", "verify", "--help"])
        assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# quarry provenance verify — pass / fail behaviour
# ---------------------------------------------------------------------------


class TestProvenanceVerifyCommand:
    def test_verify_pass_writes_invocation_json_and_exits_0(self, tmp_path: Path) -> None:

        from quarry_cli.main import app

        inv = _make_invocation(system_hash="a" * 64)
        inv_file = tmp_path / "inv.json"
        inv_file.write_text(inv.model_dump_json())

        result = _runner.invoke(
            app,
            [
                "provenance",
                "verify",
                str(inv_file),
                "--system-hash",
                "a" * 64,
            ],
        )
        assert result.exit_code == 0, result.output

    def test_verify_fail_exits_nonzero_on_hash_mismatch(self, tmp_path: Path) -> None:
        from quarry_cli.main import app

        inv = _make_invocation(system_hash="a" * 64)
        inv_file = tmp_path / "inv.json"
        inv_file.write_text(inv.model_dump_json())

        result = _runner.invoke(
            app,
            [
                "provenance",
                "verify",
                str(inv_file),
                "--system-hash",
                "b" * 64,  # tampered
            ],
        )
        assert result.exit_code != 0, "Tampered hash must produce non-zero exit"

    def test_verify_missing_file_exits_nonzero(self, tmp_path: Path) -> None:
        from quarry_cli.main import app

        result = _runner.invoke(
            app,
            [
                "provenance",
                "verify",
                str(tmp_path / "nonexistent.json"),
                "--system-hash",
                "a" * 64,
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# GC retention helpers
# ---------------------------------------------------------------------------


class TestRetentionHelpers:
    def test_gc_check_function_importable(self) -> None:
        from quarry_cli.provenance import should_gc_scan

        assert callable(should_gc_scan)

    def test_legal_hold_scan_not_eligible_for_gc(self) -> None:
        from quarry_cli.provenance import should_gc_scan

        scan = _make_scan(legal_hold=True)
        assert should_gc_scan(scan) is False

    def test_normal_scan_eligible_for_gc(self) -> None:
        from quarry_cli.provenance import should_gc_scan

        scan = _make_scan(legal_hold=False)
        assert should_gc_scan(scan) is True

    def test_gc_check_command_exists_in_cli(self) -> None:
        from quarry_cli.main import app

        result = _runner.invoke(app, ["provenance", "gc-check", "--help"])
        assert result.exit_code == 0, result.output

    def test_gc_check_command_filters_legal_hold(self, tmp_path: Path) -> None:
        import json

        from quarry_cli.main import app

        hold_scan = _make_scan(legal_hold=True)
        free_scan = _make_scan(legal_hold=False)
        free_scan = free_scan.model_copy(update={"id": "s-free"})

        scans_file = tmp_path / "scans.json"
        scans_file.write_text(
            json.dumps([hold_scan.model_dump(mode="json"), free_scan.model_dump(mode="json")])
        )

        result = _runner.invoke(app, ["provenance", "gc-check", str(scans_file)])
        assert result.exit_code == 0, result.output
        # Only the free scan should appear in GC-eligible output
        assert "s-free" in result.output
        assert "s-cli-gc" not in result.output  # legal_hold scan excluded
