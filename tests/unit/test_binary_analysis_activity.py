"""Unit tests for the binary-analysis activity and context injector (C6)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.binary_analysis import (
    binary_analysis_activity,
    build_binary_analysis_report,
    discover_elf_binaries,
    persist_binary_analysis_report,
)
from quarry_plugins.context.binary_analysis_context import (
    BINARY_ANALYSIS_ARTIFACT_KEY,
    BinaryAnalysisContextInjector,
    merge_binary_analysis_context,
)

_ELF_MAGIC = b"\x7fELF"


def _task(vuln_class: VulnerabilityClass | None, domain_context: str = "") -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-task",
        vuln_class=vuln_class,
        domain_context=domain_context,
        status="pending",
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------


class TestActivity:
    def test_no_binaries_yields_empty_report(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "README.md").write_text("no binaries here\n", encoding="utf-8")
        report = build_binary_analysis_report(repo)
        assert report["binaries"] == []
        assert report["suid_sgid"] == []
        assert report["symlinks"] == []
        assert report["tool_unavailable"] == []

    def test_activity_persists_report_under_well_known_key(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        artifact_root = tmp_path / "artifacts"
        result = binary_analysis_activity(str(repo), str(artifact_root))
        assert result["artifact_key"] == BINARY_ANALYSIS_ARTIFACT_KEY
        stored = artifact_root / BINARY_ANALYSIS_ARTIFACT_KEY
        assert stored.exists()
        payload = json.loads(stored.read_text(encoding="utf-8"))
        assert payload["binaries"] == []

    def test_report_has_per_binary_sections(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        # A minimal ELF header is enough for discovery; the tools degrade to
        # errors rather than crashing, but here the system binaries are present
        # so a real compiled target is used instead.
        import shutil
        import subprocess

        if shutil.which("gcc") is None:
            pytest.skip("gcc unavailable")
        source = repo / "prog.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        binary = repo / "prog"
        subprocess.run(
            ["gcc", "-o", str(binary), str(source)], check=True, capture_output=True, text=True
        )
        report = build_binary_analysis_report(repo)
        paths = [entry["path"] for entry in report["binaries"]]
        assert "prog" in paths
        entry = next(item for item in report["binaries"] if item["path"] == "prog")
        assert "ELF" in entry["file_type"]
        assert entry["checksec"]["relro"] in {"Full", "Partial", "None"}
        assert entry["linked_libraries"]["dynamic"] is True
        assert entry["strings_total"] >= 1

    def test_missing_tool_binaries_recorded_not_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "fake").write_bytes(_ELF_MAGIC + b"\x00" * 32)
        empty_path = tmp_path / "empty-bin"
        empty_path.mkdir()
        # No gcc in this test: the file above is discovered by ELF magic only.
        monkeypatch.setenv("PATH", str(empty_path))
        report = build_binary_analysis_report(repo)
        assert [entry["path"] for entry in report["binaries"]] == ["fake"]
        # ``file``/``readelf`` are absent, so those checks are unavailable; the
        # strings check has a pure-Python fallback and therefore still runs.
        assert report["tool_unavailable"] == ["file", "readelf"]

    def test_discovery_is_sorted_and_elf_only(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "b.bin").write_bytes(_ELF_MAGIC + b"\x00" * 8)
        (repo / "a.txt").write_text("text\n", encoding="utf-8")
        (repo / "a.bin").write_bytes(_ELF_MAGIC + b"\x00" * 8)
        assert [p.name for p in discover_elf_binaries(repo)] == ["a.bin", "b.bin"]

    def test_persist_is_deterministic_bytes(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        report = build_binary_analysis_report(repo)
        first = tmp_path / "one"
        second = tmp_path / "two"
        persist_binary_analysis_report(str(first), report)
        persist_binary_analysis_report(str(second), report)
        assert (first / BINARY_ANALYSIS_ARTIFACT_KEY).read_bytes() == (
            second / BINARY_ANALYSIS_ARTIFACT_KEY
        ).read_bytes()


# ---------------------------------------------------------------------------
# Injector
# ---------------------------------------------------------------------------


class TestInjector:
    def test_returns_none_when_artifact_absent(self, tmp_path: Path) -> None:
        injector = BinaryAnalysisContextInjector(artifact_root=str(tmp_path))
        task = _task(VulnerabilityClass.SECURITY_MISCONFIGURATION)
        assert (
            injector.inject_context(VulnerabilityClass.SECURITY_MISCONFIGURATION, task, "") is None
        )

    def test_returns_report_text_when_present(self, tmp_path: Path) -> None:
        (tmp_path / BINARY_ANALYSIS_ARTIFACT_KEY).write_text('{"binaries": []}', encoding="utf-8")
        injector = BinaryAnalysisContextInjector(artifact_root=str(tmp_path))
        task = _task(VulnerabilityClass.SECURITY_MISCONFIGURATION)
        assert injector.inject_context(VulnerabilityClass.SECURITY_MISCONFIGURATION, task, "") == (
            '{"binaries": []}'
        )

    def test_returns_none_for_other_class(self, tmp_path: Path) -> None:
        (tmp_path / BINARY_ANALYSIS_ARTIFACT_KEY).write_text('{"binaries": []}', encoding="utf-8")
        injector = BinaryAnalysisContextInjector(artifact_root=str(tmp_path))
        task = _task(VulnerabilityClass.COMMAND_INJECTION)
        assert injector.inject_context(VulnerabilityClass.COMMAND_INJECTION, task, "") is None

    def test_singleton_has_no_artifact_root(self) -> None:
        from quarry_plugins.context.binary_analysis_context import BINARY_ANALYSIS_PLUGIN

        task = _task(VulnerabilityClass.SECURITY_MISCONFIGURATION)
        assert (
            BINARY_ANALYSIS_PLUGIN.inject_context(
                VulnerabilityClass.SECURITY_MISCONFIGURATION, task, ""
            )
            is None
        )


class TestMergeHelper:
    def test_merges_and_records_provenance(self, tmp_path: Path) -> None:
        (tmp_path / BINARY_ANALYSIS_ARTIFACT_KEY).write_text('{"binaries": []}', encoding="utf-8")
        task = _task(VulnerabilityClass.SECURITY_MISCONFIGURATION, domain_context="existing")
        merged = merge_binary_analysis_context(task, str(tmp_path))
        assert merged.domain_context == '{"binaries": []}\n\nexisting'
        assert merged.domain_context_sources == ["binary_analysis"]

    def test_is_idempotent(self, tmp_path: Path) -> None:
        (tmp_path / BINARY_ANALYSIS_ARTIFACT_KEY).write_text('{"binaries": []}', encoding="utf-8")
        task = _task(VulnerabilityClass.SECURITY_MISCONFIGURATION, domain_context="existing")
        once = merge_binary_analysis_context(task, str(tmp_path))
        twice = merge_binary_analysis_context(once, str(tmp_path))
        assert twice.domain_context == once.domain_context
        assert twice.domain_context_sources == ["binary_analysis"]

    def test_non_matching_class_untouched(self, tmp_path: Path) -> None:
        (tmp_path / BINARY_ANALYSIS_ARTIFACT_KEY).write_text('{"binaries": []}', encoding="utf-8")
        task = _task(VulnerabilityClass.COMMAND_INJECTION, domain_context="existing")
        merged = merge_binary_analysis_context(task, str(tmp_path))
        assert merged.domain_context == "existing"
        assert merged.domain_context_sources == []

    def test_absent_artifact_untouched(self, tmp_path: Path) -> None:
        task = _task(VulnerabilityClass.SECURITY_MISCONFIGURATION, domain_context="existing")
        merged = merge_binary_analysis_context(task, str(tmp_path))
        assert merged.domain_context == "existing"
        assert merged.domain_context_sources == []
