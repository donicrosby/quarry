"""Unit tests for the binary analysis tools (openspec binary-analysis-tools, C6).

Covers the tool registry contract, file type / strings / checksec / linked-libraries
behaviour on real compiled binaries, filesystem-metadata tools (SUID/sgid,
symlinks/hardlinks), and the read-only + repo-root-confined security properties.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from quarry_tools.binary_analysis import (
    BINARY_ANALYSIS_TOOLS,
    CHECKSEC_TOOL,
    EXTRACT_STRINGS_TOOL,
    FILE_TYPE_TOOL,
    LINKED_LIBRARIES_TOOL,
    SUID_SGID_TOOL,
    SYMLINK_ANALYSIS_TOOL,
    build_checksec_report,
    list_linked_libraries,
    resolve_in_repo,
)
from quarry_tools.errors import ToolSecurityError, ToolUnavailableError
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner

_TOOL_NAMES = {
    "file_type",
    "extract_strings",
    "checksec",
    "linked_libraries",
    "suid_sgid_detect",
    "symlink_analysis",
}

_C_SOURCE = """
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 2) { char buf[64]; buf[0] = (char)argc; return buf[0]; }
    return 0;
}
"""


def _compile(tmp_path: Path, name: str, flags: list[str]) -> Path | None:
    """Compile *name* with *flags*; return the binary or None when gcc is absent."""
    if shutil.which("gcc") is None:
        return None
    source = tmp_path / f"{name}.c"
    source.write_text(_C_SOURCE, encoding="utf-8")
    binary = tmp_path / name
    try:
        subprocess.run(
            ["gcc", *flags, "-o", str(binary), str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    return binary


# ---------------------------------------------------------------------------
# Registry contract
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_tools_are_discoverable_in_registry(self) -> None:
        registry = load_registry()
        for name in _TOOL_NAMES:
            tool = registry[name]
            assert tool.description.strip()
            assert tool.input_schema
            assert tool.roles

    def test_builtin_registry_carries_all_six(self) -> None:
        assert set(BINARY_ANALYSIS_TOOLS) == _TOOL_NAMES

    def test_roles_include_recon_hunt_prove(self) -> None:
        for tool in BINARY_ANALYSIS_TOOLS.values():
            assert {"recon", "hunt", "prove"} <= set(tool.roles)

    def test_missing_external_binary_raises_tool_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "thing.bin"
        target.write_bytes(b"\x7fELF" + b"\x00" * 16)
        empty_path = tmp_path / "empty-bin"
        empty_path.mkdir()
        monkeypatch.setenv("PATH", str(empty_path))
        with pytest.raises(ToolUnavailableError) as excinfo:
            FILE_TYPE_TOOL.run({"path": "thing.bin"}, tmp_path)
        assert "file" in str(excinfo.value)


# ---------------------------------------------------------------------------
# file_type
# ---------------------------------------------------------------------------


class TestFileType:
    def test_elf_binary_is_detected(self, tmp_path: Path) -> None:
        binary = _compile(tmp_path, "hello", [])
        if binary is None:
            pytest.skip("gcc unavailable")
        output = FILE_TYPE_TOOL.run({"path": binary.name}, tmp_path)
        assert "ELF" in output
        assert "x86-64" in output or "aarch64" in output

    def test_non_binary_file_is_classified(self, tmp_path: Path) -> None:
        text = tmp_path / "notes.txt"
        text.write_text("just some text\n", encoding="utf-8")
        output = FILE_TYPE_TOOL.run({"path": "notes.txt"}, tmp_path)
        assert "text" in output.lower()
        assert "error" not in output.lower()


# ---------------------------------------------------------------------------
# extract_strings
# ---------------------------------------------------------------------------


class TestExtractStrings:
    def _binary_with_strings(self, tmp_path: Path) -> Path:
        marker = "UNIQUEMARKERABCDEF"
        source = tmp_path / "console.c"
        source.write_text(
            "#include <stdio.h>\n"
            f'int main(void) {{ puts("{marker}"); puts("short"); return 0; }}\n',
            encoding="utf-8",
        )
        if shutil.which("gcc") is None:
            pytest.skip("gcc unavailable")
        binary = tmp_path / "console"
        subprocess.run(
            ["gcc", "-o", str(binary), str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
        return binary

    def test_strings_are_extracted_with_default_min_length(self, tmp_path: Path) -> None:
        binary = self._binary_with_strings(tmp_path)
        output = EXTRACT_STRINGS_TOOL.run({"path": binary.name}, tmp_path)
        assert "UNIQUEMARKERABCDEF" in output

    def test_configurable_min_length_is_honored(self, tmp_path: Path) -> None:
        binary = self._binary_with_strings(tmp_path)
        short = EXTRACT_STRINGS_TOOL.extract(binary, tmp_path, 4)
        long = EXTRACT_STRINGS_TOOL.extract(binary, tmp_path, 8)
        assert "UNIQUEMARKERABCDEF" in long
        assert all(len(item) >= 8 for item in long)
        assert len(long) < len(short)

    def test_pure_python_fallback_keeps_tab_and_splits_on_newline(self) -> None:
        from quarry_tools.binary_analysis import extract_printable_bytes

        data = b"abc\tdef\nxy\x00okay\xfflonger"
        # Tab is printable and kept inside a run; newline and NUL terminate.
        assert extract_printable_bytes(data, 3) == ["abc\tdef", "okay", "longer"]


# ---------------------------------------------------------------------------
# checksec
# ---------------------------------------------------------------------------


class TestChecksec:
    def test_fully_hardened_binary_reports_all_protections(self, tmp_path: Path) -> None:
        binary = _compile(
            tmp_path, "hardened", ["-fstack-protector-strong", "-pie", "-Wl,-z,relro,-z,now"]
        )
        if binary is None:
            pytest.skip("gcc unavailable")
        report = build_checksec_report(binary, tmp_path)
        assert report["relro"] == "Full"
        assert report["nx"] == "Enabled"
        assert report["pie"] == "Enabled"
        assert report["canary"] == "Enabled"

    def test_unhardened_binary_reports_missing_protections(self, tmp_path: Path) -> None:
        binary = _compile(
            tmp_path,
            "unhardened",
            ["-z", "execstack", "-no-pie", "-z", "norelro", "-fno-stack-protector"],
        )
        if binary is None:
            pytest.skip("gcc unavailable")
        report = build_checksec_report(binary, tmp_path)
        assert report["relro"] == "None"
        assert report["nx"] == "Disabled"
        assert report["pie"] == "Disabled"
        assert report["canary"] == "Disabled"

    def test_non_elf_returns_error(self, tmp_path: Path) -> None:
        text = tmp_path / "data.txt"
        text.write_text("nope\n", encoding="utf-8")
        assert build_checksec_report(text, tmp_path) == {"error": "not an ELF file"}

    def test_tool_run_renders_flags(self, tmp_path: Path) -> None:
        binary = _compile(tmp_path, "render", ["-pie", "-Wl,-z,relro,-z,now"])
        if binary is None:
            pytest.skip("gcc unavailable")
        output = CHECKSEC_TOOL.run({"path": binary.name}, tmp_path)
        assert "RELRO: Full" in output
        assert "NX: Enabled" in output
        assert "PIE: Enabled" in output


# ---------------------------------------------------------------------------
# linked_libraries
# ---------------------------------------------------------------------------


class TestLinkedLibraries:
    def test_dynamically_linked_binary_lists_libraries(self, tmp_path: Path) -> None:
        binary = _compile(tmp_path, "dynamic", [])
        if binary is None:
            pytest.skip("gcc unavailable")
        report = list_linked_libraries(binary, tmp_path)
        assert report["dynamic"] is True
        assert "libc.so.6" in report["libraries"]

    def test_statically_linked_binary_reports_none(self, tmp_path: Path) -> None:
        binary = _compile(tmp_path, "static", ["-static"])
        if binary is None:
            pytest.skip("static gcc build unavailable")
        report = list_linked_libraries(binary, tmp_path)
        assert report["dynamic"] is False
        assert report["libraries"] == []
        output = LINKED_LIBRARIES_TOOL.run({"path": binary.name}, tmp_path)
        assert "no dynamic libraries" in output


# ---------------------------------------------------------------------------
# suid_sgid_detect
# ---------------------------------------------------------------------------


class TestSuidSgid:
    def test_suid_binary_is_reported(self, tmp_path: Path) -> None:
        secret = tmp_path / "helper"
        secret.write_text("#!/bin/sh\n", encoding="utf-8")
        secret.chmod(0o4755)
        findings = SUID_SGID_TOOL.scan(tmp_path)
        assert findings == [{"path": "helper", "mode": "4755"}]

    def test_cleared_suid_bit_is_not_reported(self, tmp_path: Path) -> None:
        secret = tmp_path / "helper"
        secret.write_text("#!/bin/sh\n", encoding="utf-8")
        secret.chmod(0o4755)
        secret.chmod(0o755)
        assert SUID_SGID_TOOL.scan(tmp_path) == []

    def test_no_suid_files_reports_empty(self, tmp_path: Path) -> None:
        # A fresh empty tree has no setuid/sgid bits.
        assert SUID_SGID_TOOL.scan(tmp_path) == []

    def test_sgid_directory_is_skipped(self, tmp_path: Path) -> None:
        d = tmp_path / "shared"
        d.mkdir()
        os.chmod(d, stat.S_ISGID | 0o755)
        assert SUID_SGID_TOOL.scan(tmp_path) == []


# ---------------------------------------------------------------------------
# symlink_analysis
# ---------------------------------------------------------------------------


class TestSymlinkAnalysis:
    def test_symlink_is_reported_with_target(self, tmp_path: Path) -> None:
        real = tmp_path / "real.txt"
        real.write_text("x", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to("real.txt")
        report = SYMLINK_ANALYSIS_TOOL.scan(tmp_path)
        assert {"path": "link.txt", "target": "real.txt"} in report["symlinks"]

    def test_hardlink_is_detected_via_inode(self, tmp_path: Path) -> None:
        first = tmp_path / "a.txt"
        first.write_text("payload", encoding="utf-8")
        second = tmp_path / "b.txt"
        os.link(first, second)
        report = SYMLINK_ANALYSIS_TOOL.scan(tmp_path)
        groups = [group for group in report["hardlinks"] if len(group["paths"]) == 2]
        assert groups, report["hardlinks"]
        assert groups[0]["paths"] == ["a.txt", "b.txt"]


# ---------------------------------------------------------------------------
# Security: read-only + repo-root confinement
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_path_escape_is_refused_by_runner(self, tmp_path: Path) -> None:
        runner = ToolRunner(repo_root=tmp_path, role="hunt", registry=load_registry())
        with pytest.raises(ToolSecurityError):
            runner.run("file_type", {"path": "../outside.txt"})

    def test_resolve_in_repo_refuses_escape(self, tmp_path: Path) -> None:
        with pytest.raises(ToolSecurityError):
            resolve_in_repo("/etc/passwd", tmp_path)

    def test_tool_never_writes_files(self, tmp_path: Path) -> None:
        binary = _compile(tmp_path, "subject", [])
        if binary is None:
            pytest.skip("gcc unavailable")
        (tmp_path / "notes.txt").write_text("hello world\n", encoding="utf-8")

        def snapshot() -> dict[str, tuple[int, float]]:
            state: dict[str, tuple[int, float]] = {}
            for dirpath, _dirs, files in os.walk(tmp_path):
                for name in files:
                    path = Path(dirpath) / name
                    info = path.lstat()
                    state[str(path.relative_to(tmp_path))] = (info.st_size, info.st_mtime)
            return state

        before = snapshot()
        FILE_TYPE_TOOL.run({"path": binary.name}, tmp_path)
        EXTRACT_STRINGS_TOOL.run({"path": binary.name}, tmp_path)
        CHECKSEC_TOOL.run({"path": binary.name}, tmp_path)
        LINKED_LIBRARIES_TOOL.run({"path": binary.name}, tmp_path)
        SUID_SGID_TOOL.run({}, tmp_path)
        SYMLINK_ANALYSIS_TOOL.run({}, tmp_path)
        assert snapshot() == before
