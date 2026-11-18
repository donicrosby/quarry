"""Golden smoke test: binary analysis against examples/vulnerable-cli (C6).

Builds the Rust fixture, runs the deterministic ``binary-analysis`` activity over
it, and asserts the hardening report identifies the compiled binary, its file
type, hardening flags, and linked libraries, and that the SUID/sgid sweep is
clean. Skipped when the Rust toolchain is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from quarry_activities.binary_analysis import binary_analysis_activity

REPO_ROOT = Path(__file__).parents[2]
FIXTURE = REPO_ROOT / "examples" / "vulnerable-cli"
_BINARY_REL = "target/release/vulnerable-cli"


@pytest.fixture(scope="module")
def vulnerable_cli_report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    if shutil.which("cargo") is None:
        pytest.skip("cargo unavailable")
    if not FIXTURE.exists():
        pytest.skip("examples/vulnerable-cli not present")
    subprocess.run(
        ["cargo", "build", "--release"],
        cwd=str(FIXTURE),
        check=True,
        capture_output=True,
        text=True,
    )
    artifact_root = tmp_path_factory.mktemp("artifacts")
    return binary_analysis_activity(str(FIXTURE), str(artifact_root))


def _binary_entry(report: dict[str, Any], path: str) -> dict[str, Any] | None:
    binaries: list[dict[str, Any]] = report.get("binaries", [])
    for entry in binaries:
        if entry.get("path") == path:
            return entry
    return None


def test_binary_analysis_golden_reports_compiled_binary(
    vulnerable_cli_report: dict[str, Any],
) -> None:
    entry = _binary_entry(vulnerable_cli_report, _BINARY_REL)
    assert entry is not None, vulnerable_cli_report.get("binaries")
    assert "ELF" in str(entry["file_type"])


def test_binary_analysis_golden_checksec_fields_present(
    vulnerable_cli_report: dict[str, Any],
) -> None:
    entry = _binary_entry(vulnerable_cli_report, _BINARY_REL)
    assert entry is not None
    checksec: dict[str, Any] = entry["checksec"]
    for key in ("relro", "nx", "pie", "canary"):
        assert checksec.get(key) in {"Full", "Partial", "None", "Enabled", "Disabled"}


def test_binary_analysis_golden_linked_libraries(
    vulnerable_cli_report: dict[str, Any],
) -> None:
    entry = _binary_entry(vulnerable_cli_report, _BINARY_REL)
    assert entry is not None
    libraries: dict[str, Any] = entry["linked_libraries"]
    names = " ".join(str(name) for name in libraries["libraries"])
    assert "libc" in names
    assert "libgcc_s" in names


def test_binary_analysis_golden_suid_sgid_clean(
    vulnerable_cli_report: dict[str, Any],
) -> None:
    assert vulnerable_cli_report["suid_sgid"] == []


def test_binary_analysis_golden_hardlink_pairs_reported(
    vulnerable_cli_report: dict[str, Any],
) -> None:
    # cargo's release build commonly hardlinks the deps artifact to the final
    # binary (st_nlink >= 2); the report lists those path groups when they exist.
    # Zero findings is also acceptable when no hardlinks were produced.
    hardlinks: list[dict[str, Any]] = vulnerable_cli_report["hardlinks"]
    for group in hardlinks:
        assert set(group) == {"paths"}
        assert len(group["paths"]) >= 2
