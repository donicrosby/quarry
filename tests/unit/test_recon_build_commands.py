"""Tests for build-command detection in recon synthesis (ADR-024 §C.1).

Recon synthesis must detect the target's build system from manifest files and
populate ``ArchitectureDoc.build_commands`` so the prove sandbox can build
targets generically, instead of hardcoding ``build_commands=[]``.
"""

from __future__ import annotations

from pathlib import Path

from quarry_activities.recon_synthesis import detect_build_commands


def _mk(root: Path, *files: str) -> Path:
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    return root


def test_cargo_toml_yields_cargo_build_release(tmp_path: Path) -> None:
    _mk(tmp_path, "Cargo.toml")
    cmds = detect_build_commands(tmp_path)
    assert any(c.purpose == "build" and "cargo build --release" in c.command for c in cmds)


def test_pyproject_yields_python_run(tmp_path: Path) -> None:
    _mk(tmp_path, "pyproject.toml", "app.py")
    cmds = detect_build_commands(tmp_path)
    assert any(c.purpose == "run" and "python" in c.command for c in cmds)


def test_package_json_yields_npm(tmp_path: Path) -> None:
    _mk(tmp_path, "package.json")
    cmds = detect_build_commands(tmp_path)
    assert any("npm" in c.command for c in cmds)


def test_go_mod_yields_go_build(tmp_path: Path) -> None:
    _mk(tmp_path, "go.mod", "main.go")
    cmds = detect_build_commands(tmp_path)
    assert any("go build" in c.command or "go run" in c.command for c in cmds)


def test_makefile_yields_make(tmp_path: Path) -> None:
    _mk(tmp_path, "Makefile")
    cmds = detect_build_commands(tmp_path)
    assert any("make" in c.command for c in cmds)


def test_cmakelists_yields_cmake(tmp_path: Path) -> None:
    _mk(tmp_path, "CMakeLists.txt")
    cmds = detect_build_commands(tmp_path)
    assert any("cmake" in c.command for c in cmds)


def test_unknown_build_system_yields_empty_list(tmp_path: Path) -> None:
    _mk(tmp_path, "README.md", "main.cob")
    assert detect_build_commands(tmp_path) == []


def test_empty_repo_yields_empty_list(tmp_path: Path) -> None:
    assert detect_build_commands(tmp_path) == []


def test_nonexistent_root_yields_empty_list(tmp_path: Path) -> None:
    assert detect_build_commands(tmp_path / "does-not-exist") == []


def test_all_commands_have_working_dir(tmp_path: Path) -> None:
    _mk(tmp_path, "Cargo.toml")
    for c in detect_build_commands(tmp_path):
        assert c.working_dir  # never empty


# --- Acceptance (board ticket C1): real example targets ---------------------

EXAMPLES = Path(__file__).resolve().parent.parent.parent / "examples"


def test_vulnerable_cli_acceptance() -> None:
    """Recon on vulnerable-cli (Rust) must produce `cargo build --release`."""
    if not (EXAMPLES / "vulnerable-cli" / "Cargo.toml").exists():
        import pytest

        pytest.skip("vulnerable-cli example not present")
    cmds = detect_build_commands(EXAMPLES / "vulnerable-cli")
    assert any(c.purpose == "build" and "cargo build --release" in c.command for c in cmds)


def test_vulnerable_fastapi_acceptance() -> None:
    """Recon on vulnerable-fastapi (Python) must produce a run command."""
    if not (EXAMPLES / "vulnerable-fastapi" / "pyproject.toml").exists():
        import pytest

        pytest.skip("vulnerable-fastapi example not present")
    cmds = detect_build_commands(EXAMPLES / "vulnerable-fastapi")
    assert any(c.purpose == "run" for c in cmds)


def test_recon_synthesis_populates_build_commands(tmp_path: Path) -> None:
    """End-to-end: the activity wires detection into the ArchitectureDoc."""
    from quarry_activities.recon_synthesis import recon_synthesis_activity

    _mk(tmp_path, "Cargo.toml")
    doc = recon_synthesis_activity([], tmp_path, "scan-bc")
    assert any("cargo build --release" in c.command for c in doc.build_commands)


def test_recon_synthesis_empty_when_no_build_system(tmp_path: Path) -> None:
    from quarry_activities.recon_synthesis import recon_synthesis_activity

    doc = recon_synthesis_activity([], tmp_path, "scan-none")
    assert doc.build_commands == []
