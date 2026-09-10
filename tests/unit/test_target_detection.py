"""Tests for generalized target-type detection and launch commands (D7).

The target launcher must not assume a Python/uvicorn app. It detects the target
runtime from repo contents and builds the appropriate launch command so
``quarry target start`` works across all examples/vulnerable-* targets.
"""

from __future__ import annotations

from pathlib import Path

from quarry_activities.target import TargetKind, detect_target_kind, launch_command


def _mk(root: Path, *files: str) -> Path:
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    return root


# --- detection ---------------------------------------------------------------


def test_detects_fastapi(tmp_path: Path) -> None:
    _mk(tmp_path, "app.py", "pyproject.toml")
    assert detect_target_kind(tmp_path) == TargetKind.FASTAPI


def test_detects_express(tmp_path: Path) -> None:
    _mk(tmp_path, "package.json", "app.js")
    assert detect_target_kind(tmp_path) == TargetKind.EXPRESS


def test_detects_go(tmp_path: Path) -> None:
    _mk(tmp_path, "go.mod", "main.go")
    assert detect_target_kind(tmp_path) == TargetKind.GO


def test_detects_rust(tmp_path: Path) -> None:
    _mk(tmp_path, "Cargo.toml")
    assert detect_target_kind(tmp_path) == TargetKind.RUST


def test_detects_compose(tmp_path: Path) -> None:
    _mk(tmp_path, "docker-compose.yml")
    assert detect_target_kind(tmp_path) == TargetKind.COMPOSE


def test_detects_compose_alt_name(tmp_path: Path) -> None:
    _mk(tmp_path, "compose.yml")
    assert detect_target_kind(tmp_path) == TargetKind.COMPOSE


def test_unknown_target_raises(tmp_path: Path) -> None:
    _mk(tmp_path, "README.md")
    import pytest

    with pytest.raises(ValueError, match="[Uu]nsupported|[Uu]nknown|detect"):
        detect_target_kind(tmp_path)


# --- launch command construction ---------------------------------------------


def test_fastapi_command_is_uvicorn(tmp_path: Path) -> None:
    _mk(tmp_path, "app.py", "pyproject.toml")
    cmd = launch_command(tmp_path, host="127.0.0.1", port=8000)
    assert "uvicorn" in cmd


def test_express_command_is_node(tmp_path: Path) -> None:
    _mk(tmp_path, "package.json", "app.js")
    cmd = launch_command(tmp_path, host="127.0.0.1", port=8000)
    assert any("node" in part for part in cmd)


def test_go_command_is_go_run(tmp_path: Path) -> None:
    _mk(tmp_path, "go.mod", "main.go")
    cmd = launch_command(tmp_path, host="127.0.0.1", port=8000)
    assert any("go" in part for part in cmd)


def test_rust_command_is_cargo(tmp_path: Path) -> None:
    _mk(tmp_path, "Cargo.toml")
    cmd = launch_command(tmp_path, host="127.0.0.1", port=8000)
    assert any("cargo" in part for part in cmd)


def test_compose_command_is_docker_compose(tmp_path: Path) -> None:
    _mk(tmp_path, "docker-compose.yml")
    cmd = launch_command(tmp_path, host="127.0.0.1", port=8000)
    assert any("compose" in part for part in cmd)


# --- acceptance: real example targets ----------------------------------------

EXAMPLES = Path(__file__).resolve().parent.parent.parent / "examples"


def test_acceptance_all_examples_detectable() -> None:
    """Every examples/vulnerable-* target resolves to a kind + launch command."""
    expected = {
        "vulnerable-fastapi": TargetKind.FASTAPI,
        "vulnerable-express": TargetKind.EXPRESS,
        "vulnerable-go": TargetKind.GO,
        "vulnerable-cli": TargetKind.RUST,
    }
    import pytest

    for name, kind in expected.items():
        target = EXAMPLES / name
        if not target.is_dir():
            pytest.skip(f"{name} example not present")
        assert detect_target_kind(target) == kind, name
        assert launch_command(target, host="127.0.0.1", port=8000), name
