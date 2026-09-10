"""Tests for the exec-capable tmp_path override in conftest.

These pin the behavior of the session fixture that stages ``tmp_path`` on an
exec-capable filesystem when pytest's default basetemp lives on a ``noexec``
mount (common in containers/CI where /tmp is a noexec tmpfs). Without it,
integration tests that stage and execute a binary from ``tmp_path`` fail with
exit 126 ("Permission denied") despite a correct chmod.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def _is_noexec(path: Path) -> bool:
    """True if `path`'s filesystem is mounted noexec (best-effort)."""
    try:
        out = subprocess.run(
            ["findmnt", "-no", "OPTIONS", "--target", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return "noexec" in out.stdout.split(",")
    except Exception:
        return False


@pytest.fixture
def staged_exec_dir(tmp_path: Path) -> Path:
    """Stage a dummy executable in tmp_path and return the dir.

    The dummy is a real ELF (a copy of /bin/true or equivalent) so a noexec
    mount produces a genuine EACCES, not a shell 'not found'.
    """
    src = None
    for cand in ("/bin/true", "/usr/bin/true", "/bin/echo"):
        if Path(cand).exists():
            src = Path(cand)
            break
    if src is None:
        pytest.skip("no system executable available to stage")
    dest = tmp_path / "probe"
    dest.write_bytes(src.read_bytes())
    dest.chmod(0o755)
    return tmp_path


def test_tmp_path_can_execute_staged_binary(staged_exec_dir: Path) -> None:
    """tmp_path must permit executing a staged binary.

    RED on a noexec /tmp until conftest overrides tmp_path to an exec-capable
    location; GREEN once the fixture reroutes basetemp.
    """
    probe = staged_exec_dir / "probe"
    assert os.access(probe, os.X_OK), f"{probe} lost its exec bit"
    result = subprocess.run([str(probe)], cwd=staged_exec_dir, capture_output=True)
    assert result.returncode == 0, (
        f"staged binary would not execute (exit={result.returncode}); "
        f"tmp_path is likely on a noexec mount: {staged_exec_dir} "
        f"(noexec={_is_noexec(staged_exec_dir)})"
    )
