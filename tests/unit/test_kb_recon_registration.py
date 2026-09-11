"""Tests for worker/server/test-fixture registration of the KB recon activity.

Written RED first for openspec change candidate-precision-and-calibration,
task 2.3 (register in server + worker + tests per the sandboxed-runner rules).

The parity hazard: every new activity must be registered in ALL of
``quarry_worker.main``, ``quarry_server.app`` (in-process worker), and
``tests/conftest.py`` (temporal_worker fixture), or runs fail
non-deterministically with "activity not registered" on whichever worker picks
up the task.
"""

from __future__ import annotations

import inspect


def test_kb_recon_activity_has_defn_decorator() -> None:
    """The activity is a sync ``@activity.defn`` so workers can register it."""
    from quarry_activities.kb_recon import kb_recon_activity

    assert hasattr(kb_recon_activity, "__temporal_activity_definition")
    assert not inspect.iscoroutinefunction(kb_recon_activity)


def test_kb_recon_registered_in_standalone_worker() -> None:
    from quarry_worker.main import run_worker

    source = inspect.getsource(run_worker)
    assert "kb_recon_activity" in source, (
        "kb_recon_activity must be registered in quarry_worker/main.py"
    )


def test_kb_recon_registered_in_server_worker() -> None:
    import quarry_server.app as server_app

    source = inspect.getsource(server_app)
    assert "kb_recon_activity" in source, (
        "kb_recon_activity must be registered in the in-process worker in "
        "quarry_server/app.py"
    )


def test_kb_recon_registered_in_test_fixture() -> None:
    import tests.conftest as conftest

    source = inspect.getsource(conftest)
    assert "kb_recon_activity" in source, (
        "kb_recon_activity must be registered in the temporal_worker fixture in "
        "tests/conftest.py (sandboxed-runner parity with the production workers)"
    )
