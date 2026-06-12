"""Assert that activity registration lists in worker and server stay in sync.

Written RED first — fails until the dynamic_http activity exists and is
registered in both quarry_worker.main and quarry_server.app.

The two-place gotcha: every activity must be in BOTH:
  - src/quarry_worker/main.py (quarry-control and quarry-control workers)
  - src/quarry_server/app.py lifespan (same workers when no_worker=False)

An activity registered in only one place causes non-deterministic "activity not
registered" failures on whichever worker picks up the task.
"""

from __future__ import annotations

import ast
from pathlib import Path


def _extract_activity_list_from_file(path: Path) -> set[str]:
    """Extract the set of activity function names from a Worker(...) call.

    Parses the source file looking for activities=[...] keyword arguments
    inside Worker(...) constructor calls. Returns the set of all names found.
    """
    source = path.read_text()
    tree = ast.parse(source)

    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Look for Worker(...) calls
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name != "Worker":
            continue
        for kw in node.keywords:
            if kw.arg == "activities" and isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Name):
                        names.add(elt.id)
                    elif isinstance(elt, ast.Attribute):
                        names.add(elt.attr)
    return names


REPO_ROOT = Path(__file__).parent.parent.parent
WORKER_FILE = REPO_ROOT / "src/quarry_worker/main.py"
SERVER_FILE = REPO_ROOT / "src/quarry_server/app.py"


class TestWorkerRegistrationParity:
    def test_worker_and_server_activity_lists_are_identical(self) -> None:
        """Both files must register the same activities."""
        worker_activities = _extract_activity_list_from_file(WORKER_FILE)
        server_activities = _extract_activity_list_from_file(SERVER_FILE)

        only_in_worker = worker_activities - server_activities
        only_in_server = server_activities - worker_activities

        errors: list[str] = []
        if only_in_worker:
            missing = sorted(only_in_worker)
            errors.append(f"Registered in worker only (missing from server): {missing}")
        if only_in_server:
            missing = sorted(only_in_server)
            errors.append(f"Registered in server only (missing from worker): {missing}")

        assert not errors, (
            "Activity registration parity violation:\n"
            + "\n".join(str(e) for e in errors)
            + "\n\nBoth src/quarry_worker/main.py and src/quarry_server/app.py "
            "must register identical activity lists."
        )

    def test_dynamic_http_activity_registered_in_worker(self) -> None:
        """http_request_activity must appear in the worker's activity list."""
        worker_activities = _extract_activity_list_from_file(WORKER_FILE)
        assert "http_request_activity" in worker_activities, (
            "http_request_activity must be registered in quarry_worker/main.py. "
            "It runs on the quarry-control task queue."
        )

    def test_dynamic_http_activity_registered_in_server(self) -> None:
        """http_request_activity must appear in the server's activity list."""
        server_activities = _extract_activity_list_from_file(SERVER_FILE)
        assert "http_request_activity" in server_activities, (
            "http_request_activity must be registered in quarry_server/app.py. "
            "It runs on the quarry-control task queue."
        )
