"""CyberGym smoke test — one C/C++ task, no scored benchmark run.

This script takes a single synthetic CyberGym-style C task (a file with a
buffer overflow / command injection sink), runs hunt_activity against it
with a MockModelClient fixture, and asserts that at least one CandidateFinding
is emitted.

Usage:
    uv run python eval/cybergym_smoke.py

Exit code 0 = smoke passed; 1 = failure.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import _hunt_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

# A minimal C function that passes user input to system() — the kind of
# pattern a CyberGym task would contain.
_C_TASK_SOURCE = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Processes a command string from the network buffer. */
int handle_network_command(const char *input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s >> /var/log/audit.log", input);
    return system(cmd);
}
"""

_MOCK_FINDING = {
    "vuln_class": "command_injection",
    "title": "User input reaches system() via snprintf in handle_network_command",
    "hypothesis": "The 'input' parameter is interpolated into a shell command string passed to system() without sanitization.",
    "affected_component": "task.c:10",
    "confidence": "high",
    "severity": "critical",
    "source_refs": [
        {
            "repo": ".",
            "file": "task.c",
            "start_line": 9,
            "end_line": 10,
            "snippet": 'snprintf(cmd, ..., "echo %s ...", input); return system(cmd);',
        }
    ],
}


class _HuntResponse(BaseModel):
    findings: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def run_smoke() -> int:
    with tempfile.TemporaryDirectory(prefix="quarry-cybergym-") as tmpdir:
        task_file = Path(tmpdir) / "task.c"
        task_file.write_text(_C_TASK_SOURCE, encoding="utf-8")

        client = MockModelClient(
            default=_HuntResponse(findings=[_MOCK_FINDING], tool_calls=[])
        )

        task = AgentTask(
            id="cybergym-smoke-1",
            scan_id="cybergym-smoke",
            role="hunt",
            task_name="hunt-command_injection-c-task",
            task_prompt=(
                "Hunt for command injection in this C task. "
                "Look for calls to system(), popen(), or exec() that receive "
                "unsanitized user input."
            ),
            vuln_class=VulnerabilityClass.COMMAND_INJECTION,
            scope=".",
            status="pending",
            created_at=datetime.now(UTC),
        )

        findings = _hunt_impl(
            task=task,
            repo_path=tmpdir,
            max_iterations=12,
            budget_spec=BudgetSpec(max_cost_usd=None),
            client=client,
        )

        if not findings:
            print("FAIL: no findings produced", file=sys.stderr)
            return 1

        cmdi = [f for f in findings if f.vuln_class == VulnerabilityClass.COMMAND_INJECTION]
        if not cmdi:
            print(
                f"FAIL: findings present but none are command_injection: "
                f"{[f.vuln_class.value for f in findings]}",
                file=sys.stderr,
            )
            return 1

        print(
            f"PASS: {len(cmdi)} command_injection candidate(s) — "
            f"'{cmdi[0].title}' in {cmdi[0].affected_component}"
        )
        return 0


if __name__ == "__main__":
    sys.exit(run_smoke())
