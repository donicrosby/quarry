"""Golden fixture test: hunt against examples/vulnerable-go.

Uses a recorded response fixture to drive the hunt loop, then asserts that at
least one CandidateFinding has vuln_class in ("command_injection", "idor") and
a file path ending in ".go".  Exact line number is not required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import _hunt_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

FIXTURE_REPO = Path("examples/vulnerable-go").resolve()
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "vulnerable-go-hunt.json"

_ACCEPTED_CLASSES = {VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.IDOR}


@pytest.mark.skipif(
    not FIXTURE_REPO.exists(),
    reason="examples/vulnerable-go not present",
)
def test_hunt_go_finds_command_injection(tmp_path: Path) -> None:
    """Hunt loop against vulnerable-go finds the known command-injection sink.

    The hunter uses a fixture-backed mock; no Go-specific detector code is involved.
    The test proves that the same generic hunt loop works for Go targets.
    """
    fixture = json.loads(FIXTURE_PATH.read_text())
    raw_finding = fixture["mock_finding"]

    class _HuntResponse(BaseModel):
        findings: list[dict[str, Any]] = []
        tool_calls: list[ToolCallRequest] = []

    client = MockModelClient(
        default=_HuntResponse(findings=[raw_finding], tool_calls=[])
    )

    task = AgentTask(
        id="golden-go-1",
        scan_id="golden-scan",
        role="hunt",
        task_name="hunt-command_injection-handlers",
        task_prompt="Look for OS command injection sinks including exec.Command.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        status="pending",
        created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )

    findings = _hunt_impl(
        task=task,
        repo_path=str(FIXTURE_REPO),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
    )

    assert len(findings) >= 1, "Expected at least one finding from the Go hunt"

    accepted_findings = [f for f in findings if f.vuln_class in _ACCEPTED_CLASSES]
    assert len(accepted_findings) >= 1, (
        f"Expected a finding with vuln_class in {[c.value for c in _ACCEPTED_CLASSES]}"
    )

    affected = accepted_findings[0].affected_component or ""
    source_files = [ref.file for ref in accepted_findings[0].source_refs]
    all_paths = [affected] + source_files

    assert any(p.endswith(".go") or ".go:" in p for p in all_paths), (
        f"Expected a .go file path in finding, got: {all_paths}"
    )
