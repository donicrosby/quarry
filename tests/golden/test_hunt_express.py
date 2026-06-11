"""Golden fixture test: hunt against examples/vulnerable-express.

Uses a recorded response fixture to drive the hunt loop, then asserts that at
least one CandidateFinding has vuln_class="command_injection" and a file path
containing "routes/".  The exact line number is not required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import hunt_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

FIXTURE_REPO = Path("examples/vulnerable-express").resolve()
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "vulnerable-express-hunt.json"


@pytest.mark.skipif(
    not FIXTURE_REPO.exists(),
    reason="examples/vulnerable-express not present",
)
def test_hunt_express_finds_command_injection(tmp_path: Path) -> None:
    """Hunt loop against vulnerable-express finds the known command-injection route."""
    fixture = json.loads(FIXTURE_PATH.read_text())
    raw_finding = fixture["mock_finding"]

    class _HuntResponse(BaseModel):
        findings: list[dict[str, Any]] = []
        tool_calls: list[ToolCallRequest] = []

    client = MockModelClient(default=_HuntResponse(findings=[raw_finding], tool_calls=[]))

    task = AgentTask(
        id="golden-express-1",
        scan_id="golden-scan",
        role="hunt",
        task_name="hunt-command_injection-routes",
        task_prompt="Look for OS command injection sinks.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="routes/",
        status="pending",
        created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )

    findings, _gaps = hunt_impl(
        task=task,
        repo_path=str(FIXTURE_REPO),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
    )

    assert len(findings) >= 1, "Expected at least one finding from the Express hunt"

    cmdi_findings = [f for f in findings if f.vuln_class == VulnerabilityClass.COMMAND_INJECTION]
    assert len(cmdi_findings) >= 1, "Expected at least one command_injection finding"

    affected = cmdi_findings[0].affected_component or ""
    source_files = [ref.file_path for ref in cmdi_findings[0].source_refs]
    all_paths = [affected] + source_files

    assert any("routes/" in p or "routes" in p for p in all_paths), (
        f"Expected a finding in routes/, got paths: {all_paths}"
    )
