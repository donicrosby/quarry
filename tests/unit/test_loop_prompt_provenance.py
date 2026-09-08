"""run_agent_loop stamps per-part provenance + real scan_id on invocations.

loop-path-prompt-provenance: with a PromptProvenance bundle, loop-minted
ModelInvocations become verifiable; without it, behavior is unchanged.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from pydantic import BaseModel

from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, PromptProvenance


class _Answer(BaseModel):
    answer: str = "done"
    tool_calls: list[ToolCallRequest] = []


class _NoopRunner:
    def run(self, tool: str, inputs: dict[str, Any]) -> Any:
        class _R:
            output = ""

        return _R()


_PROV = PromptProvenance(
    template_id="hunt/hunt",
    template_version="1.0.0",
    template_sha256="a" * 64,
    part_hashes={"system": "b" * 64, "developer": "d" * 64},
    evidence_hashes=["e" * 64],
)

_SYSTEM = "Hunt for vulnerabilities."
_USER = "Find command injection."


def _run(
    *,
    prompt_provenance: PromptProvenance | None = None,
    scan_id: str | None = None,
) -> MockModelClient:
    client = MockModelClient(default=_Answer())
    run_agent_loop(
        client=client,
        role="hunt",
        agent_kind="hunt",
        system_prompt=_SYSTEM,
        initial_user_message=_USER,
        runner=_NoopRunner(),
        budget_spec=BudgetSpec(),
        response_model=_Answer,
        max_iterations=3,
        prompt_provenance=prompt_provenance,
        scan_id=scan_id,
    )
    return client


def test_provenance_and_scan_id_stamped() -> None:
    client = _run(prompt_provenance=_PROV, scan_id="scan-x")

    assert client.invocations, "loop should mint at least one invocation"
    for inv in client.invocations:
        assert inv.template_sha256 == "a" * 64
        assert inv.system_prompt_hash == "b" * 64
        assert inv.developer_prompt_hash == "d" * 64
        assert inv.user_prompt_hash == sha256(_USER.encode("utf-8")).hexdigest()
        assert inv.evidence_hashes == ["e" * 64]
        assert inv.prompt_template_id == "hunt/hunt"
        assert inv.prompt_template_version == "1.0.0"
        assert inv.scan_id == "scan-x"


def test_backward_compatible_without_provenance() -> None:
    client = _run(prompt_provenance=None, scan_id=None)

    assert client.invocations
    for inv in client.invocations:
        assert inv.template_sha256 == ""
        assert inv.system_prompt_hash == ""
        assert inv.user_prompt_hash == ""
        assert inv.evidence_hashes == []
        # scan_id defaults to the "loop" placeholder when not supplied.
        assert inv.scan_id == "loop"
