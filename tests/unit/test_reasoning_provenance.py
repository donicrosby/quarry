"""Session D — reasoning provenance persistence tests (TDD: red first).

Tests:
1. reasoning_summary == scrubbed hypothesis field from ActionReasoning
2. Rejected reasoning leads to non-empty rejected_reasoning_refs on AgentStep
3. QUARRY_SECRET_* pattern is redacted from ActionReasoning fields before use
4. No reasoning_summary from a hunt ActionReasoning appears in the validate-role prompt
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from quarry.panel_config import DEFAULT_PANEL
from quarry.schemas import (
    ActionReasoning,
    CandidateFinding,
    ProposedAction,
    VulnerabilityClass,
)
from quarry_activities.validate import ValidateResponse, validate_impl
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.redaction import scrub
from quarry_models.types import BudgetSpec, ModelResponse

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _LoopAnswer(BaseModel):
    answer: str = "done"
    tool_calls: list[ToolCallRequest] = []
    proposed_actions: list[ProposedAction] = []


_VAGUE_ACTION = ProposedAction(
    kind="read_file",
    tool_name="read_file",
    args={"path": "src/app.py"},
    reasoning=ActionReasoning(
        hypothesis="test the exploit",
        target_ref="somewhere",
        expected_evidence="it works",
        why_this_tool="see what happens",
    ),
)


class _NoopRunner:
    def run(self, tool: str, inputs: dict[str, Any]) -> Any:
        class _R:
            output = ""

        return _R()


class _SequentialMockClient:
    def __init__(self, responses: list[BaseModel]) -> None:
        self._queue = list(responses)
        self.call_count = 0

    def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
        idx = min(self.call_count, len(self._queue) - 1)
        canned = self._queue[idx]
        self.call_count += 1
        parsed = response_model.model_validate(canned.model_dump())
        return ModelResponse(
            parsed=parsed,
            provider="mock",
            model="mock-v1",
            role=request.role,
            prompt_version=request.prompt_version,
            token_input=10,
            token_output=5,
            cached_tokens=0,
            estimated_cost=0.0,
            finish_reason="stop",
        )


# ---------------------------------------------------------------------------
# 1. reasoning_summary == scrubbed hypothesis
# ---------------------------------------------------------------------------


class TestReasoningSummaryIsScrubbedHypothesis:
    def test_scrubbed_hypothesis_has_no_secrets(self) -> None:
        """ActionReasoning.hypothesis with a secret is scrubbed before use."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        reasoning = ActionReasoning(
            hypothesis=f"Looking for AWS key {secret} in the codebase",
            target_ref="src/config.py",
            expected_evidence="AWS key pattern in source file",
            why_this_tool="grep searches recursively for the credential pattern",
        )
        # scrub() should redact the AWS key pattern
        scrubbed = scrub(reasoning.hypothesis)
        assert secret not in scrubbed.text
        assert scrubbed.hits > 0

    def test_reasoning_summary_equals_scrubbed_hypothesis(self) -> None:
        """The scrubbed hypothesis is what should become the reasoning_summary."""
        reasoning = ActionReasoning(
            hypothesis="IDOR via id param — user.py:fetch_profile returns other users",
            target_ref="GET /profile?id=",
            expected_evidence="response body contains another user name",
            why_this_tool="http_request sends crafted id to /profile endpoint",
        )
        expected_summary = scrub(reasoning.hypothesis).text
        assert expected_summary == reasoning.hypothesis  # no secrets → unchanged
        assert len(expected_summary) > 0

    def test_secret_in_why_this_tool_is_scrubbed(self) -> None:
        """Secrets in any ActionReasoning field are scrubbed."""
        reasoning = ActionReasoning(
            hypothesis="SSRF via URL param pointing to internal service",
            target_ref="GET /fetch?url=",
            expected_evidence="Internal service response or redirect",
            why_this_tool="Use token AKIAIOSFODNN7EXAMPLE to test the auth endpoint",
        )
        scrubbed_why = scrub(reasoning.why_this_tool)
        assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed_why.text
        assert scrubbed_why.hits > 0


# ---------------------------------------------------------------------------
# 2. Rejected reasoning leads to non-empty rejected_reasoning_refs on AgentStep
# ---------------------------------------------------------------------------


class TestRejectedReasoningRefs:
    def test_reasoning_rejected_step_has_non_empty_detail(self) -> None:
        """When loop halts with reasoning_rejected, detail should be non-empty."""
        client = _SequentialMockClient(
            [
                _LoopAnswer(
                    proposed_actions=[_VAGUE_ACTION],
                    tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "src/app.py"})],
                )
            ]
            * 5
        )

        result = run_agent_loop(
            client=client,
            role="hunt",
            agent_kind="hunt",
            system_prompt="Hunt for vulnerabilities.",
            initial_user_message="Find XSS.",
            runner=_NoopRunner(),
            budget_spec=BudgetSpec(),
            response_model=_LoopAnswer,
            max_iterations=10,
            reasoning_max_retries=2,
            task_context={"vuln_class": "xss"},
        )

        assert result.stop_reason == "reasoning_rejected"

    def test_reasoning_rejected_uses_fewer_iterations(self) -> None:
        """reasoning_rejected halts well before max_iterations."""
        client = _SequentialMockClient(
            [
                _LoopAnswer(
                    proposed_actions=[_VAGUE_ACTION],
                    tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "src/app.py"})],
                )
            ]
            * 20
        )

        result = run_agent_loop(
            client=client,
            role="hunt",
            agent_kind="hunt",
            system_prompt="Hunt for vulnerabilities.",
            initial_user_message="Find XSS.",
            runner=_NoopRunner(),
            budget_spec=BudgetSpec(),
            response_model=_LoopAnswer,
            max_iterations=10,
            reasoning_max_retries=2,
            task_context={"vuln_class": "xss"},
        )

        assert result.stop_reason == "reasoning_rejected"
        # Should only have 1 real iteration (3 model calls: initial + 2 retries)
        assert result.iterations_used == 1
        assert client.call_count == 3  # initial + reasoning_max_retries


# ---------------------------------------------------------------------------
# 3. Validator independence: no ActionReasoning in validate prompt
# ---------------------------------------------------------------------------


class TestValidatorIndependenceReasoning:
    def _make_finding(self, reasoning_summary: str) -> CandidateFinding:
        """Build a CandidateFinding whose reasoning field contains a sentinel."""
        return CandidateFinding(
            id="cf-prov-1",
            scan_id="scan-prov",
            workspace_id="ws-prov",
            vuln_class=VulnerabilityClass.XSS,
            title="XSS in search",
            hypothesis="Reflected XSS via q param",
            reasoning=reasoning_summary,  # hunt-step reasoning
            hunter_provider="litellm",
            affected_component="src/search.py:42",
            created_by="hunt-agent",
            created_at=_NOW,
        )

    def _capture_prompt(self, finding: CandidateFinding) -> str:
        captured: list[str] = []
        panel = dict(DEFAULT_PANEL)

        class _CapturingClient:
            def complete_structured(self, request: Any, response_model: Any) -> Any:
                for msg in request.messages:
                    captured.append(msg.content)
                return MockModelClient(default=ValidateResponse()).complete_structured(
                    request, response_model
                )

        validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=_CapturingClient(),
        )
        return "\n".join(captured)

    def test_hunt_reasoning_summary_not_in_validate_prompt(self) -> None:
        """A sentinel string set as the hunt step's reasoning must not appear in validate prompt."""
        sentinel = "HUNT_ACTION_REASONING_CANARY_SESSION_D_9876"
        finding = self._make_finding(reasoning_summary=sentinel)

        prompt_text = self._capture_prompt(finding)

        assert sentinel not in prompt_text, (
            "Hunt ActionReasoning (reasoning_summary) must not appear in the validate-role prompt "
            "(validator independence boundary — ADR-020/ADR-021)"
        )

    def test_hunter_provider_not_in_validate_prompt(self) -> None:
        """hunter_provider is excluded from the ValidatorClaim and must not appear in the prompt."""
        finding = self._make_finding("some reasoning")
        finding_dict = finding.model_dump()
        finding_dict["hunter_provider"] = "PROVIDER_SENTINEL_99"
        modified = CandidateFinding.model_validate(finding_dict)

        prompt_text = self._capture_prompt(modified)

        assert "PROVIDER_SENTINEL_99" not in prompt_text
