"""Tests for ValidateActivity (Week 13 / Part 1B).

Written RED first — these fail until validate_activity is implemented.

The activity:
- Receives a CandidateFinding and builds a ValidatorClaim (never passes the
  full finding to the prompt builder).
- Calls run_agent_loop with role='validate' (read_file + grep only).
- Parses a ternary verdict: validated | rejected | needs_proof.
- Sets cross_vendor_disagreement by comparing provider names (not model names).
- The rendered prompt must contain none of the hunter-provenance fields.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from pydantic import BaseModel

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    CandidateFinding,
    VulnerabilityClass,
)
from quarry_activities.validate import validate_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 6, 9, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class ValidateResponse(BaseModel):
    """Mock response schema that the validate loop produces."""

    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


def _make_finding(
    hunter_provider: str = "anthropic",
    reasoning: str = "HUNTER_REASONING_SECRET",
    affected_component: str = "src/admin.js:42-55",
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        reasoning=reasoning,
        hunter_provider=hunter_provider,
        affected_component=affected_component,
        created_by="hunt-agent",
        created_at=_NOW,
    )


def _make_panel(validate_provider: str = "litellm") -> dict[str, RoleConfig]:
    """Return a panel with validate role using the given provider.

    Uses 'litellm' for the validate role to create a provider mismatch against
    a finding whose hunter_provider is 'anthropic' (a plain string). The
    cross-vendor check compares the provider string from panel entry vs
    finding.hunter_provider.
    """
    panel = dict(DEFAULT_PANEL)
    panel["validate"] = RoleConfig(provider=validate_provider, model="gpt-4o", rpm=30)  # type: ignore[assignment]
    return panel


# ---------------------------------------------------------------------------
# Outcome tests
# ---------------------------------------------------------------------------


class TestValidateActivityOutcomes:
    def test_validated_outcome(self) -> None:
        finding = _make_finding()
        panel = _make_panel(validate_provider="litellm")
        client = MockModelClient(default=ValidateResponse(verdict="validated"))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        assert result.verdict == "validated"
        assert result.candidate_finding_id == "cf-1"

    def test_rejected_outcome(self) -> None:
        finding = _make_finding()
        panel = _make_panel(validate_provider="litellm")
        client = MockModelClient(
            default=ValidateResponse(
                verdict="rejected",
                reasons=["No evidence of unsanitized data flow to exec."],
            )
        )

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        assert result.verdict == "rejected"

    def test_needs_proof_outcome(self) -> None:
        finding = _make_finding()
        panel = _make_panel(validate_provider="litellm")
        client = MockModelClient(
            default=ValidateResponse(
                verdict="needs_proof",
                reasons=["Suspicious pattern found but insufficient static evidence."],
            )
        )

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        assert result.verdict == "needs_proof"


# ---------------------------------------------------------------------------
# Cross-vendor disagreement tests
# ---------------------------------------------------------------------------


class TestCrossVendorDisagreement:
    def test_disagreement_when_providers_differ(self) -> None:
        # hunter used "anthropic" (plain string); validate panel uses "litellm"
        finding = _make_finding(hunter_provider="anthropic")
        panel = _make_panel(validate_provider="litellm")
        client = MockModelClient(default=ValidateResponse(verdict="validated"))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        assert result.cross_vendor_disagreement is True

    def test_no_disagreement_when_same_provider(self) -> None:
        # Both sides use "litellm"
        finding = _make_finding(hunter_provider="litellm")
        panel = _make_panel(validate_provider="litellm")
        client = MockModelClient(default=ValidateResponse(verdict="validated"))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        assert result.cross_vendor_disagreement is False

    def test_disagreement_when_hunter_provider_none(self) -> None:
        """Null hunter_provider + real validate provider → no disagreement (unknown)."""
        finding = _make_finding(hunter_provider=None)  # type: ignore[arg-type]
        panel = _make_panel(validate_provider="litellm")
        client = MockModelClient(default=ValidateResponse(verdict="validated"))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        # hunter_provider is None; we can't assert disagreement
        assert result.cross_vendor_disagreement is False


# ---------------------------------------------------------------------------
# Independence boundary tests
# ---------------------------------------------------------------------------


class TestValidatorIndependenceBoundary:
    def _capture_prompt(self, finding: CandidateFinding, panel: dict[str, Any]) -> str:
        """Capture the prompt text passed to the model by intercepting the client."""
        captured: list[str] = []

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

    def test_hunter_reasoning_not_in_prompt(self) -> None:
        sentinel = "HUNTER_REASONING_SECRET_CANARY_12345"
        finding = _make_finding(reasoning=sentinel)
        panel = _make_panel()

        prompt_text = self._capture_prompt(finding, panel)

        assert sentinel not in prompt_text, (
            "Hunter reasoning text must not appear in the validate-role prompt"
        )

    def test_hunter_provider_not_in_prompt(self) -> None:
        # Use a distinctive string as the hunter_provider sentinel
        finding = _make_finding(hunter_provider="HUNTER_PROVIDER_SENTINEL_XYZ")
        panel = _make_panel()

        prompt_text = self._capture_prompt(finding, panel)

        assert "HUNTER_PROVIDER_SENTINEL_XYZ" not in prompt_text, (
            "Hunter provider name must not appear in the validate-role prompt"
        )

    def test_finding_id_not_in_prompt(self) -> None:
        """The finding ID is internal; the validator should not know which finding it is."""
        finding = _make_finding()
        panel = _make_panel()

        prompt_text = self._capture_prompt(finding, panel)

        # The finding id is an internal UUID; it should not appear
        assert finding.id not in prompt_text

    def test_validate_result_links_to_finding(self) -> None:
        finding = _make_finding()
        panel = _make_panel()
        client = MockModelClient(default=ValidateResponse(verdict="validated"))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=client,
        )

        assert result.candidate_finding_id == finding.id
        assert result.scan_id == finding.scan_id


# ---------------------------------------------------------------------------
# Panel-aware client selection for validate_activity (Change 3)
# ---------------------------------------------------------------------------


def test_validate_activity_mock_panel_does_not_call_build(tmp_path: Path) -> None:
    """validate_activity with provider=mock must not call build_model_client."""
    from unittest.mock import patch

    from quarry.panel_config import RoleConfig
    from quarry.schemas import Provider

    mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30).model_dump_json()
    finding = _make_finding()

    with patch("quarry_activities.validate.build_model_client") as mock_build:
        from quarry_activities.validate import validate_activity

        validate_activity(
            finding.model_dump(mode="json"), str(tmp_path), None, None, mock_panel_json
        )

    mock_build.assert_not_called()


def test_validate_activity_litellm_panel_builds_litellm_client(tmp_path: Path) -> None:
    """validate_activity with provider=litellm must call build_model_client and pass policy."""
    from unittest.mock import patch

    from quarry.panel_config import RoleConfig
    from quarry.schemas import Provider
    from quarry_models.types import ProviderPolicy

    litellm_panel_json = RoleConfig(
        provider=Provider.LITELLM,
        model="chutes/Qwen/Qwen3-235B-A22B",
        rpm=20,
    ).model_dump_json()
    finding = _make_finding()

    fake_client = MagicMock()
    received_policies: list[ProviderPolicy] = []

    def _spy_loop(**kwargs: object) -> object:
        p = kwargs.get("provider_policy")
        if isinstance(p, ProviderPolicy):
            received_policies.append(p)
        from quarry.schemas import AgentLoopResult

        return AgentLoopResult(
            final_answer=None,
            steps=[],
            iterations_used=1,
            total_cost=0.0,
            stop_reason="final_answer",
        )

    with (
        patch(
            "quarry_activities.validate.build_model_client", return_value=fake_client
        ) as mock_build,
        patch("quarry_activities.validate.run_agent_loop", side_effect=_spy_loop),
    ):
        from quarry_activities.validate import validate_activity

        validate_activity(
            finding.model_dump(mode="json"), str(tmp_path), None, None, litellm_panel_json
        )

    mock_build.assert_called_once()
    assert len(received_policies) == 1
    assert received_policies[0].provider == "litellm"
    assert received_policies[0].model == "chutes/Qwen/Qwen3-235B-A22B"
