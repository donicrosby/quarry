"""Feature flag: checklist refuter on/off (cpc task 5.4).

``QUARRY_VALIDATE_CHECKLIST_ENABLED`` (default on) selects the adversarial
negative-constraint checklist refuter. When disabled the validator falls back
to the current binary refuter — no checklist recorded, legacy stance semantics.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from quarry.config import QuarrySettings
from quarry.panel_config import DEFAULT_PANEL, ModelTier, Provider, RoleConfig, TierKind
from quarry.schemas import (
    ChecklistConstraint,
    ChecklistItem,
    ChecklistOutcome,
    CandidateFinding,
    VulnerabilityClass,
)
from quarry_activities.validate import (
    ChecklistRefuteResponse,
    RefuteResponse,
    validate_impl,
)
from quarry_models.checklist import discharged_checklist
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 9, 11, tzinfo=UTC)


class _ValidateResponse(BaseModel):
    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


def _finding() -> CandidateFinding:
    return CandidateFinding(
        id="cf-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        hunter_provider="anthropic",
        affected_component="src/admin.py:42",
        created_by="hunt-agent",
        created_at=_NOW,
    )


def _debater_tier() -> ModelTier:
    return ModelTier(
        kind=TierKind.DEBATER,
        provider=Provider.MOCK,
        model="mock-debater",
        prompt_regime="refute",
    )


def _panel() -> dict[str, RoleConfig]:
    return dict(DEFAULT_PANEL)


class TestChecklistFlagDefault:
    def test_flag_defaults_on(self) -> None:
        assert QuarrySettings().validate_checklist_enabled is True

    def test_flag_reads_env_off(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.setenv("QUARRY_VALIDATE_CHECKLIST_ENABLED", "false")
        assert QuarrySettings().validate_checklist_enabled is False


class TestChecklistOnPath:
    def test_enabled_records_checklist_and_promotes_discharged(self) -> None:
        result = validate_impl(
            finding=_finding(),
            repo_path="/tmp/repo",
            panel=_panel(),
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
            debater_client=MockModelClient(
                default=ChecklistRefuteResponse(refuted=False, checklist=discharged_checklist())
            ),
            debater_tier=_debater_tier(),
            checklist_enabled=True,
        )
        assert result.verdict == "validated"
        assert [i.constraint for i in result.checklist] == list(ChecklistConstraint)


class TestChecklistOffPath:
    def test_disabled_falls_back_to_binary_refuter(self) -> None:
        """Legacy path: RefuteResponse, no checklist, stance honored unchanged."""
        result = validate_impl(
            finding=_finding(),
            repo_path="/tmp/repo",
            panel=_panel(),
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
            debater_client=MockModelClient(default=RefuteResponse(refuted=False)),
            debater_tier=_debater_tier(),
            checklist_enabled=False,
        )
        # Binary refuter failed to refute → reasoner verdict stands as validated.
        assert result.verdict == "validated"
        assert result.checklist == []

    def test_disabled_binary_refuter_rejection_does_not_add_checklist(self) -> None:
        result = validate_impl(
            finding=_finding(),
            repo_path="/tmp/repo",
            panel=_panel(),
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
            debater_client=MockModelClient(default=RefuteResponse(refuted=True)),
            debater_tier=_debater_tier(),
            checklist_enabled=False,
        )
        # Binary refuter stance never rewrites the reasoner verdict on the
        # legacy path, and no checklist is recorded.
        assert result.verdict == "validated"
        assert result.checklist == []
        debater = [j for j in result.ensemble if j.tier == TierKind.DEBATER.value]
        assert debater and debater[0].refuted is True


# Sentinel import guard: ChecklistItem must exist for the flag-gated schema.
_ = ChecklistItem
_ = ChecklistOutcome
