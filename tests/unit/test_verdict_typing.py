"""Cruft-purge §2.5 residue: verdict typing + parse-boundary tolerance.

Pins the deliverable of the cruft-2.5-verdict-typing slice:

1. ``EnsembleJudgement.verdict`` is typed against the new ``JudgementVerdict``
   StrEnum (house style — see ``ReachabilityVerdict``) and serialises
   byte-identically to the former bare-``str`` field on the JSON wire
   (model_dump_json round-trip regression test).
2. Unknown/empty model-derived verdict strings are tolerated at the parse
   boundary, never raising: schema-level pydantic coercion on the model, and
   the workflow's ensemble mirror in ``run_scan.py`` (VALIDATE stage), which
   applies model-derived judgements onto the persisted CandidateFinding.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import BaseModel

from quarry.panel_config import DEFAULT_PANEL, ModelTier, RoleConfig, TierKind
from quarry.schemas import (
    CandidateFinding,
    EnsembleJudgement,
    JudgementVerdict,
    Provider,
    VulnerabilityClass,
)
from quarry_activities.validate import validate_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient


def _judgement(**overrides: Any) -> EnsembleJudgement:
    base: dict[str, Any] = {
        "role": "validate",
        "tier": "reasoner",
        "provider": "mock",
        "model": "mock-reasoner",
        "verdict": "validated",
        "model_invocation_id": "inv-1",
    }
    base.update(overrides)
    return EnsembleJudgement(**base)


class TestJudgementVerdictTyping:
    def test_verdict_vocabulary_parses_without_loss(self) -> None:
        for raw in ("validated", "rejected", "refuted", "unrefuted"):
            judgement = _judgement(verdict=raw)
            # StrEnum semantics: equal to both the enum member and its value.
            assert judgement.verdict == JudgementVerdict(raw)
            assert judgement.verdict == raw

    def test_enum_construction_is_canonical(self) -> None:
        assert [m.value for m in JudgementVerdict] == [
            "validated",
            "rejected",
            "refuted",
            "unrefuted",
        ]

    def test_wire_format_is_byte_identical_to_bare_str(self) -> None:
        """Serialised JSON must equal the pre-typing (plain str) wire format."""
        for raw in ("validated", "rejected", "refuted", "unrefuted"):
            judgement = _judgement(verdict=raw)
            dumped = judgement.model_dump_json()
            decoded = cast(dict[str, Any], json.loads(dumped))
            assert decoded["verdict"] == raw
            assert f'"verdict":"{raw}"' in dumped
            # Round-trip through the wire reproduces the identical byte string.
            assert EnsembleJudgement.model_validate_json(dumped).model_dump_json() == dumped

    def test_json_schema_still_admits_plain_strings(self) -> None:
        """The schema keeps a plain-string arm so model-derived verdicts that
        fall outside the enum vocabulary remain schema-valid on the wire."""
        verdict_schema = EnsembleJudgement.model_json_schema(mode="serialization")["properties"][
            "verdict"
        ]
        options = verdict_schema.get("anyOf", [verdict_schema])
        assert any(opt.get("type") == "string" for opt in options)

    def test_unknown_verdict_string_is_tolerated(self) -> None:
        """An unknown model-emitted verdict must not raise at parse."""
        judgement = _judgement(verdict="bogus")
        assert judgement.verdict == "bogus"

    def test_empty_verdict_string_is_tolerated(self) -> None:
        """An empty verdict string must not raise at parse."""
        judgement = _judgement(verdict="")
        assert judgement.verdict == ""


class TestWorkflowEnsembleMirrorTolerance:
    """The workflow mirrors model-derived ensemble judgements onto the candidate
    (run_scan.py VALIDATE stage) and the mirrored candidate later round-trips
    through ``CandidateFinding.model_validate`` at every persistence boundary
    (e.g. ``_load_candidate_findings``, post-hunt re-validation). Unknown/empty
    verdict strings in those judgements must survive the pydantic coercion —
    a judgement is retained for audit, never a scan-killing parse failure."""

    def test_unknown_and_empty_verdicts_survive_model_validate(self) -> None:
        candidate = CandidateFinding(
            id="cf-1",
            scan_id="scan-1",
            workspace_id="ws-1",
            vuln_class=VulnerabilityClass.COMMAND_INJECTION,
            title="t",
            hypothesis="h",
            created_by="hunt-agent",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        ensemble_payload: list[dict[str, Any]] = [
            {
                "role": "validate",
                "tier": "reasoner",
                "provider": "mock",
                "model": "m",
                "verdict": "bogus",
                "model_invocation_id": "inv-1",
            },
            {
                "role": "validate",
                "tier": "debater",
                "provider": "mock",
                "model": "m",
                "verdict": "",
                "refuted": False,
                "model_invocation_id": "inv-2",
            },
        ]
        payload = candidate.model_dump(mode="json")
        payload["ensemble"] = ensemble_payload
        parsed = CandidateFinding.model_validate(payload)
        assert [j.verdict for j in parsed.ensemble] == ["bogus", ""]


class _ValidateResponse(BaseModel):
    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


class _RefuteResponse(BaseModel):
    refuted: bool = False
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


def _finding() -> CandidateFinding:
    return CandidateFinding(
        id="cf-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="t",
        hypothesis="h",
        hunter_provider="anthropic",
        created_by="hunt-agent",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _debater_tier() -> ModelTier:
    return ModelTier(
        kind=TierKind.DEBATER,
        provider=Provider.MOCK,
        model="mock-debater",
        prompt_regime="refute",
    )


class TestWriterEmitsJudgementVerdict:
    """``validate_impl`` writes the ensemble judgements — pin that the verdict
    values it records are ``JudgementVerdict`` members, not ad-hoc strings."""

    def _run(self, *, refuted: bool) -> Any:
        panel = dict(DEFAULT_PANEL)
        panel["validate"] = RoleConfig(provider=Provider.MOCK, model="mock-reasoner")
        return validate_impl(
            finding=_finding(),
            repo_path="/tmp/repo",
            panel=panel,
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
            debater_client=MockModelClient(default=_RefuteResponse(refuted=refuted)),
            debater_tier=_debater_tier(),
        )

    def test_reasoner_verdict_is_enum_member(self) -> None:
        result = self._run(refuted=False)
        reasoner = next(j for j in result.ensemble if j.tier == TierKind.REASONER.value)
        assert reasoner.verdict == JudgementVerdict.VALIDATED

    def test_debater_unrefuted_verdict_is_enum_member(self) -> None:
        result = self._run(refuted=False)
        debater = next(j for j in result.ensemble if j.tier == TierKind.DEBATER.value)
        assert debater.verdict == JudgementVerdict.UNREFUTED

    def test_debater_refuted_verdict_is_enum_member(self) -> None:
        result = self._run(refuted=True)
        debater = next(j for j in result.ensemble if j.tier == TierKind.DEBATER.value)
        assert debater.verdict == JudgementVerdict.REFUTED
