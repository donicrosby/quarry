"""End-to-end evidence-path population + source_refs reliance retirement (cpc 7.2).

The sink-first ordered ``evidence_path`` must be populated at every finding
construction site (hunt parse, secrets plugin, FinalFinding promotion) so
dedup's sink key works end to end, and no stage may *rely* on unordered
``source_refs`` ordering any more (the field stays for back-compat; reads
prefer the ordered path).

Written RED first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.benchmark import GroundTruthFinding, compare
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    EvidencePathElement,
    FinalFinding,
    HttpResponseCapture,
    RedactionStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_activities.hunt import hunt_impl
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec
from quarry_plugins.vuln_classes.secrets import SecretMatch, secret_match_to_candidate_finding
from quarry_workflows.run_scan import final_from_candidate, promote_with_dynamic_evidence

_NOW = datetime(2026, 9, 12, tzinfo=UTC)


class _HuntOut(BaseModel):
    """Mirrors the hunt loop's response schema (validated by MockModelClient)."""

    findings: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []


def _task() -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-7",
        role="hunt",
        task_name="hunt-ssrf",
        task_prompt="Look for outbound request sinks.",
        vuln_class=VulnerabilityClass.SSRF,
        scope="app.py",
        status="pending",
        created_at=_NOW,
    )


def _hunt(raw_findings: list[dict[str, Any]]) -> list[CandidateFinding]:
    findings, _gaps = hunt_impl(
        task=_task(),
        repo_path=".",
        max_iterations=4,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=MockModelClient(default=_HuntOut(findings=raw_findings)),
    )
    return findings


# ---------------------------------------------------------------------------
# Hunt: evidence_path populated from model output, sink first
# ---------------------------------------------------------------------------


class TestHuntParseEvidencePath:
    def test_model_evidence_path_preserved_sink_first(self) -> None:
        findings = _hunt(
            [
                {
                    "title": "SSRF in fetch-local",
                    "hypothesis": "User URL reaches outbound fetch.",
                    "affected_component": "app.py:78",
                    "confidence": "medium",
                    "severity": "high",
                    "evidence_path": [
                        {"path": "app.py", "line": 78},
                        {"path": "client.py", "line": 30},
                        {"path": "routes.py", "line": 12},
                    ],
                }
            ]
        )
        assert len(findings) == 1
        assert [el.locator for el in findings[0].evidence_path] == [
            "app.py:78",
            "client.py:30",
            "routes.py:12",
        ]

    def test_sink_derived_from_affected_component_when_path_absent(self) -> None:
        """Back-compat: a model that only emits affected_component still gets a
        sink-first path with the sink at index 0."""
        findings = _hunt(
            [
                {
                    "title": "SSRF in fetch-local",
                    "hypothesis": "h",
                    "affected_component": "app.py:78",
                    "confidence": "medium",
                    "severity": "high",
                }
            ]
        )
        assert len(findings) == 1
        assert [el.locator for el in findings[0].evidence_path] == ["app.py:78"]

    def test_no_fabricated_locator_when_affected_component_has_no_line(self) -> None:
        """Spec: no fabricated locators — a component without a parseable line
        yields an empty evidence path, not a made-up line."""
        findings = _hunt(
            [
                {
                    "title": "SSRF in fetch-local",
                    "hypothesis": "h",
                    "affected_component": "app.py",
                    "confidence": "medium",
                    "severity": "high",
                }
            ]
        )
        assert len(findings) == 1
        assert findings[0].evidence_path == []

    def test_invalid_evidence_path_elements_dropped(self) -> None:
        findings = _hunt(
            [
                {
                    "title": "SSRF in fetch-local",
                    "hypothesis": "h",
                    "affected_component": "app.py:78",
                    "confidence": "medium",
                    "severity": "high",
                    "evidence_path": [
                        {"path": "/abs/is/rejected.py", "line": 1},
                        {"path": "app.py", "line": 78},
                        {"path": "app.py", "line": "not-a-number"},
                    ],
                }
            ]
        )
        assert len(findings) == 1
        assert [el.locator for el in findings[0].evidence_path] == ["app.py:78"]

    def test_malformed_evidence_path_falls_back_to_derivation(self) -> None:
        findings = _hunt(
            [
                {
                    "title": "SSRF in fetch-local",
                    "hypothesis": "h",
                    "affected_component": "app.py:78",
                    "confidence": "medium",
                    "severity": "high",
                    "evidence_path": "not-a-list",
                }
            ]
        )
        assert len(findings) == 1
        assert [el.locator for el in findings[0].evidence_path] == ["app.py:78"]


# ---------------------------------------------------------------------------
# Secrets plugin populates the sink
# ---------------------------------------------------------------------------


class TestSecretsPopulateSink:
    def test_secret_match_carries_sink_evidence_path(self) -> None:
        match = SecretMatch(
            file_path="config/settings.py", line_number=9, key_name="ADMIN_API_KEY", value="x"
        )
        finding = secret_match_to_candidate_finding(match, scan_id="s1")
        assert [el.locator for el in finding.evidence_path] == ["config/settings.py:9"]


# ---------------------------------------------------------------------------
# Promotion carries the ordered path; source_refs[0] reliance retired
# ---------------------------------------------------------------------------


def _candidate(**overrides: object) -> CandidateFinding:
    base: dict[str, object] = {
        "id": "cf-1",
        "scan_id": "s1",
        "workspace_id": "local",
        "vuln_class": VulnerabilityClass.SSRF,
        "title": "SSRF in fetch-local",
        "hypothesis": "h",
        "affected_component": "app.py:78",
        "source_refs": [
            SourceRef(file_path="routes.py", start_line=12),
            SourceRef(file_path="app.py", start_line=78),
        ],
        "evidence_path": [EvidencePathElement(path="app.py", line=78)],
        "confidence": Confidence.MEDIUM,
        "severity": Severity.HIGH,
        "created_by": "hunt-agent",
        "created_at": _NOW,
    }
    base.update(overrides)
    return CandidateFinding.model_validate(base)


class TestPromotionCarriesEvidencePath:
    def test_final_from_candidate_carries_evidence_path(self) -> None:
        final = final_from_candidate(_candidate(), "s1", _NOW)
        assert [el.locator for el in final.evidence_path] == ["app.py:78"]

    def test_dynamic_promotion_links_sink_not_source_refs_zero(self) -> None:
        """The DynamicEvidenceLink must cite the ordered sink (app.py:78),
        not the first unordered source_ref (routes.py:12)."""
        capture = HttpResponseCapture(
            status_code=200,
            elapsed_ms=5,
            body_artifact_ref="body",
            request_artifact_ref="req",
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        result = promote_with_dynamic_evidence(_candidate(), capture, "s1", _NOW)
        assert result is not None
        final, link = result
        assert link.source_ref.file_path == "app.py"
        assert link.source_ref.start_line == 78
        assert [el.locator for el in final.evidence_path] == ["app.py:78"]

    def test_dynamic_promotion_falls_back_to_source_refs_without_path(self) -> None:
        capture = HttpResponseCapture(
            status_code=200,
            elapsed_ms=5,
            body_artifact_ref="body",
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        result = promote_with_dynamic_evidence(_candidate(evidence_path=[]), capture, "s1", _NOW)
        assert result is not None
        _final, link = result
        assert link.source_ref.file_path == "routes.py"


# ---------------------------------------------------------------------------
# Benchmark scoring prefers the ordered sink path over source_refs order
# ---------------------------------------------------------------------------


def _final(**overrides: object) -> FinalFinding:
    base: dict[str, object] = {
        "id": "f1",
        "scan_id": "s1",
        "workspace_id": "local",
        "fingerprint": "fp",
        "vuln_class": VulnerabilityClass.SSRF,
        "severity": Severity.HIGH,
        "title": "t",
        "summary": "s",
        "source_refs": [SourceRef(file_path="unrelated.py")],
        "evidence_path": [EvidencePathElement(path="app.py", line=78)],
        "validation_result_id": "vr",
        "created_at": _NOW,
    }
    base.update(overrides)
    return FinalFinding.model_validate(base)


class TestBenchmarkPrefersSinkPath:
    def test_benchmark_matches_on_sink_path_not_source_refs_order(self) -> None:
        """A finding whose unordered source_refs[0] names a different file than
        the sink still matches ground truth for the sink's file."""
        truth = [
            GroundTruthFinding(
                id="gt-1",
                vuln_class=VulnerabilityClass.SSRF,
                file_path="app.py",
                severity=Severity.HIGH,
            )
        ]
        result = compare([_final()], truth)
        assert len(result.matched) == 1
        assert not result.missed

    def test_benchmark_still_matches_via_source_refs_fallback(self) -> None:
        truth = [
            GroundTruthFinding(
                id="gt-1",
                vuln_class=VulnerabilityClass.SSRF,
                file_path="legacy.py",
                severity=Severity.HIGH,
            )
        ]
        result = compare(
            [_final(evidence_path=[], source_refs=[SourceRef(file_path="legacy.py")])], truth
        )
        assert len(result.matched) == 1


# ---------------------------------------------------------------------------
# Hunt prompts ask the model for the ordered sink-first path
# ---------------------------------------------------------------------------


class TestHuntPromptAsksForEvidencePath:
    def test_generic_hunt_template_names_evidence_path_sink_first(self) -> None:
        source = (
            Path(__file__).parent.parent.parent / "prompts" / "hunt" / "hunt.1.0.0.j2"
        ).read_text(encoding="utf-8")
        assert "evidence_path" in source
        assert "sink first" in source.lower()

    def test_every_per_class_hunt_template_names_evidence_path(self) -> None:
        prompts_root = Path(__file__).parent.parent.parent / "prompts" / "hunt"
        per_class = sorted(p for p in prompts_root.glob("*.1.0.0.j2") if p.name != "hunt.1.0.0.j2")
        assert per_class, "expected per-class hunt templates"
        for path in per_class:
            source = path.read_text(encoding="utf-8")
            assert "evidence_path" in source, f"{path.name} does not ask for evidence_path"
