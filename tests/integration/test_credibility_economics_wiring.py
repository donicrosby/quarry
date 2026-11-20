"""Integration: credibility-economics cascade wiring (task 8.4).

Drives the REAL validate wiring — config parse, SQLite counter selection, the
corroboration cascade, the debater branch, and the ``finding.cascade`` event —
with a mixed-tier mock scan, then feeds the cascade result into the coverage
ledger. The cascade's per-step unit tests live in
``tests/unit/test_credibility_economics.py``; this file exercises the wiring end
to end, which is where the probe-budget-drain defect (R2) lived: nothing else
drove ``validate_impl`` / ``validate_activity`` with a non-None credibility
config.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import text

from quarry.panel_config import CredibilityConfig, ModelTier, Provider, RoleConfig, TierKind
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    CredibilityLevel,
    Scan,
    ScanProfile,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
)
from quarry_activities.coverage import compute_cell_coverage
from quarry_activities.validate import (
    RefuteResponse,
    ValidateResponse,
    validate_activity,
    validate_impl,
)
from quarry_models.mock_client import MockModelClient
from quarry_persistence import QuarryRepository
from quarry_persistence.counters import MODEL_COUNTER_NAME, PROBE_COUNTER_NAME
from quarry_persistence.db import create_sqlite_engine

_NOW = datetime(2026, 11, 20, tzinfo=UTC)
_SCAN_ID = "scan-ce"
_ECONOMY = "gpt-4.1-mini"  # ECONOMY tier → prior 0.6 for a model judgment
_FRONTIER = "claude-opus-4-8"  # FRONTIER tier → prior 1.0 for a model judgment


def _finding(
    fid: str,
    *,
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQL_INJECTION,
    grounded: bool = False,
    model_id: str | None = _ECONOMY,
    severity: Severity = Severity.HIGH,
    affected: str = "src/app.py",
    root_cause_key: str | None = "rc-app",
    metadata: dict[str, object] | None = None,
    corroborated: bool = False,
) -> CandidateFinding:
    return CandidateFinding(
        id=fid,
        scan_id=_SCAN_ID,
        workspace_id="local",
        vuln_class=vuln_class,
        title=f"candidate {fid}",
        hypothesis="h",
        affected_component=affected,
        root_cause_key=root_cause_key,
        severity=severity,
        grounded=grounded,
        originating_model_id=model_id,
        corroborated=corroborated,
        created_by="hunt-agent",
        created_at=_NOW,
        metadata=metadata or {},
    )


def _task(
    tid: str,
    vuln_class: VulnerabilityClass,
    *,
    scope: str,
    source: str = "recon",
) -> AgentTask:
    return AgentTask(
        id=tid,
        scan_id=_SCAN_ID,
        role="hunt",
        task_name="hunt",
        vuln_class=vuln_class,
        scope=scope,
        source=source,  # type: ignore[arg-type]
        status="pending",
        created_at=_NOW,
    )


def _validate_role() -> RoleConfig:
    """A mixed-tier validate role: a reasoner plus an independent debater."""
    return RoleConfig(
        provider=Provider.MOCK,
        model="mock-v1",
        tiers=[
            ModelTier(kind=TierKind.REASONER, provider=Provider.MOCK, model=_FRONTIER),
            ModelTier(
                kind=TierKind.DEBATER,
                provider=Provider.MOCK,
                model=_ECONOMY,
                prompt_regime="refute",
            ),
        ],
    )


def _debater_tier() -> ModelTier:
    return ModelTier(
        kind=TierKind.DEBATER,
        provider=Provider.MOCK,
        model=_ECONOMY,
        prompt_regime="refute",
    )


def _run(
    finding: CandidateFinding,
    *,
    db_path: Path,
    repo_path: Path,
    config: CredibilityConfig | None = None,
    refuted: bool = False,
):
    """Drive the real validate wiring for one finding through the cascade."""
    return validate_impl(
        finding=finding,
        repo_path=str(repo_path),
        panel={"validate": _validate_role()},
        client=MockModelClient(default=ValidateResponse(verdict="validated")),
        debater_client=MockModelClient(
            default=RefuteResponse(
                refuted=refuted,
                reasons=["the sink is guarded"] if refuted else [],
            )
        ),
        debater_tier=_debater_tier(),
        checklist_enabled=False,
        credibility_config=config if config is not None else CredibilityConfig(),
        db_path=str(db_path),
    )


def _create_scan(db_path: Path) -> QuarryRepository:
    repo = QuarryRepository(db_path)
    repo.create_scan(
        Scan(
            id=_SCAN_ID,
            workspace_id="local",
            target_id="tgt-1",
            requested_by="test",
            profile=ScanProfile(id="p", name="p", vuln_classes=[VulnerabilityClass.SQL_INJECTION]),
            status=ScanStatus.RUNNING,
            created_at=_NOW,
        ),
        Target(id="tgt-1", workspace_id="local", repo_path="/tmp/repo", created_at=_NOW),
    )
    return repo


def _counter(db_path: Path, name: str) -> int:
    engine = create_sqlite_engine(db_path)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT value FROM credibility_counters WHERE scan_id = :s AND name = :n"),
            {"s": _SCAN_ID, "n": name},
        ).first()
    assert row is not None, f"counter {name!r} was never seeded"
    return int(row[0])


# ---------------------------------------------------------------------------
# Cascade order: the zero-cost steps resolve without touching either counter
# ---------------------------------------------------------------------------


def test_zero_cost_steps_resolve_in_order(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    repo = _create_scan(db)
    # Step 2 needs a stored tool-grounded finding on the SAME target.
    repo.save_candidate_finding(
        _finding(
            "other-free",
            vuln_class=VulnerabilityClass.SECRETS,
            grounded=True,
            model_id=None,
            affected="src/free.py",
            root_cause_key=None,
        )
    )

    frontier = _run(
        _finding(
            "f-frontier",
            grounded=False,
            model_id=_FRONTIER,
            affected="src/frontier.py",
            root_cause_key="k-frontier",
        ),
        db_path=db,
        repo_path=tmp_path,
    )
    assert frontier.cascade_step == "frontier_pass"
    assert frontier.credibility is CredibilityLevel.UNREFUTED

    free = _run(
        _finding(
            "f-free",
            vuln_class=VulnerabilityClass.SECRETS,
            grounded=False,
            model_id=_ECONOMY,
            affected="src/free.py",
            root_cause_key=None,
        ),
        db_path=db,
        repo_path=tmp_path,
    )
    assert free.cascade_step == "free_tool_corroboration"
    assert free.corroborated is True

    passive = _run(
        _finding(
            "f-passive",
            grounded=False,
            model_id=_ECONOMY,
            severity=Severity.INFO,
            affected="src/passive.py",
            root_cause_key="k-passive",
        ),
        db_path=db,
        repo_path=tmp_path,
    )
    assert passive.cascade_step == "passive_low_severity"
    assert passive.credibility is CredibilityLevel.UNREFUTED

    # All three resolved at zero cost: neither counter moved from its cap.
    assert _counter(db, PROBE_COUNTER_NAME) == 20
    assert _counter(db, MODEL_COUNTER_NAME) == 5


# ---------------------------------------------------------------------------
# Step 4: deterministic probe, confirm and refute paths
# ---------------------------------------------------------------------------


def test_step4_confirm_and_refute_spend_one_probe_unit(tmp_path: Path) -> None:
    db = tmp_path / "q.db"

    confirm = _run(
        _finding(
            "f-probe-ok",
            vuln_class=VulnerabilityClass.SSTI,
            affected="src/ssti.py",
            root_cause_key="k-ssti",
            metadata={"live_probe": {"status_code": 200, "body_text": "{{7*7}} -> 49"}},
        ),
        db_path=db,
        repo_path=tmp_path,
    )
    assert confirm.cascade_step == "probe_oracle"
    assert confirm.credibility is CredibilityLevel.UNREFUTED
    assert confirm.corroborated is True
    assert _counter(db, PROBE_COUNTER_NAME) == 19

    refute = _run(
        _finding(
            "f-probe-no",
            vuln_class=VulnerabilityClass.SSTI,
            affected="src/ssti2.py",
            root_cause_key="k-ssti2",
            metadata={"live_probe": {"status_code": 200, "body_text": "no marker"}},
        ),
        db_path=db,
        repo_path=tmp_path,
    )
    assert refute.cascade_step == "probe_oracle"
    assert refute.credibility is CredibilityLevel.CONTESTED
    assert _counter(db, PROBE_COUNTER_NAME) == 18
    # A refuting probe stops before the debater — the model budget is untouched.
    assert _counter(db, MODEL_COUNTER_NAME) == 5


def test_missing_probe_evidence_does_not_drain_probe_budget(tmp_path: Path) -> None:
    """R2 regression: a finding with no recorded probe evidence must skip step 4
    WITHOUT spending a probe unit — the pre-fix cascade drained the budget for a
    guaranteed-inconclusive evaluation."""
    db = tmp_path / "q.db"
    result = _run(
        _finding("f-noprobe", affected="src/noprobe.py", root_cause_key="k-noprobe"),
        db_path=db,
        repo_path=tmp_path,
    )
    assert result.cascade_step == "paid_debater"
    assert result.credibility is CredibilityLevel.UNREFUTED
    assert _counter(db, PROBE_COUNTER_NAME) == 20  # NOT drained
    assert _counter(db, MODEL_COUNTER_NAME) == 4


# ---------------------------------------------------------------------------
# Step 5: the paid debater, confirm and refute paths
# ---------------------------------------------------------------------------


def test_step5_debater_confirms_unrefuted(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    result = _run(
        _finding("f-debate-ok", affected="src/debate.py", root_cause_key="k-debate"),
        db_path=db,
        repo_path=tmp_path,
    )
    assert result.cascade_step == "paid_debater"
    assert result.credibility is CredibilityLevel.UNREFUTED
    assert result.corroborated is True
    assert _counter(db, MODEL_COUNTER_NAME) == 4


def test_step5_debater_refutes(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    result = _run(
        _finding("f-debate-no", affected="src/debate2.py", root_cause_key="k-debate2"),
        db_path=db,
        repo_path=tmp_path,
        refuted=True,
    )
    assert result.cascade_step == "paid_debater"
    assert result.credibility is CredibilityLevel.REFUTED
    assert _counter(db, MODEL_COUNTER_NAME) == 4


def test_model_budget_exhausted_records_contested(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    result = _run(
        _finding("f-exhausted", affected="src/exh.py", root_cause_key="k-exh"),
        db_path=db,
        repo_path=tmp_path,
        config=CredibilityConfig(model_budget=0),
    )
    assert result.cascade_step == "model_budget_exhausted"
    assert result.credibility is CredibilityLevel.CONTESTED
    assert _counter(db, MODEL_COUNTER_NAME) == 0


# ---------------------------------------------------------------------------
# Activity wiring: config parse, SQLite counters, finding.cascade event
# ---------------------------------------------------------------------------


def test_validate_activity_parses_config_and_emits_cascade_event(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    _create_scan(db)
    finding = _finding("f-activity", affected="src/activity.py", root_cause_key="k-act")

    result = validate_activity(
        finding,
        str(tmp_path),
        None,
        None,
        _validate_role().model_dump_json(),
        str(db),
        20,
        None,
        None,
        None,
        CredibilityConfig().model_dump_json(),
    )

    assert result["cascade_step"] == "paid_debater"
    assert result["credibility"] == "unrefuted"
    assert result["corroborated"] is True
    # The SQLite counters were selected (db_path path), not the in-process ones.
    assert _counter(db, MODEL_COUNTER_NAME) == 4
    assert _counter(db, PROBE_COUNTER_NAME) == 20  # no live_probe evidence → step 4 skipped

    events = QuarryRepository(db).load_events(_SCAN_ID)
    cascade_events = [e for e in events if e.event_type == "finding.cascade"]
    assert len(cascade_events) == 1
    payload = cascade_events[0].payload
    assert payload["finding_id"] == "f-activity"
    assert payload["cascade_step"] == "paid_debater"
    assert payload["corroborated"] == "true"


# ---------------------------------------------------------------------------
# Coverage ledger: thresholds, promotion, terminal state
# ---------------------------------------------------------------------------


def test_coverage_ledger_respects_thresholds_and_terminal_state() -> None:
    tasks = [
        _task("t-sqli", VulnerabilityClass.SQL_INJECTION, scope="src/"),
        # A gapfill re-hunt of the same cell marks it terminal once it stays
        # uncovered after the re-hunt.
        _task("t-sqli-gf", VulnerabilityClass.SQL_INJECTION, scope="src/", source="gapfill"),
        _task("t-xss", VulnerabilityClass.XSS, scope="lib/"),
        _task("t-ssrf", VulnerabilityClass.SSRF, scope="web/"),
    ]
    findings = [
        # Discounted economy judgment, uncorroborated → cell uncovered + terminal.
        _finding(
            "c-sqli",
            vuln_class=VulnerabilityClass.SQL_INJECTION,
            grounded=False,
            affected="src/a.py",
            root_cause_key="k1",
        ),
        # Tool-grounded → covered regardless of tier.
        _finding(
            "c-xss",
            vuln_class=VulnerabilityClass.XSS,
            grounded=True,
            model_id=None,
            affected="lib/x.js",
            root_cause_key="k2",
        ),
        # Low-tier but corroborated → covered + corroboration_promotion.
        _finding(
            "c-ssrf",
            vuln_class=VulnerabilityClass.SSRF,
            grounded=False,
            affected="web/s.py",
            root_cause_key="k3",
            corroborated=True,
        ),
    ]

    cells = {
        cell.vuln_class: cell
        for cell in compute_cell_coverage(tasks, findings, credibility_enabled=True)
    }

    assert cells[VulnerabilityClass.SQL_INJECTION].covered is False
    assert cells[VulnerabilityClass.SQL_INJECTION].terminal_uncovered is True
    assert cells[VulnerabilityClass.XSS].covered is True
    assert cells[VulnerabilityClass.SSRF].covered is True
    assert cells[VulnerabilityClass.SSRF].corroboration_promotion is True


def test_cascade_promotion_flows_into_coverage_ledger(tmp_path: Path) -> None:
    """End to end: a probe-confirmed low-tier judgment is promoted by the cascade
    and then marks its coverage cell covered."""
    db = tmp_path / "q.db"
    finding = _finding(
        "c-promoted",
        vuln_class=VulnerabilityClass.SSRF,
        grounded=False,
        affected="web/s.py",
        root_cause_key="k-ssrf",
        metadata={
            "live_probe": {
                "status_code": 200,
                "body_text": "internal data",
                "additional": [{"status_code": 200, "body_text": "denied"}],
            }
        },
    )
    result = _run(finding, db_path=db, repo_path=tmp_path)
    assert result.cascade_step == "probe_oracle"
    assert result.corroborated is True

    # Mirror the workflow's post-gather copy of the cascade signal onto the finding.
    promoted = finding.model_copy(update={"corroborated": result.corroborated})
    cells = compute_cell_coverage(
        [_task("t-ssrf", VulnerabilityClass.SSRF, scope="web/")],
        [promoted],
        credibility_enabled=True,
    )
    assert cells[0].covered is True
    assert cells[0].corroboration_promotion is True
