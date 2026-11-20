"""credibility-economics: write-time gating, cascade, counters, coverage cells.

Scenario names mirror the reviewed change's spec deltas
(``openspec/changes/credibility-economics/specs/*/spec.md``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.panel_config import CredibilityConfig
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    CredibilityLevel,
    Severity,
    VulnerabilityClass,
)
from quarry_activities.corroborator import (
    LIVE_CONFIRMED,
    LIVE_INCONCLUSIVE,
    LIVE_REFUTED,
    CascadeCounters,
    CascadeEvaluators,
    CascadeStep,
    CascadeVerdict,
    Corroborator,
)
from quarry_activities.coverage import (
    compute_cell_coverage,
    finding_counts_toward_coverage,
)
from quarry_activities.verdict_evaluators import (
    TIMING_INJECTED_DELAY_FRACTION,
    TIMING_MIN_SIGMA_MULTIPLIER,
    LiveProbeEvidence,
    timing_differential_evaluator,
)
from quarry_models.credibility import (
    BASE_CREDIBILITY_PRIOR,
    TIER_THRESHOLD,
    ModelReliabilityTier,
    credibility_prior_for,
    resolve_model_tier,
)
from quarry_persistence.counters import (
    MODEL_COUNTER_NAME,
    PROBE_COUNTER_NAME,
    InProcessBudgetCounter,
    SqliteBudgetCounter,
    initialize_credibility_counters,
)
from quarry_persistence.db import create_sqlite_engine

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _finding(
    *,
    fid: str = "f1",
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQL_INJECTION,
    grounded: bool = True,
    model_id: str | None = None,
    severity: Severity = Severity.HIGH,
    affected: str = "src/app.py",
    root_cause_key: str | None = "rc-1",
    corroborated: bool = False,
) -> CandidateFinding:
    return CandidateFinding(
        id=fid,
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=vuln_class,
        title="t",
        hypothesis="h",
        affected_component=affected,
        root_cause_key=root_cause_key,
        severity=severity,
        grounded=grounded,
        originating_model_id=model_id,
        corroborated=corroborated,
        created_by="test",
        created_at=_NOW,
    )


def _task(
    *,
    vuln_class: VulnerabilityClass | None = VulnerabilityClass.SQL_INJECTION,
    scope: str | None = "src",
    source: str = "recon",
    tid: str = "t1",
) -> AgentTask:
    return AgentTask(
        id=tid,
        scan_id="scan-1",
        role="hunt",
        task_name="hunt",
        vuln_class=vuln_class,
        scope=scope,
        source=source,  # type: ignore[arg-type]
        status="pending",
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Tier map + prior
# ---------------------------------------------------------------------------


def test_tier_map_is_static_and_documented() -> None:
    """tier-map-is-static-and-documented: no live pricing call, source cited."""
    import inspect

    import quarry_models.credibility as mod

    doc = inspect.getdoc(mod.ModelReliabilityTier) or ""
    assert "Swarm" in doc
    assert isinstance(mod.MODEL_TIER_MAP, dict)
    # A pure dict lookup — the resolver performs no I/O.
    assert resolve_model_tier("claude-opus-4-8") is ModelReliabilityTier.FRONTIER


def test_known_model_resolves_to_correct_tier() -> None:
    assert resolve_model_tier("claude-opus-4-8") is ModelReliabilityTier.FRONTIER
    assert resolve_model_tier("claude-sonnet-4-6") is ModelReliabilityTier.STRONG
    assert resolve_model_tier("gpt-4.1-mini") is ModelReliabilityTier.ECONOMY
    # Vendor-prefixed LiteLLM ids and deployment suffixes normalise.
    assert resolve_model_tier("anthropic/claude-opus-4-8") is ModelReliabilityTier.FRONTIER
    assert resolve_model_tier("chutes/deepseek-ai/DeepSeek-V3.2-TEE") is ModelReliabilityTier.MID
    # Longest key wins: opus-4-8 is FRONTIER, not the shorter opus-4 entry.
    assert resolve_model_tier("claude-opus-4-8-preview") is ModelReliabilityTier.FRONTIER


def test_unknown_and_absent_model_fall_back_to_mid() -> None:
    """None-case (reviewer nit): an absent model id resolves to MID."""
    assert resolve_model_tier("some-unknown-model") is ModelReliabilityTier.MID
    assert resolve_model_tier(None) is ModelReliabilityTier.MID


def test_grounded_finding_gets_full_prior() -> None:
    """tool-grounded-finding-gets-full-prior."""
    prior, discount = credibility_prior_for(grounded=True, originating_model_id="gpt-4.1-mini")
    assert prior == 1.0
    assert discount is None
    assert BASE_CREDIBILITY_PRIOR == 1.0


def test_frontier_model_judgment_gets_undiscounted() -> None:
    """frontier-model-judgment-gets-undiscounted."""
    prior, discount = credibility_prior_for(grounded=False, originating_model_id="claude-opus-4-8")
    assert prior == 1.0
    assert discount == 1.0


def test_economy_model_judgment_gets_discounted() -> None:
    """economy-model-judgment-gets-discounted: prior = base * tier_factor < 1.0."""
    prior, discount = credibility_prior_for(grounded=False, originating_model_id="gpt-4.1-mini")
    assert prior == pytest.approx(0.6)
    assert discount == pytest.approx(0.6)
    assert prior < 1.0


def test_finding_derives_prior_and_records_discount() -> None:
    grounded = _finding(grounded=True, model_id="gpt-4.1-mini")
    assert grounded.credibility_prior == 1.0
    assert grounded.credibility_discount is None

    judgment = _finding(grounded=False, model_id="gpt-4.1-mini")
    assert judgment.credibility_prior == pytest.approx(0.6)
    assert judgment.credibility_discount == pytest.approx(0.6)


def test_grounded_flag_survives_round_trip(tmp_path: Path) -> None:
    """grounded-flag-survives-round-trip: persistence preserves the tag + prior."""
    from quarry.schemas import Scan, ScanProfile, ScanStatus, Target
    from quarry_persistence import QuarryRepository

    db = tmp_path / "q.db"
    repo = QuarryRepository(db)
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id="tgt-1",
        requested_by="test",
        profile=ScanProfile(id="p", name="p", vuln_classes=[VulnerabilityClass.SQL_INJECTION]),
        status=ScanStatus.RUNNING,
        created_at=_NOW,
    )
    target = Target(
        id="tgt-1",
        workspace_id="local",
        repo_path="/tmp/repo",
        created_at=_NOW,
    )
    repo.create_scan(scan, target)
    finding = _finding(grounded=False, model_id="gpt-4.1-mini")
    repo.save_candidate_finding(finding)
    loaded = repo.load_candidate_findings("scan-1")
    assert len(loaded) == 1
    assert loaded[0].grounded is False
    assert loaded[0].originating_model_id == "gpt-4.1-mini"
    assert loaded[0].credibility_prior == pytest.approx(0.6)
    assert loaded[0].credibility_discount == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# Write-time tagging at the construction sites
# ---------------------------------------------------------------------------


def test_hunt_findings_are_model_judgments() -> None:
    """grounded-tag-applied-at-all-construction-sites (hunt path)."""
    from quarry_activities.hunt import _parse_finding  # type: ignore[reportPrivateUsage]

    parsed = _parse_finding(
        {"title": "x", "hypothesis": "y", "affected_component": "src/a.py:3"},
        "scan-1",
        "local",
        VulnerabilityClass.SQL_INJECTION,
        originating_model_id="gpt-4.1-mini",
    )
    assert parsed is not None
    assert parsed.grounded is False
    assert parsed.originating_model_id == "gpt-4.1-mini"
    assert parsed.credibility_prior == pytest.approx(0.6)


def test_deterministic_sweep_findings_are_grounded() -> None:
    """grounded-tag-applied-at-all-construction-sites (tool-observed paths)."""
    from quarry_plugins.vuln_classes.secrets import SecretMatch, secret_match_to_candidate_finding
    from quarry_workflows.candidate_sources import secret_candidates_from_activity_payload

    match = SecretMatch(
        key_name="API_KEY",
        file_path="src/a.py",
        line_number=3,
        value="***",
    )
    plugin_finding = secret_match_to_candidate_finding(match, scan_id="scan-1", created_at=_NOW)
    assert plugin_finding.grounded is True
    assert plugin_finding.credibility_prior == 1.0

    sweep = secret_candidates_from_activity_payload(
        [{"key_name": "API_KEY", "file_path": "src/a.py", "line_number": 3}],
        scan_id="scan-1",
        created_at=_NOW,
    )
    assert [f.grounded for f in sweep] == [True]


def test_exploitation_chain_finding_is_grounded() -> None:
    from quarry_workflows.exploitation_loop import ExploitChain, exploit_chain_to_candidate

    chain = ExploitChain(
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SSRF,
        proven=True,
        steps=[],
    )
    finding = exploit_chain_to_candidate(
        chain,
        finding_id="f",
        title="t",
        hypothesis="h",
        created_by="exploit-loop",
        created_at=_NOW,
    )
    assert finding is not None
    assert finding.grounded is True


# ---------------------------------------------------------------------------
# Cascade
# ---------------------------------------------------------------------------


class _StubCounter:
    """A budget counter that always grants (or always gates)."""

    def __init__(self, grants: bool) -> None:
        self.grants = grants

    def take(self) -> bool:
        return self.grants


def _counters(*, probe: bool = True, model: bool = True) -> CascadeCounters:
    """Build the two-counter bundle the cascade consumes from grant flags."""
    return CascadeCounters(probe=_StubCounter(probe), model=_StubCounter(model))


def _evaluators(
    *,
    free: CascadeStep | None = None,
    probe: str | None = None,
    debater: bool | None = False,
    severity_threshold: Severity = Severity.MEDIUM,
) -> CascadeEvaluators:
    return CascadeEvaluators(
        free_corroboration=lambda _f: free,
        probe=lambda _f: probe,
        debater=lambda _f: debater,
        severity_threshold=severity_threshold,
    )


def test_step1_frontier_prior_skips_debater() -> None:
    """frontier-prior-skips-debater."""
    outcome = Corroborator().decide(
        _finding(grounded=True),
        TIER_THRESHOLD,
        _counters(),
        _evaluators(),
    )
    assert outcome.credibility is CredibilityLevel.UNREFUTED
    assert outcome.cascade_step is CascadeStep.FRONTIER_PASS


def test_step2_free_tool_corroboration() -> None:
    """tool-grounded-evidence-promotes-free."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(),
        _evaluators(free=CascadeStep.FREE_TOOL_CORROBORATION),
    )
    assert outcome.credibility is CredibilityLevel.UNREFUTED
    assert outcome.cascade_step is CascadeStep.FREE_TOOL_CORROBORATION
    assert outcome.corroborated is True


def test_step2_two_independent_signals() -> None:
    """two-independent-signals-promote-free."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(),
        _evaluators(free=CascadeStep.FREE_SIGNAL_CORROBORATION),
    )
    assert outcome.cascade_step is CascadeStep.FREE_SIGNAL_CORROBORATION


def test_step3_low_severity_passive_pass() -> None:
    """low-severity-passive-pass."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini", severity=Severity.INFO),
        0.6,
        _counters(),
        _evaluators(),
    )
    assert outcome.credibility is CredibilityLevel.UNREFUTED
    assert outcome.cascade_step is CascadeStep.PASSIVE_LOW_SEVERITY


def test_step4_probe_confirms() -> None:
    """probe-oracle-confirms-unrefuted."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(),
        _evaluators(probe=LIVE_CONFIRMED),
    )
    assert outcome.credibility is CredibilityLevel.UNREFUTED
    assert outcome.cascade_step is CascadeStep.PROBE_ORACLE
    assert outcome.verdict is CascadeVerdict.CONFIRMED
    assert outcome.corroborated is True


def test_step4_probe_refutes_demotes_to_contested() -> None:
    """probe-oracle-refutes-demotes-to-contested: no debater step."""
    seen: list[str] = []
    evaluators = CascadeEvaluators(
        free_corroboration=lambda _f: None,
        probe=lambda _f: LIVE_REFUTED,
        debater=lambda _f: seen.append("debater") or False,
        severity_threshold=Severity.MEDIUM,
    )
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"), 0.6, _counters(), evaluators
    )
    assert outcome.credibility is CredibilityLevel.CONTESTED
    assert outcome.verdict is CascadeVerdict.REFUTED
    assert seen == []


def test_step4_budget_exhausted_skips_oracle() -> None:
    """probe-budget-exhausted-skips-oracle: skip is recorded, debater runs."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(probe=False),
        _evaluators(probe=LIVE_CONFIRMED),
    )
    assert outcome.cascade_step is CascadeStep.PAID_DEBATER
    assert CascadeStep.PROBE_BUDGET_EXHAUSTED in outcome.skipped_steps


def test_step5_debater_confirms() -> None:
    """debater-confirms-unrefuted."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(),
        _evaluators(probe=LIVE_INCONCLUSIVE, debater=False),
    )
    assert outcome.credibility is CredibilityLevel.UNREFUTED
    assert outcome.cascade_step is CascadeStep.PAID_DEBATER
    assert outcome.verdict is CascadeVerdict.CONFIRMED


def test_step5_debater_refutes() -> None:
    """debater-refutes-finding-refuted."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(),
        _evaluators(probe=LIVE_INCONCLUSIVE, debater=True),
    )
    assert outcome.credibility is CredibilityLevel.REFUTED
    assert outcome.verdict is CascadeVerdict.REFUTED


def test_model_budget_exhausted_records_contested() -> None:
    """model-budget-exhausted-recorded-contested: scan continues."""
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        _counters(probe=False, model=False),
        _evaluators(),
    )
    assert outcome.credibility is CredibilityLevel.CONTESTED
    assert outcome.cascade_step is CascadeStep.MODEL_BUDGET_EXHAUSTED
    assert outcome.verdict is CascadeVerdict.INDETERMINATE


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def _counter(db_path: Path, name: str, *, cap: int, unlimited: bool = False) -> SqliteBudgetCounter:
    engine = create_sqlite_engine(db_path)
    counter = SqliteBudgetCounter(engine, "scan-1", name, unlimited=unlimited)
    counter.initialize(cap)
    return counter


def test_probe_counter_decrements_atomically(tmp_path: Path) -> None:
    """probe-counter-decrements-atomically."""
    counter = _counter(tmp_path / "q.db", PROBE_COUNTER_NAME, cap=2)
    assert counter.take() is True
    assert counter.value() == 1


def test_counter_exhaustion_gates_and_restores(tmp_path: Path) -> None:
    """probe-counter-exhaustion-gates-oracle-step: gated, then restored via INCR."""
    counter = _counter(tmp_path / "q.db", PROBE_COUNTER_NAME, cap=1)
    assert counter.take() is True
    assert counter.value() == 0
    assert counter.take() is False
    # Restored, not left negative.
    assert counter.value() == 0


def test_counter_initialization_is_idempotent_on_resume(tmp_path: Path) -> None:
    """counter-initialization-at-scan-start / counter-persistence-survives-scan-resume."""
    db = tmp_path / "q.db"
    initialize_credibility_counters(db_path=db, scan_id="scan-1", probe_budget=3, model_budget=5)
    counter = _counter(db, PROBE_COUNTER_NAME, cap=3)
    assert counter.take() is True
    # Resume: re-seeding must NOT re-grant the ceiling.
    initialize_credibility_counters(db_path=db, scan_id="scan-1", probe_budget=3, model_budget=5)
    assert counter.value() == 2


def test_zero_cap_gates_unless_explicitly_unlimited(tmp_path: Path) -> None:
    """counters-are-configured-with-defaults: zero cap is not unlimited."""
    gated = _counter(tmp_path / "a.db", MODEL_COUNTER_NAME, cap=0)
    assert gated.take() is False
    unlimited = _counter(tmp_path / "b.db", MODEL_COUNTER_NAME, cap=0, unlimited=True)
    assert unlimited.take() is True


def test_default_credibility_config_caps() -> None:
    config = CredibilityConfig()
    assert (config.probe_budget, config.model_budget) == (20, 5)
    assert config.probe_unlimited is False
    assert config.model_unlimited is False


def test_in_process_counter_contract() -> None:
    counter = InProcessBudgetCounter(1)
    assert counter.take() is True
    assert counter.take() is False
    assert InProcessBudgetCounter(0, unlimited=True).take() is True


# ---------------------------------------------------------------------------
# Coverage cells
# ---------------------------------------------------------------------------


def test_low_tier_uncorroborated_leaves_cell_uncovered() -> None:
    """low-tier-uncorroborated-leaves-cell-uncovered (and is gapfill-eligible)."""
    cells = compute_cell_coverage(
        [_task()],
        [_finding(grounded=False, model_id="gpt-4.1-mini")],
        credibility_enabled=True,
    )
    assert len(cells) == 1
    assert cells[0].covered is False
    assert cells[0].terminal_uncovered is False


def test_tool_grounded_marks_cell_covered() -> None:
    """tool-grounded-marks-cell-covered: regardless of tier."""
    cells = compute_cell_coverage(
        [_task()],
        [_finding(grounded=True, model_id="gpt-4.1-mini")],
        credibility_enabled=True,
    )
    assert cells[0].covered is True


def test_corroborated_low_tier_counts_covered() -> None:
    """corroborated-low-tier-counts-covered: corroboration_promotion recorded."""
    cells = compute_cell_coverage(
        [_task()],
        [_finding(grounded=False, model_id="gpt-4.1-mini", corroborated=True)],
        credibility_enabled=True,
    )
    assert cells[0].covered is True
    assert cells[0].corroboration_promotion is True


def test_frontier_tier_judgment_counts_covered_and_records_tier() -> None:
    """frontier-or-strong-tier-judgment-counts-covered: tier recorded for audit."""
    cells = compute_cell_coverage(
        [_task()],
        [_finding(grounded=False, model_id="claude-opus-4-8")],
        credibility_enabled=True,
    )
    assert cells[0].covered is True
    assert cells[0].tier == "frontier"


def test_exhausted_gapfill_marks_terminal_uncovered() -> None:
    """exhausted-gapfill-marks-terminal-uncovered: still uncovered after one re-hunt."""
    tasks = [_task(tid="t1"), _task(tid="t2", source="gapfill")]
    cells = compute_cell_coverage(
        tasks,
        [_finding(grounded=False, model_id="gpt-4.1-mini")],
        credibility_enabled=True,
    )
    assert cells[0].covered is False
    assert cells[0].terminal_uncovered is True


def test_feature_disabled_counts_every_occupant() -> None:
    """Backward compatibility: with no [credibility] config every occupant counts."""
    cells = compute_cell_coverage(
        [_task()],
        [_finding(grounded=False, model_id="gpt-4.1-mini")],
        credibility_enabled=False,
    )
    assert cells[0].covered is True
    assert cells[0].terminal_uncovered is False


def test_finding_counts_toward_coverage_predicate() -> None:
    assert finding_counts_toward_coverage(_finding(grounded=True)) is True
    assert finding_counts_toward_coverage(_finding(grounded=False, model_id="claude-opus-4-8"))
    assert not finding_counts_toward_coverage(_finding(grounded=False, model_id="gpt-4.1-mini"))


# ---------------------------------------------------------------------------
# Timing-differential evaluator
# ---------------------------------------------------------------------------


def _timing_evidence(
    attack: float, baselines: list[float], injected: float | None
) -> LiveProbeEvidence:
    return LiveProbeEvidence(
        status_code=200,
        duration_seconds=attack,
        injected_delay_seconds=injected,
        additional=tuple(LiveProbeEvidence(status_code=200, duration_seconds=b) for b in baselines),
    )


def test_timing_evaluator_corroborates_induced_delay() -> None:
    evidence = _timing_evidence(5.0, [0.10, 0.11, 0.09, 0.12], injected=5.0)
    assert timing_differential_evaluator(evidence) == LIVE_CONFIRMED
    # The bound is max(K * sigma, 0.6 * injected): a delay under it does not count.
    weak = _timing_evidence(3.0, [0.10, 0.11, 0.09, 0.12], injected=5.0)
    assert timing_differential_evaluator(weak) == LIVE_REFUTED
    assert TIMING_MIN_SIGMA_MULTIPLIER == 3.0
    assert TIMING_INJECTED_DELAY_FRACTION == 0.6


def test_timing_evaluator_inconclusive_without_samples() -> None:
    assert timing_differential_evaluator(LiveProbeEvidence(status_code=200)) == LIVE_INCONCLUSIVE
    assert (
        timing_differential_evaluator(_timing_evidence(5.0, [0.1], injected=5.0))
        == LIVE_INCONCLUSIVE
    )
    assert (
        timing_differential_evaluator(_timing_evidence(5.0, [0.1, 0.1], injected=5.0))
        == LIVE_INCONCLUSIVE
    )


def test_timing_evaluator_registered_for_command_injection() -> None:
    from quarry_activities.verdict_evaluators import resolve_evaluator

    assert resolve_evaluator(VulnerabilityClass.COMMAND_INJECTION) is timing_differential_evaluator


# ---------------------------------------------------------------------------
# R1 — cross-class free-corroboration spoof
# ---------------------------------------------------------------------------


def _stored_db(tmp_path: Path, *findings: CandidateFinding) -> str:
    """Create a scan DB and persist *findings* for the free-corroboration check."""
    from quarry.schemas import Scan, ScanProfile, ScanStatus, Target
    from quarry_persistence import QuarryRepository

    db = tmp_path / "q.db"
    repo = QuarryRepository(db)
    repo.create_scan(
        Scan(
            id="scan-1",
            workspace_id="local",
            target_id="tgt-1",
            requested_by="test",
            profile=ScanProfile(id="p", name="p", vuln_classes=[VulnerabilityClass.SQL_INJECTION]),
            status=ScanStatus.RUNNING,
            created_at=_NOW,
        ),
        Target(id="tgt-1", workspace_id="local", repo_path="/tmp/repo", created_at=_NOW),
    )
    for finding in findings:
        repo.save_candidate_finding(finding)
    return str(db)


def test_cross_class_component_echo_does_not_corroborate(tmp_path: Path) -> None:
    """R1: a grounded finding on the same component under a DIFFERENT class is
    NOT corroboration — the target hypothesis is class-specific, so a
    prompt-injected hunter echoing a grounded finding's ``affected_component``
    under another class harvests nothing."""
    from quarry_activities.validate import (
        _free_corroboration_step,  # type: ignore[reportPrivateUsage]
    )

    grounded = _finding(
        fid="g",
        vuln_class=VulnerabilityClass.SECRETS,
        grounded=True,
        affected="src/app.py",
        root_cause_key=None,
    )
    db = _stored_db(tmp_path, grounded)
    echo = _finding(
        fid="echo",
        vuln_class=VulnerabilityClass.SQL_INJECTION,
        grounded=False,
        model_id="gpt-4.1-mini",
        affected="src/app.py",
        root_cause_key=None,
    )
    assert _free_corroboration_step(db, echo) is None


def test_same_class_keyless_component_echo_still_corroborates(tmp_path: Path) -> None:
    """Positive control: the class check must not deny a genuine same-class,
    same-component match (both keyless) — that is a real free-tool promotion."""
    from quarry_activities.corroborator import CASCADE_STEP_FREE_TOOL
    from quarry_activities.validate import (
        _free_corroboration_step,  # type: ignore[reportPrivateUsage]
    )

    grounded = _finding(
        fid="g",
        vuln_class=VulnerabilityClass.SQL_INJECTION,
        grounded=True,
        affected="src/app.py",
        root_cause_key=None,
    )
    db = _stored_db(tmp_path, grounded)
    echo = _finding(
        fid="echo",
        vuln_class=VulnerabilityClass.SQL_INJECTION,
        grounded=False,
        model_id="gpt-4.1-mini",
        affected="src/app.py",
        root_cause_key=None,
    )
    assert _free_corroboration_step(db, echo) is CASCADE_STEP_FREE_TOOL


def test_exploitation_chain_finding_gets_canonical_root_cause_key() -> None:
    """R1: the exploitation site now sets ``root_cause_key`` so the cascade
    compares keys, never bare component equality."""
    from quarry.schemas import ExploitStep, HttpRequestSpec
    from quarry_workflows.exploitation_loop import ExploitChain, exploit_chain_to_candidate

    chain = ExploitChain(
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SSRF,
        proven=True,
        steps=[
            ExploitStep(
                order=0,
                intent="exploit",
                request_spec=HttpRequestSpec(method="GET", path="/fetch-local"),
                status_code=200,
                confirmed=True,
            )
        ],
    )
    finding = exploit_chain_to_candidate(
        chain,
        finding_id="f",
        title="t",
        hypothesis="h",
        created_by="exploit-loop",
        created_at=_NOW,
    )
    assert finding is not None
    assert finding.root_cause_key == "ssrf::/fetch-local"


# ---------------------------------------------------------------------------
# R2 — probe budget drained for a guaranteed-inconclusive evaluation
# ---------------------------------------------------------------------------


class _CountingCounter:
    """A budget counter that records how many times it was consulted."""

    def __init__(self, grants: bool = True) -> None:
        self.grants = grants
        self.takes = 0

    def take(self) -> bool:
        self.takes += 1
        return self.grants


def test_step4_unavailable_skips_without_spending_probe_unit() -> None:
    """R2: when no deterministic evaluator can run for a finding, step 4 is
    skipped and NO probe unit is consumed (previously the budget was drained for
    nothing)."""
    probe = _CountingCounter()
    model = _CountingCounter()
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        CascadeCounters(probe=probe, model=model),
        _evaluators(probe=None, debater=False),
    )
    assert outcome.cascade_step is CascadeStep.PAID_DEBATER
    assert CascadeStep.PROBE_UNAVAILABLE in outcome.skipped_steps
    assert probe.takes == 0
    assert model.takes == 1


def test_step4_runnable_probe_spends_exactly_one_unit() -> None:
    """The availability gate must not weaken a runnable probe: it still costs one
    unit and the debater is not reached."""
    probe = _CountingCounter()
    model = _CountingCounter()
    outcome = Corroborator().decide(
        _finding(grounded=False, model_id="gpt-4.1-mini"),
        0.6,
        CascadeCounters(probe=probe, model=model),
        _evaluators(probe=LIVE_CONFIRMED),
    )
    assert outcome.cascade_step is CascadeStep.PROBE_ORACLE
    assert probe.takes == 1
    assert model.takes == 0
