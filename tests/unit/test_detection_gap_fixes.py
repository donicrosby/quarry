"""Unit tests: detection-gap fixes from the 2caa3abc post-mortem.

Four defect classes, one per section:

1. Presence-based rubric — hardcoded-secret claims have no untrusted-input
   path (the secret IS the source), so the source→sink-shaped validate
   rubric and the debater's mandatory trust_boundary check structurally
   reject every secrets claim. Fixed by v1.1.0 validate/refute templates
   with a presence-based clause, pinned by module constants.
2. Secrets sweep in the full-scan HUNT stage — RunScanWorkflow never ran the
   deterministic secrets plugin (only diff scans did), so key_name-carrying
   auto-promotable candidates could not exist in a full scan.
3. Coverage-ledger truth — tasks whose class produced candidates that were
   then rejected/needs_proof were labelled "no finding from hunt agent".
4. Accumulator hygiene — the needs_proof branch didn't sync the updated
   candidate back into the candidate_findings accumulator (TRACER then
   re-persisted the stale row, clobbering live_verdict metadata), and
   inconclusive-with-no-remaining-path findings were invisible.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FinalFinding,
    VulnerabilityClass,
    utc_now,
)

PROMPTS_ROOT = Path(__file__).resolve().parents[2] / "prompts"


# ── 1. Presence-based rubric templates ─────────────────────────────────────


def _render_validate_template(vuln_class: str) -> str:
    from quarry_prompts.registry import PromptRegistry

    registry = PromptRegistry(PROMPTS_ROOT)
    loaded = registry.load("validate", "validate", "1.1.0")
    return loaded.render(
        {
            "vuln_class": vuln_class,
            "file": "app.py",
            "line_start": 10,
            "line_end": 10,
            "description": "Hardcoded ADMIN_API_KEY assignment",
            "affected_code_snippet": 'ADMIN_API_KEY = "x"',
            "kb_context": "",
        }
    )


def _render_refute_template(vuln_class: str) -> str:
    from quarry_prompts.registry import PromptRegistry

    registry = PromptRegistry(PROMPTS_ROOT)
    loaded = registry.load("validate", "refute", "1.1.0")
    return loaded.render(
        {
            "vuln_class": vuln_class,
            "file": "app.py",
            "line_start": 10,
            "line_end": 10,
            "description": "Hardcoded ADMIN_API_KEY assignment",
            "affected_code_snippet": 'ADMIN_API_KEY = "x"',
        }
    )


def test_validate_template_1_1_0_exists_and_renders() -> None:
    text = _render_validate_template("secrets")
    assert "secrets" in text
    assert "app.py" in text


def test_validate_template_presence_based_clause_for_secrets() -> None:
    """The v1.1.0 reasoner rubric must not require a source→sink path for
    presence-based classes (the secret is the source)."""
    text = _render_validate_template("secrets").lower()
    assert "presence-based" in text
    assert "not applicable" in text or "not_applicable" in text


def test_validate_template_keeps_sink_shaped_path_for_flow_classes() -> None:
    """The source→sink requirement must remain the default for flow classes."""
    text = _render_validate_template("command_injection")
    assert "untrusted input" in text.lower()


def test_refute_template_1_1_0_exists_and_trust_boundary_na_for_secrets() -> None:
    """v1.1.0 debater checklist must let trust_boundary be not_applicable for
    presence-based claims instead of mandatory-failing them."""
    text = _render_refute_template("secrets")
    assert "presence-based" in text.lower()
    assert "not_applicable" in text


def test_validate_activity_pins_1_2_0() -> None:
    """v1.2.0 = 1.1.0 + the redaction-disclosure notice (run-5 self-own fix).

    The pin moves together for both templates; the 1.1.0 presence-based clause
    is preserved additively (see tests/unit/test_validate_redaction_grounding.py
    lineage anchors).
    """
    from quarry_activities.validate import (
        REFUTE_PROMPT_VERSION,
        VALIDATE_PROMPT_VERSION,
    )

    assert VALIDATE_PROMPT_VERSION == "1.2.0"
    assert REFUTE_PROMPT_VERSION == "1.2.0"


# ── 2. Secrets sweep in the full-scan HUNT stage ────────────────────────────


def _sample_secret_payload() -> list[dict[str, object]]:
    return [
        {
            "line_number": 12,
            "key_name": "ADMIN_API_KEY",
            "value": "super-secret-admin-key-please-rotate",
            "file_path": "app.py",
        }
    ]


def test_secret_candidates_from_activity_payload_builds_key_name_candidate() -> None:
    from quarry_workflows.run_scan import secret_candidates_from_activity_payload

    now = utc_now()
    candidates = secret_candidates_from_activity_payload(
        _sample_secret_payload(), scan_id="scan-1", created_at=now
    )
    assert len(candidates) == 1
    c = candidates[0]
    assert c.vuln_class is VulnerabilityClass.SECRETS
    assert c.scan_id == "scan-1"
    assert c.created_at == now
    # key_name metadata is what the deterministic gate keys on
    assert c.metadata.get("key_name") == "ADMIN_API_KEY"
    assert c.created_by == "secrets-scanner"
    assert c.source_refs[0].file_path == "app.py"
    assert c.source_refs[0].start_line == 12


def test_secret_candidates_from_activity_payload_rejects_non_list() -> None:
    from quarry_workflows.run_scan import secret_candidates_from_activity_payload

    with pytest.raises(TypeError):
        secret_candidates_from_activity_payload({"nope": 1}, scan_id="s", created_at=utc_now())


def test_secret_candidates_payload_roundtrip_via_plugin_activity() -> None:
    """The payload dicts the activity actually returns (dataclass asdict form)
    must convert; integration mirrors diff_scan's _secret_matches_from_activity."""
    from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets

    matches = scan_repo_for_secrets(
        Path(__file__).resolve().parents[2] / "examples" / "vulnerable-fastapi"
    )
    names = {m.key_name for m in matches}
    assert "ADMIN_API_KEY" in names  # fixture app has this hardcoded key

    from quarry_workflows.run_scan import secret_candidates_from_activity_payload

    payload = [
        {
            "line_number": m.line_number,
            "key_name": m.key_name,
            "value": m.value,
            "file_path": m.file_path,
        }
        for m in matches
    ]
    candidates = secret_candidates_from_activity_payload(
        payload, scan_id="scan-rt", created_at=utc_now()
    )
    assert any(c.metadata.get("key_name") == "ADMIN_API_KEY" for c in candidates)


# ── 3. Coverage-ledger truth ────────────────────────────────────────────────


def _task(vuln_class: VulnerabilityClass, task_id: str) -> object:
    from quarry.schemas import AgentTask

    return AgentTask(
        id=task_id,
        scan_id="s",
        role="hunt",
        task_name=f"hunt-{vuln_class.value}",
        status="pending",
        vuln_class=vuln_class,
        scope="app.py",
        created_at=utc_now(),
    )


def _candidate(vuln_class: VulnerabilityClass, scan_id: str) -> CandidateFinding:
    return CandidateFinding(
        id=f"cand-{vuln_class.value}",
        scan_id=scan_id,
        workspace_id="local",
        vuln_class=vuln_class,
        title=f"candidate {vuln_class.value}",
        hypothesis="h",
        root_cause_key="rk",
        affected_component="app.py",
        source_refs=[],
        evidence_path=[],
        confidence=Confidence.MEDIUM,
        created_by="hunt-agent",
        created_at=utc_now(),
    )


def test_skipped_tasks_distinguish_no_finding_from_rejected() -> None:
    from quarry_workflows.run_scan import skipped_task_records

    tasks = [_task(VulnerabilityClass.SECRETS, "t1"), _task(VulnerabilityClass.SSRF, "t2")]
    candidates = [_candidate(VulnerabilityClass.SECRETS, "s")]
    finals: list[FinalFinding] = []

    records = skipped_task_records(tasks, candidates, finals)
    by_class = {r["vuln_class"]: r for r in records}
    # SECRETS: hunt produced a candidate, promotion failed → NOT "no finding"
    assert "candidate not promoted" in by_class["secrets"]["reason"]
    # SSRF: hunt produced nothing → the classic reason stands
    assert by_class["ssrf"]["reason"] == "no finding from hunt agent"


def test_skipped_tasks_empty_when_all_promoted() -> None:
    from quarry_workflows.run_scan import skipped_task_records

    tasks = [_task(VulnerabilityClass.IDOR, "t1")]
    candidates = [_candidate(VulnerabilityClass.IDOR, "s")]
    finals: list[FinalFinding] = []  # presence asserted via _promoted_classes
    records = skipped_task_records(
        tasks, candidates, finals, _promoted_classes={VulnerabilityClass.IDOR}
    )
    assert records == []


# ── 4. Accumulator hygiene ──────────────────────────────────────────────────


def test_sync_candidate_accumulator_updates_matching_row_in_place() -> None:
    from quarry_workflows.run_scan import sync_candidate_accumulator

    scan_id = "s"
    base = _candidate(VulnerabilityClass.SSRF, scan_id)
    metadata = {**base.metadata, "live_verdict": "inconclusive"}
    updated = base.model_copy(update={"metadata": metadata})
    accumulator = [base]
    sync_candidate_accumulator(accumulator, updated)
    assert accumulator[0].metadata.get("live_verdict") == "inconclusive"


def test_sync_candidate_accumulator_appends_when_missing() -> None:
    from quarry_workflows.run_scan import sync_candidate_accumulator

    scan_id = "s"
    updated = _candidate(VulnerabilityClass.SSRF, scan_id)
    accumulator: list[CandidateFinding] = []
    sync_candidate_accumulator(accumulator, updated)
    assert accumulator == [updated]


def test_promotion_exhaustion_reason_names_the_dead_end() -> None:
    from quarry_workflows.run_scan import promotion_exhaustion_reason

    # Dynamic ran, verdict inconclusive, no prove stage → visible dead end.
    reason = promotion_exhaustion_reason(
        dynamic_active=True, live_verdict="inconclusive", proof_enabled=False
    )
    assert reason is not None
    assert "inconclusive" in reason
    assert "proof" in reason
    # Corroborated-but-unpromoted still has the PROVE path → no dead end.
    assert (
        promotion_exhaustion_reason(
            dynamic_active=True, live_verdict="corroborated", proof_enabled=True
        )
        is None
    )
    # No dynamic track and no prove → nothing was ever going to promote it.
    assert (
        promotion_exhaustion_reason(dynamic_active=False, live_verdict="", proof_enabled=False)
        == "no dynamic validation and proof disabled for this scan"
    )
