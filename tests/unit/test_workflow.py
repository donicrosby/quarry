from quarry.schemas import VulnerabilityClass, local_scan_profile
from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER, RunScanInput, budget_decision


def test_budget_decision_no_cap_disables_gating() -> None:
    over, remaining = budget_decision(None, 5.0)
    assert over is False
    assert remaining is None


def test_budget_decision_under_cap() -> None:
    over, remaining = budget_decision(2.0, 0.5)
    assert over is False
    assert remaining == 1.5


def test_budget_decision_at_or_over_cap() -> None:
    over, remaining = budget_decision(1.0, 1.0)
    assert over is True
    assert remaining == 0.0
    over2, remaining2 = budget_decision(1.0, 1.5)
    assert over2 is True
    assert remaining2 == 0.0  # never negative


def test_run_scan_input_accepts_budget_and_retry_fields() -> None:
    inp = RunScanInput(repo_path="/tmp/repo", activity_max_attempts=4, budget_cap_usd=2.5)
    assert inp.activity_max_attempts == 4
    assert inp.budget_cap_usd == 2.5


def test_run_scan_input_retry_default_is_one() -> None:
    """Default preserves historical fail-fast behaviour for direct construction."""
    inp = RunScanInput(repo_path="/tmp/repo")
    assert inp.activity_max_attempts == 1
    assert inp.budget_cap_usd is None


def test_workflow_stage_order() -> None:
    assert COMPLETED_STAGE_ORDER["SNAPSHOT"] < COMPLETED_STAGE_ORDER["RECON"]
    assert COMPLETED_STAGE_ORDER["RECON"] < COMPLETED_STAGE_ORDER["HUNT"]
    assert COMPLETED_STAGE_ORDER["HUNT"] < COMPLETED_STAGE_ORDER["VALIDATION"]
    assert COMPLETED_STAGE_ORDER["VALIDATION"] < COMPLETED_STAGE_ORDER["REPORT"]


def test_local_scan_profile_includes_idor() -> None:
    profile = local_scan_profile(target_url="http://localhost:8000")

    assert VulnerabilityClass.IDOR in profile.vuln_classes
    # A bare target_url does NOT enable live validation — CLI flags are authoritative
    # (ADR-017 "Alternatives considered": "Make live validation always enabled when a
    # target URL is present" was explicitly rejected).
    assert profile.dynamic_validation_enabled is False


def test_local_scan_profile_dynamic_flag_is_authoritative() -> None:
    """Only the explicit flag enables live HTTP — not URL presence."""
    without_flag = local_scan_profile(target_url="http://localhost:8000")
    assert without_flag.dynamic_validation_enabled is False

    with_flag = local_scan_profile(
        target_url="http://localhost:8000",
        dynamic_validation_enabled=True,
    )
    assert with_flag.dynamic_validation_enabled is True

    no_url_but_flag = local_scan_profile(dynamic_validation_enabled=True)
    assert no_url_but_flag.dynamic_validation_enabled is True


def test_split_hunt_result_tolerates_dict_list_and_exceptions() -> None:
    """split_hunt_result must never raise — it underpins the tolerant hunt fan-out."""
    from quarry_workflows.run_scan import split_hunt_result

    # New dict contract: findings + coverage_gaps.
    f, g = split_hunt_result({"findings": [{"x": 1}], "coverage_gaps": [{"area": "config/"}]})
    assert f == [{"x": 1}] and g == [{"area": "config/"}]

    # Legacy/mock list contract: findings only.
    f, g = split_hunt_result([{"x": 2}])
    assert f == [{"x": 2}] and g == []

    # Exception result (return_exceptions=True): a failed hunter contributes nothing.
    f, g = split_hunt_result(TimeoutError("request timed out"))
    assert f == [] and g == []
