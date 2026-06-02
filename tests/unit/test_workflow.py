from quarry.schemas import VulnerabilityClass, local_scan_profile
from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER


def test_workflow_has_idor_stage() -> None:
    assert COMPLETED_STAGE_ORDER["ATTACK_SURFACE"] < COMPLETED_STAGE_ORDER["SECRETS_SCAN"]
    assert COMPLETED_STAGE_ORDER["SECRETS_SCAN"] < COMPLETED_STAGE_ORDER["IDOR_SCAN"]
    assert COMPLETED_STAGE_ORDER["IDOR_SCAN"] < COMPLETED_STAGE_ORDER["REPORT"]


def test_local_scan_profile_includes_idor() -> None:
    profile = local_scan_profile(target_url="http://localhost:8000")

    assert VulnerabilityClass.IDOR in profile.vuln_classes
    assert profile.dynamic_validation_enabled is True
