from quarry.schemas import VulnerabilityClass, local_scan_profile
from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER


def test_workflow_stage_order() -> None:
    assert COMPLETED_STAGE_ORDER["SNAPSHOT"] < COMPLETED_STAGE_ORDER["RECON"]
    assert COMPLETED_STAGE_ORDER["RECON"] < COMPLETED_STAGE_ORDER["HUNT"]
    assert COMPLETED_STAGE_ORDER["HUNT"] < COMPLETED_STAGE_ORDER["VALIDATION"]
    assert COMPLETED_STAGE_ORDER["VALIDATION"] < COMPLETED_STAGE_ORDER["REPORT"]


def test_local_scan_profile_includes_idor() -> None:
    profile = local_scan_profile(target_url="http://localhost:8000")

    assert VulnerabilityClass.IDOR in profile.vuln_classes
    assert profile.dynamic_validation_enabled is True
