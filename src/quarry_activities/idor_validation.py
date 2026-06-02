"""IDOR dynamic validation activity.

This activity performs runtime validation of IDOR (Insecure Direct Object Reference)
vulnerabilities by attempting to access another user's resources.

Validation logic:
- If target_url is None → inconclusive (cannot test without target)
- If target is unreachable → inconclusive (network error, retry later)
- If User A can access User B's data → validated (IDOR confirmed)
- If User A cannot access User B's data → rejected (access control working)

HTTP artifacts (request/response) are captured and stored with redacted credentials.
"""

from __future__ import annotations

from temporalio import activity

from quarry.schemas import CandidateFinding, ValidationResult, utc_now
from quarry_activities.inputs import ValidateIDORInput


@activity.defn(name="validate-idor-candidate")
def validate_idor_candidate(
    input_data: ValidateIDORInput | dict[str, str | None],
    artifact_store: object | None = None,
) -> ValidationResult:
    """Validate an IDOR candidate by attempting cross-user access.

    This activity:
    1. Authenticates as User A
    2. Attempts to access User B's resource (e.g., /api/users/2)
    3. Captures HTTP request/response artifacts with redacted credentials
    4. Returns ValidationResult with verdict based on access success

    Args:
        input_data: ValidateIDORInput with finding JSON and target credentials
        artifact_store: Optional artifact store for capturing HTTP artifacts

    Returns:
        ValidationResult with verdict: validated/rejected/inconclusive

    Raises:
        TypeError: If input_data cannot be converted to ValidateIDORInput
    """
    # Convert dict to ValidateIDORInput if needed
    if isinstance(input_data, dict):
        finding_json = input_data.get("finding_json")
        if not isinstance(finding_json, str):
            msg = "finding_json must be a string"
            raise TypeError(msg)
        input_data = ValidateIDORInput(
            finding_json=finding_json,
            target_url=input_data.get("target_url"),
            user_a_username=input_data.get("user_a_username"),
            user_a_password=input_data.get("user_a_password"),
            user_b_username=input_data.get("user_b_username"),
            user_b_password=input_data.get("user_b_password"),
            artifact_store_path=input_data.get("artifact_store_path"),
        )

    # Extract finding from JSON
    finding = CandidateFinding.model_validate_json(input_data.finding_json)

    # Check if target_url is provided
    if input_data.target_url is None:
        return ValidationResult(
            id=f"{finding.id}-validation",
            candidate_finding_id=finding.id,
            scan_id=finding.scan_id,
            verdict="inconclusive",
            reasons=["No target_url provided - cannot perform dynamic validation"],
            checks_run=["target_url_check"],
            evidence_refs=[],
            cross_vendor=False,
            created_at=utc_now(),
        )

    # TODO: Implement actual IDOR validation logic
    # - Authenticate as User A
    # - Attempt to access User B's resource
    # - Capture HTTP artifacts
    # - Return validated/rejected based on response

    # Placeholder - will be implemented in Task 5 / Wave 3
    msg = "IDOR validation not yet implemented"
    raise NotImplementedError(msg)
