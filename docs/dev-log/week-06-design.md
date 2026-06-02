# Week 6 Design: IDOR Validation Protocol

## Overview

This document specifies the validation protocol for Insecure Direct Object Reference (IDOR) vulnerabilities in Quarry. The design extends the existing deterministic validation pattern from `src/quarry_activities/validation.py` to handle HTTP-based IDOR proofs.

## Target Application

The vulnerable FastAPI app (`examples/vulnerable-fastapi/app.py`) exposes an IDOR vulnerability:

```python
@app.get("/users/{user_id}")
def read_user(user_id: str) -> dict[str, str]:
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Unknown user")
    return user
```

**Vulnerability**: No authorization checks — any authenticated (or unauthenticated) user can access any other user's data by manipulating the `user_id` parameter.

## Test User Credentials

| User | Username | Password | User ID |
|------|----------|----------|---------|
| User A | `user-a` | `pass-a` | `1` |
| User B | `user-b` | `pass-b` | `2` |

## Validation Protocol

### Request Sequence

The IDOR validation follows a three-request sequence to prove unauthorized access:

1. **Baseline Request** (optional, for sanity check)
   - `GET /users/1` with User A credentials
   - Expected: Returns User A's data (`{"id": "1", "name": "Ada", ...}`)
   - Purpose: Confirms auth mechanism works

2. **IDOR Attack Request** (primary proof)
   - `GET /users/2` with User A credentials
   - Expected: Returns User B's data (`{"id": "2", "name": "Grace", ...}`)
   - **This proves IDOR**: User A should not access User B's data

3. **Cross-Check Request** (optional, strengthens proof)
   - `GET /users/1` with User B credentials
   - Expected: Returns User A's data
   - Purpose: Confirms bidirectional vulnerability

### Comparison Logic

The validation verdict is determined by:

```
IF status_code == 200 
   AND response_body contains "id": "2" (target user ID)
   AND response_body contains User B's unique data (name, email)
THEN verdict = "validated"
ELSE verdict = "rejected"
```

**Validated Response Example**:
```json
{
  "id": "2",
  "name": "Grace",
  "email": "grace@example.test"
}
```

### Auth Mechanism

The current vulnerable app has **no authentication** — this is intentional for initial development. The validation protocol supports two modes:

#### Mode 1: No Auth (Current)
- Requests sent without credentials
- Any user ID is accessible
- Proves the simplest IDOR case

#### Mode 2: Basic Auth (Future Extension)
- `Authorization: Basic base64(username:password)`
- User A credentials: `Authorization: Basic dXNlci1hOnBhc3MtYQ==`
- User B credentials: `Authorization: Basic dXNlci1iOnBhc3MtYg==`

The validation activity should accept an optional `auth_config` parameter specifying:
- `auth_type`: `"none" | "basic" | "bearer"`
- `credentials`: dict with `username`, `password`, or `token`

## Static-Only Fallback (target_url is None)

When `target_url` is `None`, the validation activity operates in **static-only mode**:

```python
if target_url is None:
    # Cannot perform HTTP validation
    # Return inconclusive — finding remains candidate
    return ValidationResult(
        verdict="inconclusive",
        reasons=["Target URL not provided — HTTP validation skipped"],
        checks_run=["static_analysis_only"],
        cross_vendor=False,
    )
```

**Behavior**:
- No HTTP requests are made
- Finding status remains `FindingStatus.CANDIDATE` (not rejected)
- Validation result marked as `inconclusive` (not `validated` or `rejected`)
- Report notes that dynamic validation was skipped

This matches the pattern where static analysis identifies potential IDOR (e.g., route pattern `/users/{user_id}` with no auth decorator), but dynamic proof requires a running target.

## Activity Input Schema

Following the pattern from `src/quarry_activities/inputs.py`, the IDOR validation input uses Pydantic with `ConfigDict(frozen=True)`:

```python
class ValidateIdorInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    finding_json: str  # CandidateFinding as JSON
    target_url: str | None  # None = static-only mode
    attack_route: str  # e.g., "/users/{user_id}"
    auth_config_json: str | None  # Optional auth configuration
    test_user_a_json: str  # {"username": "user-a", "password": "pass-a", "user_id": "1"}
    test_user_b_json: str  # {"username": "user-b", "password": "pass-b", "user_id": "2"}
```

All fields are `str` at the Temporal boundary (no `Path`, no nested objects).

## ValidationResult Mapping

The validation result maps to the existing `ValidationResult` schema from `src/quarry/schemas.py`:

```python
ValidationResult(
    id=f"{candidate.id}-validation",
    candidate_finding_id=candidate.id,
    scan_id=scan_id,
    verdict="validated" | "rejected" | "inconclusive",
    reasons=[...],  # List of human-readable reasons
    checks_run=[...],  # List of checks performed
    evidence_refs=[...],  # Optional: HTTP request/response artifacts
    cross_vendor=False,
    created_at=utc_now(),
)
```

**Verdict Options**:
- `validated`: HTTP request returned 200 with target user's data
- `rejected`: HTTP request returned 401/403, or response did not contain target data
- `inconclusive`: `target_url` is `None`, or network error, or timeout

## Integration with Existing Validation Pattern

The IDOR validation follows the same structure as `validate_secret_candidate` in `src/quarry_activities/validation.py`:

1. **Input**: Pydantic model with JSON-serialized nested objects
2. **Processing**: Deterministic checks (no LLM)
3. **Output**: `SecretValidationResult`-style dataclass with `verdict`, `reasons`, `checks_run`
4. **Mapping**: Convert to canonical `ValidationResult` schema via helper function

**Key Difference**: IDOR validation requires HTTP client (httpx) for dynamic requests, whereas secret validation is purely static regex/allowlist checks.

## Evidence Artifacts

When validation runs, the following artifacts should be captured:

- `http_request`: The exact HTTP request sent (method, URL, headers, body)
- `http_response`: The response (status, headers, body)
- `validation_log`: Step-by-step validation reasoning

These are stored as `ArtifactRef` entries in `ValidationResult.evidence_refs`.

## References

- Existing validation: `src/quarry_activities/validation.py:validate_secret_candidate()`
- Input patterns: `src/quarry_activities/inputs.py:ValidateCandidateInput`
- Schema: `src/quarry/schemas.py:ValidationResult`
- Target route: `examples/vulnerable-fastapi/app.py:read_user()`

## Next Steps

1. Implement `validate_idor_candidate()` activity in `src/quarry_activities/validation.py`
2. Add `ValidateIdorInput` to `src/quarry_activities/inputs.py`
3. Update workflow to call IDOR validation when `vuln_class == "idor"`
4. Add test cases for validated/rejected/inconclusive scenarios
