"""Backward-compatibility re-export shim for IDOR validation functions.

This module exists solely for imports that expect `validate_idor_candidate` and
`validate_idor_candidate_activity` to live in `quarry_activities.idor_validation`.
The actual implementations are in `quarry_activities.dynamic_validation`.

New code should import directly from `quarry_activities.dynamic_validation`.
"""

from quarry_activities.dynamic_validation import (
    validate_idor_candidate,
    validate_idor_candidate_activity,
)

__all__ = ["validate_idor_candidate", "validate_idor_candidate_activity"]
