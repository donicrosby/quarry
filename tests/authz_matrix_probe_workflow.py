"""Minimal workflow that drives the ``authz-matrix`` activity.

Kept in its own module (not the test module) so Temporal's workflow sandbox can
reimport it without pulling in the test's ``http.server`` stub — the sandbox
restricts ``BaseHTTPRequestHandler`` and would fail workflow validation.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow

from quarry_activities.authz_matrix import AuthzMatrixActivityInput, AuthzMatrixResult


@workflow.defn
class AuthzMatrixProbeWorkflow:
    @workflow.run
    async def run(self, activity_input: AuthzMatrixActivityInput) -> AuthzMatrixResult:
        return await workflow.execute_activity(
            "authz-matrix",
            activity_input,
            start_to_close_timeout=timedelta(seconds=30),
        )
