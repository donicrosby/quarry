"""Integration tests for the PROVE + TRACER stage wiring in run_scan.py.

These tests verify the pure-function helpers that the workflow uses when
dispatching prove-finding / sandbox-exec / tracer-finding activities.

Written RED first — these fail until:
- ``build_prove_dispatch_inputs`` is added to run_scan.py
- The PROVE stage block sets current_stage = "PROVE" and persists the stage
- The TRACER stage block sets current_stage = "TRACER" and persists the stage

All tests are pure-function — no Temporal runtime required.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    Severity,
    VulnerabilityClass,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)


def _make_candidate(  # pyright: ignore[reportUnusedFunction]
    id: str = "cf-wiring-1",
    scan_id: str = "scan-wiring",
    status: FindingStatus = FindingStatus.NEEDS_PROOF,
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id=scan_id,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Command injection",
        hypothesis="Unsanitized input to subprocess",
        affected_component="src/runner.py",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        status=status,
        created_by="hunter",
        created_at=_NOW,
    )


def _make_exec_spec_dict() -> dict[str, object]:
    return {
        "command": ["python", "-c", "import subprocess; subprocess.run(['id'])"],
        "env": {},
        "timeout_seconds": 30,
        "work_dir": "/repo",
    }


def _make_http_spec_dict() -> dict[str, object]:
    return {
        "method": "GET",
        "path": "/users/1",
        "headers": {},
        "body": None,
    }


# ---------------------------------------------------------------------------
# build_prove_dispatch_inputs helper
# ---------------------------------------------------------------------------


class TestBuildProveDispatchInputs:
    def test_function_importable(self) -> None:
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        assert callable(build_prove_dispatch_inputs)

    def test_empty_prove_response_returns_empty_lists(self) -> None:
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        exec_inputs, http_inputs = build_prove_dispatch_inputs(
            proposed_exec_specs=[],
            proposed_http_specs=[],
            scan_id="s-1",
            finding_id="cf-1",
            artifact_root="/tmp/artifacts",
            target_endpoint_json=None,
            allowed_hosts=(),
        )
        assert exec_inputs == []
        assert http_inputs == []

    def test_exec_spec_produces_sandbox_exec_input(self) -> None:
        from quarry_activities.inputs import SandboxExecActivityInput
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        exec_inputs, _ = build_prove_dispatch_inputs(
            proposed_exec_specs=[_make_exec_spec_dict()],
            proposed_http_specs=[],
            scan_id="s-exec",
            finding_id="cf-exec",
            artifact_root="/tmp/art",
            target_endpoint_json=None,
            allowed_hosts=(),
        )
        assert len(exec_inputs) == 1
        assert isinstance(exec_inputs[0], SandboxExecActivityInput)

    def test_exec_input_scan_id_linked(self) -> None:
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        exec_inputs, _ = build_prove_dispatch_inputs(
            proposed_exec_specs=[_make_exec_spec_dict()],
            proposed_http_specs=[],
            scan_id="scan-link-check",
            finding_id="cf-link",
            artifact_root="/tmp/art",
            target_endpoint_json=None,
            allowed_hosts=(),
        )
        assert exec_inputs[0].scan_id == "scan-link-check"
        assert exec_inputs[0].candidate_finding_id == "cf-link"

    def test_exec_input_no_target_endpoint_cli_prove(self) -> None:
        """CLI prove has no target endpoint; target_endpoint_json should be None."""
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        exec_inputs, _ = build_prove_dispatch_inputs(
            proposed_exec_specs=[_make_exec_spec_dict()],
            proposed_http_specs=[],
            scan_id="s-cli",
            finding_id="cf-cli",
            artifact_root="/tmp/art",
            target_endpoint_json=None,
            allowed_hosts=(),
        )
        assert exec_inputs[0].target_endpoint_json is None

    def test_http_spec_produces_http_request_input(self) -> None:
        from quarry_activities.inputs import HttpRequestActivityInput
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        target_ep = json.dumps({"host": "localhost", "port": 8000, "scheme": "http"})
        _, http_inputs = build_prove_dispatch_inputs(
            proposed_exec_specs=[],
            proposed_http_specs=[_make_http_spec_dict()],
            scan_id="s-http",
            finding_id="cf-http",
            artifact_root="/tmp/art",
            target_endpoint_json=target_ep,
            allowed_hosts=("localhost",),
        )
        assert len(http_inputs) == 1
        assert isinstance(http_inputs[0], HttpRequestActivityInput)

    def test_http_input_allowed_hosts_propagated(self) -> None:
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        target_ep = json.dumps({"host": "app.test", "port": 443, "scheme": "https"})
        _, http_inputs = build_prove_dispatch_inputs(
            proposed_exec_specs=[],
            proposed_http_specs=[_make_http_spec_dict()],
            scan_id="s-hosts",
            finding_id="cf-hosts",
            artifact_root="/tmp/art",
            target_endpoint_json=target_ep,
            allowed_hosts=("app.test", "127.0.0.1"),
        )
        assert "app.test" in http_inputs[0].allowed_hosts

    def test_mixed_specs_produce_both_input_types(self) -> None:
        from quarry_activities.inputs import HttpRequestActivityInput, SandboxExecActivityInput
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        target_ep = json.dumps({"host": "localhost", "port": 8080, "scheme": "http"})
        exec_inputs, http_inputs = build_prove_dispatch_inputs(
            proposed_exec_specs=[_make_exec_spec_dict(), _make_exec_spec_dict()],
            proposed_http_specs=[_make_http_spec_dict()],
            scan_id="s-mixed",
            finding_id="cf-mixed",
            artifact_root="/tmp/art",
            target_endpoint_json=target_ep,
            allowed_hosts=("localhost",),
        )
        assert len(exec_inputs) == 2
        assert all(isinstance(i, SandboxExecActivityInput) for i in exec_inputs)
        assert len(http_inputs) == 1
        assert isinstance(http_inputs[0], HttpRequestActivityInput)

    def test_http_specs_dropped_when_no_target_endpoint(self) -> None:
        """HTTP specs cannot be dispatched without a target endpoint — must be skipped."""
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        _, http_inputs = build_prove_dispatch_inputs(
            proposed_exec_specs=[],
            proposed_http_specs=[_make_http_spec_dict()],
            scan_id="s-no-ep",
            finding_id="cf-no-ep",
            artifact_root="/tmp/art",
            target_endpoint_json=None,  # no live target
            allowed_hosts=(),
        )
        assert http_inputs == [], "HTTP inputs must be empty when no target endpoint is set"

    def test_spec_json_is_serialized_string(self) -> None:
        from quarry_workflows.run_scan import build_prove_dispatch_inputs

        exec_inputs, _ = build_prove_dispatch_inputs(
            proposed_exec_specs=[_make_exec_spec_dict()],
            proposed_http_specs=[],
            scan_id="s-json",
            finding_id="cf-json",
            artifact_root="/tmp/art",
            target_endpoint_json=None,
            allowed_hosts=(),
        )
        # spec_json must be a JSON string (Temporal boundary requirement)
        assert isinstance(exec_inputs[0].spec_json, str)
        json.loads(exec_inputs[0].spec_json)  # must be valid JSON


# ---------------------------------------------------------------------------
# Stage order — PROVE and TRACER after DEDUP, before COVERAGE
# ---------------------------------------------------------------------------


class TestProveTracerStageOrder:
    def test_prove_after_dedup(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["PROVE"] > COMPLETED_STAGE_ORDER["DEDUP"]

    def test_tracer_after_prove(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["TRACER"] == COMPLETED_STAGE_ORDER["PROVE"] + 1

    def test_coverage_after_tracer(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["COVERAGE"] > COMPLETED_STAGE_ORDER["TRACER"]
