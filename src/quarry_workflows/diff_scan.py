"""Commit-to-commit diff scan workflow."""

import json
from datetime import timedelta
from typing import Any, cast

from pydantic import BaseModel, ConfigDict
from temporalio import workflow
from temporalio.common import RetryPolicy

from quarry.fingerprints import compute_fingerprint
from quarry.schemas import (
    ArtifactRef,
    CandidateFinding,
    ChangedFile,
    Confidence,
    FinalFinding,
    GitDiff,
    ImpactedCodeRegion,
    Report,
    Scan,
    ScanStatus,
    Severity,
    SourceRef,
    Target,
    VulnerabilityClass,
    WorkflowEvent,
    local_scan_profile,
)
from quarry_activities.diff import git_diff_commits
from quarry_activities.inputs import (
    GitDiffInput,
    MapRegionsInput,
    PersistScanStateInput,
    RenderReportInput,
    RenderReportOutput,
    RunDiffScanInput,
    ScanSecretsInput,
    ValidateCandidateInput,
)
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.validation import SecretValidationResult
from quarry_plugins.vuln_classes.secrets import SecretMatch, scan_repo_for_secrets

ACTIVITY_RETRY_POLICY = RetryPolicy(maximum_attempts=1)


class RunDiffScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    status: str
    changed_files_count: int = 0
    regions_count: int = 0
    findings_count: int = 0
    report_path: str = ""


@workflow.defn(name="RunDiffScanWorkflow")
class RunDiffScanWorkflow:
    def __init__(self) -> None:
        self._current_stage: str = "INIT"

    @workflow.run
    async def run(self, input: RunDiffScanInput) -> RunDiffScanResult:
        created_at = workflow.now()
        target = Target(
            id=str(workflow.uuid4()),
            workspace_id="local",
            repo_path=input.repo_path,
            target_url=input.target_url or None,
            target_kind="local_repo" if input.target_url == "" else "local_web_app",
            allowed_hosts=["localhost", "127.0.0.1"] if input.target_url else [],
            created_at=created_at,
        )
        scan = Scan(
            id=input.scan_id,
            workspace_id="local",
            target_id=target.id,
            requested_by="local-user",
            profile=local_scan_profile(),
            status=ScanStatus.CREATED,
            created_at=created_at,
            metadata={
                "repo_path": input.repo_path,
                "base_commit": input.base_commit,
                "head_commit": input.head_commit,
                "scan_kind": "diff",
            },
        )
        report_path = _join_path(input.output_dir, "reports", f"{input.scan_id}.md")

        await _persist_scan_state(
            input.db_path,
            "create_scan_if_missing",
            {"scan": _model_json_dict(scan), "target": _model_json_dict(target)},
        )
        started_at = workflow.now()
        await _persist_scan_state(
            input.db_path,
            "update_scan_status",
            {
                "scan_id": scan.id,
                "status": ScanStatus.RUNNING.value,
                "started_at": started_at.isoformat(),
                "completed_at": None,
                "report_path": None,
            },
        )
        await _append_workflow_event(
            input.db_path,
            scan.id,
            "diff_scan.started",
            {
                "repo_path": input.repo_path,
                "base_commit": input.base_commit,
                "head_commit": input.head_commit,
            },
        )

        self._current_stage = "GIT_DIFF"
        diff_payload = await workflow.execute_activity(
            git_diff_commits,
            GitDiffInput(
                repo_path=input.repo_path,
                base_commit=input.base_commit,
                head_commit=input.head_commit,
                scan_id=scan.id,
                workspace_id="local",
            ),
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        git_diff = _git_diff_from_activity(diff_payload)
        tool_invocation = _tool_invocation_from_activity(diff_payload)
        if tool_invocation is not None:
            await _persist_scan_state(
                input.db_path,
                "save_tool_invocation",
                {"invocation": tool_invocation},
            )
        await _append_workflow_event(
            input.db_path,
            scan.id,
            "diff_scan.diff_mapped",
            {"changed_files_count": str(len(git_diff.changed_files))},
        )

        self._current_stage = "MAP_REGIONS"
        regions_payload = await workflow.execute_activity(
            map_impacted_regions,
            MapRegionsInput(changed_files=tuple(git_diff.changed_files)),
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        impacted_regions = _regions_from_activity(regions_payload)
        await _append_workflow_event(
            input.db_path,
            scan.id,
            "diff_scan.regions_mapped",
            {"regions_count": str(len(impacted_regions))},
        )

        self._current_stage = "SCAN_REGIONS"
        region_files = tuple(sorted({region.file_path for region in impacted_regions}))
        secret_payload = await workflow.execute_activity(
            scan_repo_for_secrets,
            ScanSecretsInput(repo_root=input.repo_path, file_paths=region_files),
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        secret_matches = _secret_matches_from_activity(secret_payload)
        diff_scoped_matches = _filter_matches_to_regions(secret_matches, impacted_regions)
        candidate_findings = [
            _candidate_from_secret_match(match, scan_id=scan.id) for match in diff_scoped_matches
        ]
        for candidate in candidate_findings:
            await _persist_scan_state(
                input.db_path,
                "save_candidate_finding",
                {"finding": _model_json_dict(candidate)},
            )
            await _append_workflow_event(
                input.db_path,
                scan.id,
                "finding.candidate_created",
                {"finding_id": candidate.id},
            )

        self._current_stage = "VALIDATE"
        final_findings: list[FinalFinding] = []
        for candidate in candidate_findings:
            validation_payload = await workflow.execute_activity(
                "validate-secret-candidate",
                ValidateCandidateInput(finding_json=candidate.model_dump_json()),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            validation = _validation_result_from_activity(validation_payload)
            if validation.is_valid:
                final = _final_from_candidate(candidate)
                await _persist_scan_state(
                    input.db_path,
                    "save_final_finding",
                    {"finding": _model_json_dict(final)},
                )
                final_findings.append(final)
                await _append_workflow_event(
                    input.db_path,
                    scan.id,
                    "finding.validated",
                    {"finding_id": final.id},
                )
            else:
                await _append_workflow_event(
                    input.db_path,
                    scan.id,
                    "finding.rejected",
                    {"finding_id": candidate.id},
                )

        self._current_stage = "REPORT"
        reporting_scan = scan.model_copy(
            update={"status": ScanStatus.COMPLETED, "started_at": started_at}
        )
        rendered_report_payload = await workflow.execute_activity(
            "render-markdown-report",
            RenderReportInput(
                scan_json=reporting_scan.model_dump_json(),
                findings_json=_model_list_json(candidate_findings),
                snapshot_json=None,
                attack_surface_json=_model_list_json([]),
                final_findings_json=_model_list_json(final_findings),
                report_path=report_path,
            ),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        rendered_report = _render_report_output_from_activity(rendered_report_payload)
        report_ref = ArtifactRef.model_validate_json(rendered_report.report_ref_json)
        await _persist_scan_state(
            input.db_path,
            "save_artifact_ref",
            {"scan_id": scan.id, "artifact_ref": _model_json_dict(report_ref)},
        )
        report = Report(
            id=str(workflow.uuid4()),
            scan_id=scan.id,
            workspace_id="local",
            title="Quarry Diff Scan Report",
            summary=f"Diff scan found {len(final_findings)} validated finding(s) "
            f"and {len(candidate_findings)} candidate finding(s).",
            finding_ids=[finding.id for finding in final_findings],
            formats=["markdown"],
            artifact_refs=[report_ref],
            generated_at=workflow.now(),
        )
        await _persist_scan_state(
            input.db_path,
            "save_report",
            {"report": _model_json_dict(report), "report_path": rendered_report.report_path},
        )

        self._current_stage = "COMPLETED"
        await _persist_scan_state(
            input.db_path,
            "update_scan_status",
            {
                "scan_id": scan.id,
                "status": ScanStatus.COMPLETED.value,
                "started_at": None,
                "completed_at": workflow.now().isoformat(),
                "report_path": rendered_report.report_path,
            },
        )
        await _append_workflow_event(
            input.db_path,
            scan.id,
            "diff_scan.completed",
            {"report_path": rendered_report.report_path},
        )
        return RunDiffScanResult(
            scan_id=scan.id,
            status="completed",
            changed_files_count=len(git_diff.changed_files),
            regions_count=len(impacted_regions),
            findings_count=len(final_findings),
            report_path=rendered_report.report_path,
        )

    @workflow.query
    def current_stage(self) -> str:
        return self._current_stage

    @workflow.query
    def get_stage(self) -> str:
        return self._current_stage


async def _append_workflow_event(
    db_path: str,
    scan_id: str,
    event_type: str,
    payload: dict[str, str],
) -> None:
    await _persist_scan_state(
        db_path,
        "append_event",
        {
            "event": _model_json_dict(
                WorkflowEvent(
                    id=str(workflow.uuid4()),
                    scan_id=scan_id,
                    workspace_id="local",
                    event_type=event_type,
                    payload=payload,
                    created_at=workflow.now(),
                )
            )
        },
    )


async def _persist_scan_state(
    db_path: str,
    operation: str,
    payload: dict[str, Any],
) -> None:
    await workflow.execute_activity(
        "persist-scan-state",
        PersistScanStateInput(
            db_path=db_path,
            operation=operation,
            payload_json=json.dumps(payload, sort_keys=True),
        ),
        start_to_close_timeout=timedelta(minutes=1),
        retry_policy=ACTIVITY_RETRY_POLICY,
    )


def _candidate_from_secret_match(match: SecretMatch, *, scan_id: str) -> CandidateFinding:
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path=match.file_path,
        start_line=match.line_number,
        key_name=match.key_name,
        evidence_kind="hardcoded_assignment",
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title=f"Hardcoded secret: {match.key_name}",
        hypothesis=f"Variable '{match.key_name}' in {match.file_path}:{match.line_number} "
        f"contains a hardcoded value that may be a secret.",
        affected_component=match.file_path,
        source_refs=[
            SourceRef(
                file_path=match.file_path,
                start_line=match.line_number,
                end_line=match.line_number,
                symbol=match.key_name,
            )
        ],
        confidence=Confidence.MEDIUM,
        created_by="secrets-scanner",
        created_at=workflow.now(),
        metadata={
            "key_name": match.key_name,
            "value_length": len(match.value),
            "evidence_kind": "hardcoded_assignment",
            "scope": "diff",
        },
    )


def _final_from_candidate(candidate: CandidateFinding) -> FinalFinding:
    return FinalFinding(
        id=candidate.id,
        scan_id=candidate.scan_id,
        workspace_id="local",
        fingerprint=candidate.id,
        vuln_class=candidate.vuln_class,
        severity=Severity.HIGH,
        title=candidate.title,
        summary=candidate.hypothesis,
        affected_component=candidate.affected_component,
        source_refs=candidate.source_refs,
        validation_result_id=f"{candidate.id}-validation",
        remediation="Move the secret to an environment variable or secret manager.",
        created_at=workflow.now(),
    )


def _filter_matches_to_regions(
    matches: list[SecretMatch],
    regions: list[ImpactedCodeRegion],
) -> list[SecretMatch]:
    scoped_matches: list[SecretMatch] = []
    for match in matches:
        if any(_match_in_region(match, region) for region in regions):
            scoped_matches.append(match)
    return scoped_matches


def _match_in_region(match: SecretMatch, region: ImpactedCodeRegion) -> bool:
    return (
        match.file_path == region.file_path
        and region.start_line <= match.line_number <= region.end_line
    )


def _git_diff_from_activity(payload: object) -> GitDiff:
    if isinstance(payload, GitDiff):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        git_diff = values.get("git_diff", values)
        return GitDiff.model_validate(git_diff)
    msg = f"Unexpected git diff payload: {type(payload).__name__}"
    raise TypeError(msg)


def _tool_invocation_from_activity(payload: object) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    invocation = cast(dict[str, Any], payload).get("tool_invocation")
    if isinstance(invocation, dict):
        return cast(dict[str, Any], invocation)
    return None


def _regions_from_activity(payload: object) -> list[ImpactedCodeRegion]:
    values = _dict_payload(payload)
    regions = values.get("regions")
    if not isinstance(regions, list):
        msg = "regions must be a list"
        raise TypeError(msg)
    region_items = cast(list[object], regions)
    return [ImpactedCodeRegion.model_validate(region) for region in region_items]


def _secret_matches_from_activity(payload: object) -> list[SecretMatch]:
    if not isinstance(payload, list):
        msg = f"Unexpected secret match payload: {type(payload).__name__}"
        raise TypeError(msg)
    items = cast(list[object], payload)
    return [
        item if isinstance(item, SecretMatch) else _secret_match_from_dict(_dict_payload(item))
        for item in items
    ]


def _validation_result_from_activity(payload: object) -> SecretValidationResult:
    if isinstance(payload, SecretValidationResult):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return SecretValidationResult(
            verdict=_required_str(values, "verdict"),
            reasons=_required_str_list(values, "reasons"),
            checks_run=_required_str_list(values, "checks_run"),
        )
    msg = f"Unexpected validation payload: {type(payload).__name__}"
    raise TypeError(msg)


def _render_report_output_from_activity(payload: object) -> RenderReportOutput:
    if isinstance(payload, RenderReportOutput):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return RenderReportOutput(
            report_text=_required_str(values, "report_text"),
            report_path=_required_str(values, "report_path"),
            report_ref_json=_required_str(values, "report_ref_json"),
        )
    msg = f"Unexpected report payload: {type(payload).__name__}"
    raise TypeError(msg)


def _secret_match_from_dict(payload: dict[str, Any]) -> SecretMatch:
    return SecretMatch(
        line_number=_required_int(payload, "line_number"),
        key_name=_required_str(payload, "key_name"),
        value=_required_str(payload, "value"),
        file_path=_required_str(payload, "file_path"),
    )


def _dict_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        msg = f"Expected dict payload, got {type(payload).__name__}"
        raise TypeError(msg)
    return cast(dict[str, Any], payload)


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise TypeError(msg)
    return value


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        msg = f"{key} must be an integer"
        raise TypeError(msg)
    return value


def _required_str_list(payload: dict[str, Any], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list):
        msg = f"{key} must be a list of strings"
        raise TypeError(msg)
    items = cast(list[object], value)
    if not all(isinstance(item, str) for item in items):
        msg = f"{key} must be a list of strings"
        raise TypeError(msg)
    return [item for item in items if isinstance(item, str)]


def _model_json_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _model_list_json(items: list[CandidateFinding] | list[FinalFinding] | list[ChangedFile]) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)


def _join_path(root: str, *parts: str) -> str:
    return "/".join([root.rstrip("/"), *parts])
