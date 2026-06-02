"""Tests for finding sinks and idempotency."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import (
    FinalFinding,
    IntegrationStatus,
    Severity,
    VulnerabilityClass,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_integrations.base import DeliveryContext, FindingSink, build_idempotency_key
from quarry_integrations.sinks import (
    FileSink,
    JiraDryRunSink,
    NoopSink,
    SlackDryRunSink,
    default_sinks,
)


def _finding() -> FinalFinding:
    return FinalFinding(
        id="f-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="secrets:app.py:ADMIN_API_KEY",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.HIGH,
        title="Hardcoded secret: ADMIN_API_KEY",
        summary="A hardcoded secret was found.",
        validation_result_id="v-1",
        created_at=datetime.now(UTC),
    )


def _ctx(
    tmp_path: Path,
    *,
    dry_run: bool = True,
    already_delivered: set[str] | None = None,
) -> DeliveryContext:
    keys: set[str] = already_delivered if already_delivered is not None else set()
    return DeliveryContext(
        scan_id="scan-1",
        workspace_id="local",
        dry_run=dry_run,
        artifact_store=LocalArtifactStore(tmp_path),
        already_delivered=keys,
    )


def _read_artifact(uri: str) -> dict[str, Any]:
    return json.loads(Path(uri.removeprefix("file://")).read_text(encoding="utf-8"))


def test_noop_sink_delivers_without_payload(tmp_path: Path) -> None:
    run = NoopSink().deliver(_finding(), _ctx(tmp_path))
    assert run.status is IntegrationStatus.DELIVERED
    assert run.output_ref is None
    assert run.sink == "noop"


def test_file_sink_writes_finding_payload(tmp_path: Path) -> None:
    run = FileSink().deliver(_finding(), _ctx(tmp_path))
    assert run.status is IntegrationStatus.DELIVERED
    assert run.output_ref is not None
    payload = _read_artifact(run.output_ref.uri)
    assert payload["vuln_class"] == "secrets"


def test_jira_dry_run_writes_ticket_payload(tmp_path: Path) -> None:
    run = JiraDryRunSink().deliver(_finding(), _ctx(tmp_path))
    assert run.status is IntegrationStatus.DRY_RUN
    assert run.dry_run is True
    assert run.output_ref is not None
    ticket = _read_artifact(run.output_ref.uri)
    assert ticket["title"] == "Hardcoded secret: ADMIN_API_KEY"
    assert "quarry" in ticket["labels"]
    assert ticket["finding_fingerprint"] == "secrets:app.py:ADMIN_API_KEY"


def test_slack_dry_run_writes_message_payload(tmp_path: Path) -> None:
    run = SlackDryRunSink().deliver(_finding(), _ctx(tmp_path))
    assert run.status is IntegrationStatus.DRY_RUN
    assert run.output_ref is not None
    message = _read_artifact(run.output_ref.uri)
    assert message["scan_id"] == "scan-1"


def test_repeated_delivery_is_skipped_no_duplicate(tmp_path: Path) -> None:
    finding = _finding()
    key = build_idempotency_key("scan-1", "jira_dry_run", finding.fingerprint)
    ctx = _ctx(tmp_path, already_delivered={key})

    run = JiraDryRunSink().deliver(finding, ctx)

    assert run.status is IntegrationStatus.SKIPPED
    assert run.output_ref is None  # no payload written on repeat
    assert not list((tmp_path / "integrations" / "jira").glob("*.json"))


def test_default_sinks_are_the_cut_line_three() -> None:
    names = [sink.name for sink in default_sinks()]
    assert names == ["file", "jira_dry_run", "slack_dry_run"]


@pytest.mark.parametrize("sink", default_sinks())
def test_each_default_sink_is_idempotent(sink: FindingSink, tmp_path: Path) -> None:
    finding = _finding()
    first = sink.deliver(finding, _ctx(tmp_path))
    second = sink.deliver(finding, _ctx(tmp_path, already_delivered={first.idempotency_key}))
    assert first.status in (IntegrationStatus.DELIVERED, IntegrationStatus.DRY_RUN)
    assert second.status is IntegrationStatus.SKIPPED
