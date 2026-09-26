"""Serialization tests for integration schemas."""

from datetime import UTC, datetime

from quarry.schemas import (
    IntegrationConfig,
    IntegrationRun,
    IntegrationStatus,
    NotificationMessage,
    Severity,
    TicketCreationRequest,
)


def test_integration_run_round_trips() -> None:
    run = IntegrationRun(
        id="run-1",
        scan_id="scan-1",
        integration_config_id="cfg-1",
        integration_event_id="evt-1",
        idempotency_key="jira_dry_run:fp-1",
        status=IntegrationStatus.DRY_RUN,
        dry_run=True,
        sink="jira_dry_run",
        finding_fingerprint="fp-1",
        created_at=datetime.now(UTC),
    )

    loaded = IntegrationRun.model_validate_json(run.model_dump_json())

    assert loaded.status is IntegrationStatus.DRY_RUN
    assert loaded.dry_run is True
    assert loaded.sink == "jira_dry_run"
    assert loaded.external_ref_id is None
    assert loaded.completed_at is None


def test_integration_config_defaults() -> None:
    cfg = IntegrationConfig(integration_type="ticketing")

    assert cfg.enabled is False
    assert cfg.dry_run is True


def test_ticket_and_notification_payloads() -> None:
    ticket = TicketCreationRequest(
        idempotency_key="jira_dry_run:fp-1",
        title="IDOR on /users/{id}",
        body="...",
        severity=Severity.HIGH,
        labels=["quarry", "idor"],
        finding_fingerprint="fp-1",
    )
    message = NotificationMessage(
        title="New finding",
        body="...",
        severity=Severity.HIGH,
        scan_id="scan-1",
        finding_fingerprint="fp-1",
    )

    assert TicketCreationRequest.model_validate_json(ticket.model_dump_json()).labels == [
        "quarry",
        "idor",
    ]
    assert message.links == []
