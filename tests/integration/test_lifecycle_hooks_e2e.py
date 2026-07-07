"""End-to-end verification of the lifecycle-hook dispatch mechanism.

Exercises the REAL entry-point-discovered slack_notify plugin (no monkeypatch
of importlib.metadata — the plugin is genuinely registered in pyproject.toml)
against a real local HTTP receiver, over real httpx networking. This proves
the actual network path works, not just that httpx.post gets called.

Temporal workflow *wiring* (does _emit_and_dispatch get called at the right
site, with the right args) is already covered by
tests/integration/test_lifecycle_dispatch_wiring.py per this codebase's
established convention (test_prove_stage.py): workflow dispatch logic is
verified via pure helpers and call-site inspection, not by driving a full
agentic Temporal run (which, post pure-agentic-pivot, needs a configured
MockModelClient hunt+validate fixture that no existing e2e test wires up for
RunScanWorkflow — every existing e2e test scan yields zero findings).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from quarry.schemas import (
    FinalFinding,
    IntegrationConfig,
    IntegrationStatus,
    SecretRef,
    Severity,
    VulnerabilityClass,
)


class _RecordingWebhookHandler(BaseHTTPRequestHandler):
    received: list[dict[str, object]] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib method name
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).received.append(json.loads(body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # silence stdlib access logging


@pytest.fixture
def webhook_receiver() -> Iterator[tuple[str, list[dict[str, object]]]]:
    _RecordingWebhookHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _RecordingWebhookHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/webhook", _RecordingWebhookHandler.received
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _finding(severity: Severity = Severity.CRITICAL) -> FinalFinding:
    return FinalFinding(
        id="f-e2e-1",
        scan_id="scan-e2e-1",
        workspace_id="local",
        fingerprint="secrets:app.py:E2E_KEY",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=severity,
        title="Hardcoded secret: E2E_KEY",
        summary="A hardcoded secret was found during e2e verification.",
        validation_result_id="v-e2e-1",
        created_at=datetime.now(UTC),
    )


def test_real_slack_notify_delivers_to_real_receiver_via_real_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    webhook_receiver: tuple[str, list[dict[str, object]]],
    tmp_path: Path,
) -> None:
    """The entry-point-registered slack_notify plugin, dispatched through the
    real activity function, actually POSTs to a real HTTP receiver."""
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks
    from quarry_plugins.base import PluginType
    from quarry_plugins.registry import load_plugins, plugins_of_type

    webhook_url, received = webhook_receiver
    monkeypatch.setenv("QUARRY_SECRET_SLACK_WEBHOOK_E2E", webhook_url)

    # Confirm slack_notify is genuinely discoverable via the real entry-point
    # registration (no monkeypatching of importlib.metadata in this test).
    hooks = plugins_of_type(load_plugins(), PluginType.LIFECYCLE_HOOK)
    assert any(h.name == "slack_notify" for h in hooks), (
        'slack_notify must be registered under [project.entry-points."quarry.plugins"]'
    )

    config = IntegrationConfig(
        integration_type="slack_notify",
        enabled=True,
        dry_run=False,
        secret_ref=SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK_E2E"),
        severity_threshold=Severity.CRITICAL,
    )
    finding = _finding()

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id=finding.scan_id,
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=False,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )

    runs = dispatch_lifecycle_hooks(input_)

    assert len(runs) == 1
    assert runs[0].status is IntegrationStatus.DELIVERED
    assert len(received) == 1
    assert received[0]["scan_id"] == finding.scan_id
    assert received[0]["finding_fingerprint"] == finding.fingerprint

    # Re-dispatch with the delivered key marked as already-delivered (what a
    # resumed/replayed scan would pass) — must not produce a second POST.
    second_input = input_.model_copy(update={"existing_keys": (runs[0].idempotency_key,)})
    second_runs = dispatch_lifecycle_hooks(second_input)

    assert len(second_runs) == 1
    assert second_runs[0].status is IntegrationStatus.SKIPPED
    assert len(received) == 1, "idempotency must prevent a duplicate real POST"
