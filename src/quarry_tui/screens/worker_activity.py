"""Worker activity panel — live iteration-grained agent reasoning feed (ADR-020).

Polls ``GET /scans/{scan_id}/events?event_types=agent.*`` every 2 seconds and
renders each event as a line in the activity log:

  [hunt #3] Reflected XSS via `q` param → GET /search?q= ✓
  [hunt #4] ⚠ presence, context_reference — retries remaining: 1

Accepted actions (agent.action_proposed, check passed) are rendered in green.
Rejected reasoning (agent.reasoning_rejected or check failed) render in amber/red.

M2 baseline: polling. SSE is a future enhancement (0.3).
"""

from __future__ import annotations

import contextlib
from typing import Any

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widgets import Header, Label, RichLog, Static

from quarry_client.client import QuarryClient

_POLL_INTERVAL_SECONDS = 2.0


def format_round_label(metadata: dict[str, Any]) -> str | None:
    """Render the ADR-022 round counter from a Scan's metadata, or None pre-loop.

    ``coverage_round_index`` (0-based, updated every round) and
    ``max_coverage_rounds`` (set once at scan creation) are written by
    RunScanWorkflow (see run_scan.py). Older scans that predate the
    iterative-coverage-loop feature carry neither key — return None so the
    caller can leave the counter hidden rather than show a bogus round.
    """
    round_index = metadata.get("coverage_round_index")
    max_rounds = metadata.get("max_coverage_rounds")
    if round_index is None or max_rounds is None:
        return None
    return f"Round {int(round_index) + 1}/{int(max_rounds)}"


class WorkerActivityPanel(Static):
    """Live worker-activity panel: shows iteration-grained agent events."""

    _last_event_id: reactive[str | None] = reactive(None)
    round_label: reactive[str | None] = reactive(None)

    def __init__(self, client: QuarryClient, scan_id: str) -> None:
        super().__init__()
        self.client = client
        self.scan_id = scan_id
        # Mirror of the lines written to the RichLog, so get_events() doesn't have
        # to read RichLog's private internals.
        self._event_lines: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("", id="round-label")
        yield RichLog(id="activity-log", highlight=True, markup=True, wrap=True)

    async def on_mount(self) -> None:
        self.set_interval(_POLL_INTERVAL_SECONDS, self._poll_events)
        self.set_interval(_POLL_INTERVAL_SECONDS, self._poll_round_progress)

    async def _poll_round_progress(self) -> None:
        try:
            scan = await self.client.get_scan(self.scan_id)
        except Exception:
            return
        label = format_round_label(scan.metadata)
        if label == self.round_label:
            return
        self.round_label = label
        with contextlib.suppress(Exception):
            # Suppresses "not mounted yet" (e.g. called directly in a test).
            self.query_one("#round-label", Label).update(label or "")

    async def _poll_events(self) -> None:
        try:
            events = await self.client.poll_events(
                scan_id=self.scan_id,
                event_types=["agent.action_proposed", "agent.reasoning_rejected"],
                after_id=self._last_event_id,
                limit=50,
            )
        except Exception:
            return

        log = self.query_one(RichLog)
        for event in events:
            self._last_event_id = event.id
            line = _format_event(event.event_type, event.payload)
            self._event_lines.append(line)
            log.write(line)

    def get_events(self) -> list[dict[str, Any]]:
        """Return current event log entries (for testing and CLI --verbose mode)."""
        return [{"text": line} for line in self._event_lines]


def _format_event(event_type: str, payload: dict[str, Any]) -> str:
    """Format a WorkflowEvent as a single log line."""
    agent_kind = payload.get("agent_kind", "?")
    iteration = payload.get("iteration", "?")
    tool_name = payload.get("tool_name", "?")

    if event_type == "agent.action_proposed":
        summary = payload.get("reasoning_summary", "")
        check_passed = payload.get("check_result", {}).get("passed", True)
        icon = "✓" if check_passed else "⚠"
        colour = "green" if check_passed else "yellow"
        return f"[{colour}][{agent_kind} #{iteration}] {summary} → {tool_name} {icon}[/{colour}]"

    elif event_type == "agent.reasoning_rejected":
        failed = ", ".join(payload.get("failed_checks", []))
        retries = payload.get("retries_remaining", 0)
        return (
            f"[yellow][{agent_kind} #{iteration}] "
            f"⚠ {failed} — retries remaining: {retries}[/yellow]"
        )

    return f"[dim][{agent_kind} #{iteration}] {event_type}[/dim]"
