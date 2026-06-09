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

from typing import Any

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widgets import Header, RichLog, Static

from quarry_client.client import QuarryClient

_POLL_INTERVAL_SECONDS = 2.0


class WorkerActivityPanel(Static):
    """Live worker-activity panel: shows iteration-grained agent events."""

    _last_event_id: reactive[str | None] = reactive(None)

    def __init__(self, client: QuarryClient, scan_id: str) -> None:
        super().__init__()
        self.client = client
        self.scan_id = scan_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="activity-log", highlight=True, markup=True, wrap=True)

    async def on_mount(self) -> None:
        self.set_interval(_POLL_INTERVAL_SECONDS, self._poll_events)

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
            log.write(line)

    def get_events(self) -> list[dict[str, Any]]:
        """Return current event log entries (for testing and CLI --verbose mode)."""
        log = self.query_one(RichLog)
        return [{"text": str(line)} for line in log._lines]


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
