"""Built-in finding sinks."""

from __future__ import annotations

from quarry_integrations.base import FindingSink
from quarry_integrations.sinks.file_sink import FileSink
from quarry_integrations.sinks.jira_dry_run import JiraDryRunSink
from quarry_integrations.sinks.noop import NoopSink
from quarry_integrations.sinks.slack_dry_run import SlackDryRunSink

__all__ = [
    "FileSink",
    "JiraDryRunSink",
    "NoopSink",
    "SlackDryRunSink",
    "default_sinks",
]


def default_sinks() -> list[FindingSink]:
    """Sinks delivered on scan completion (dry-run previews + a local file copy)."""
    return [FileSink(), JiraDryRunSink(), SlackDryRunSink()]
