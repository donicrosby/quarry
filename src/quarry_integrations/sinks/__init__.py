"""Built-in finding sinks."""

from __future__ import annotations

from typing import cast

from quarry_integrations.base import FindingSink
from quarry_integrations.sinks.file_sink import FileSink
from quarry_integrations.sinks.jira_dry_run import JiraDryRunSink
from quarry_integrations.sinks.noop import NoopSink
from quarry_integrations.sinks.slack_dry_run import SlackDryRunSink
from quarry_plugins.base import PluginType
from quarry_plugins.registry import load_plugins, plugins_of_type

__all__ = [
    "FileSink",
    "JiraDryRunSink",
    "NoopSink",
    "SlackDryRunSink",
    "default_sinks",
]


def default_sinks() -> list[FindingSink]:
    """Sinks delivered on scan completion (dry-run previews + a local file copy).

    Sourced from the unified quarry.plugins loader; the cut-line default set
    is exactly the three FINDING_SINK plugins registered in pyproject.toml
    (file, jira_dry_run, slack_dry_run) — NoopSink is intentionally excluded.
    """
    plugins = load_plugins()
    # FindingSinkPlugin is an alias of FindingSink: every FINDING_SINK-typed plugin satisfies it.
    sinks = [
        cast(FindingSink, plugin) for plugin in plugins_of_type(plugins, PluginType.FINDING_SINK)
    ]
    return sorted(sinks, key=lambda sink: sink.name)
