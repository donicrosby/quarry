"""Finding sinks: deliver finalized findings to external systems.

Dry-run by default — sinks write payload artifacts that preview the external
action (Jira ticket, Slack message) without making any real API calls. Only
finalized findings are delivered, and delivery is idempotent per scan so repeated
or resumed runs never duplicate tickets.
"""
