# Quarry Architecture

Quarry is a local-first agentic vulnerability research harness for source-aware web and API testing.

The current implementation is intentionally small:

- Typer CLI accepts a local repo path.
- A fake scan runner creates a candidate finding.
- SQLite persists scans, events, candidate findings, artifact refs, and reports.
- Jinja2 renders a Markdown report.
- Textual displays scan status from SQLite.
- Temporal workflow and worker entrypoints exist for the orchestration boundary.

Deferred: real route mapping, model calls, validation, proof, target launching, plugins, and Kubernetes deployment.
