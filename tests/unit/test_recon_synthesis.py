"""Tests for recon synthesis: ArchitectureDoc + the on-disk architecture markdown."""

from __future__ import annotations

from pathlib import Path

from quarry.schemas import EntryPoint, Subsystem
from quarry_activities.recon_synthesis import (
    recon_synthesis_activity,
    render_architecture_markdown,
)


def _subsystem() -> Subsystem:
    return Subsystem(
        name="app",
        root_paths=["."],
        languages=["python"],
        responsibility="Main FastAPI application",
        entry_points=[
            EntryPoint(repo=".", file="app.py", function="fetch_local", kind="http_handler"),
        ],
        notes="SSRF sinks:\n- urlopen with user-controlled url (app.py:78)",
    )


def test_render_architecture_markdown_includes_entry_points_and_notes() -> None:
    from quarry_activities.recon_synthesis import recon_synthesis_activity as _act

    doc = _act([_subsystem()], ".", "scan-1")
    md = render_architecture_markdown(doc, "scan-1")

    assert md.startswith("# Architecture map — scan-1")
    assert "## Entry points" in md
    assert "app.py" in md and "fetch_local" in md and "http_handler" in md
    assert "## Subsystems" in md
    assert "Main FastAPI application" in md
    # The per-class sink/source inventory is surfaced.
    assert "SSRF sinks:" in md
    assert "urlopen with user-controlled url (app.py:78)" in md


def test_recon_synthesis_writes_architecture_report_to_disk(tmp_path: Path) -> None:
    out = tmp_path / "out"
    recon_synthesis_activity([_subsystem()], ".", "scan-xyz", str(out))

    report = out / "reports" / "scan-xyz-architecture.md"
    assert report.exists(), "architecture markdown report should be written under reports/"
    text = report.read_text(encoding="utf-8")
    assert "# Architecture map — scan-xyz" in text
    assert "fetch_local" in text


def test_recon_synthesis_no_write_without_output_dir(tmp_path: Path) -> None:
    # Back-compat: called without output_dir → returns the doc, writes nothing.
    doc = recon_synthesis_activity([_subsystem()], ".", "scan-1")
    assert doc.entry_points and doc.entry_points[0].function == "fetch_local"
    assert not list(tmp_path.glob("**/*.md"))
