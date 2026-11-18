"""Tests for recon synthesis: ArchitectureDoc + the on-disk architecture markdown."""

from __future__ import annotations

from pathlib import Path

from quarry.schemas import ArchitectureDoc, EntryPoint, Subsystem
from quarry_activities.recon_synthesis import (
    recon_synthesis_activity,
    render_architecture_markdown,
)


def _doc(out: object) -> ArchitectureDoc:
    """Parse the recon-synthesis output wrapper back to an ArchitectureDoc."""
    from quarry_activities.inputs import ReconSynthesisOutput

    assert isinstance(out, ReconSynthesisOutput)
    return ArchitectureDoc.model_validate_json(out.doc_json)


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

    doc = _doc(_act([_subsystem()], ".", "scan-1"))
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
    doc = _doc(recon_synthesis_activity([_subsystem()], ".", "scan-1"))
    assert doc.entry_points and doc.entry_points[0].function == "fetch_local"
    assert not list(tmp_path.glob("**/*.md"))


def test_recon_synthesis_persists_versioned_architecture_doc_artifact(tmp_path: Path) -> None:
    """With an artifact_root, synthesis writes a stamped ARCHITECTURE_DOC artifact.

    Covers tasks 3.1/3.2 and scenarios ``architecture_doc_written_to_artifact_store``
    and ``architecture_doc_artifact_round_trips``: the persisted artifact carries
    the version stamps and deserialises back to the doc the activity returned.
    """
    from quarry.schemas import ArtifactKind, ArtifactRef
    from quarry_activities.handoff import architecture_doc_key
    from quarry_activities.inputs import ReconSynthesisOutput

    root = tmp_path / "artifacts"
    out = recon_synthesis_activity([_subsystem()], ".", "scan-art", None, str(root), 3, 2)

    assert isinstance(out, ReconSynthesisOutput)
    assert out.artifact_ref_json is not None
    ref = ArtifactRef.model_validate_json(out.artifact_ref_json)
    assert ref.kind is ArtifactKind.ARCHITECTURE_DOC

    artifact_path = root / architecture_doc_key("scan-art")
    assert artifact_path.exists(), "architecture-doc artifact should be on disk"
    doc = ArchitectureDoc.model_validate_json(artifact_path.read_text(encoding="utf-8"))
    assert doc.scan_ordinal == 3
    assert doc.artifact_version == 2
    # Round-trips to the same doc the activity returned.
    returned = ArchitectureDoc.model_validate_json(out.doc_json)
    assert doc.model_dump_json() == returned.model_dump_json()
