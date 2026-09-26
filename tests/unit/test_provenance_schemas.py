"""Serialization tests for provenance schemas."""

from datetime import UTC, datetime

from quarry.schemas import (
    FindingProvenance,
    ModelPanelEntry,
    ScanManifest,
    SourceRef,
    ToolInvocation,
)


def test_scan_manifest_round_trips() -> None:
    manifest = ScanManifest(
        id="manifest-1",
        scan_id="scan-1",
        workspace_id="local",
        quarry_version="0.1.0",
        profile_id="local-fast",
        panel_snapshot=[
            ModelPanelEntry(
                id="p1", scan_id="scan-1", role="hunt", provider="anthropic", model="opus"
            )
        ],
        plugins_active=["secrets"],
        repo_commit_sha="abc123",
        created_at=datetime.now(UTC),
    )

    loaded = ScanManifest.model_validate_json(manifest.model_dump_json())

    assert loaded.quarry_version == "0.1.0"
    assert loaded.repo_commit_sha == "abc123"
    assert loaded.panel_snapshot[0].role == "hunt"
    assert loaded.prompt_bundle_hash is None


def test_tool_invocation_round_trips() -> None:
    invocation = ToolInvocation(
        id="tool-1",
        scan_id="scan-1",
        workspace_id="local",
        tool_name="git",
        tool_version="2.43.0",
        args_hash="d" * 64,
        exit_code=0,
        started_at=datetime.now(UTC),
    )

    loaded = ToolInvocation.model_validate_json(invocation.model_dump_json())

    assert loaded.tool_name == "git"
    assert loaded.args_hash == "d" * 64
    assert loaded.allowed is True
    assert loaded.exit_code == 0


def test_finding_provenance() -> None:
    finding = FindingProvenance(
        finding_fingerprint="secrets:app.py:KEY",
        scan_id="scan-1",
        manifest_id="manifest-1",
        validation_result_id="v-1",
        proof_artifact_ids=["proof-1"],
        tool_invocation_ids=["tool-1"],
        source_refs=[SourceRef(file_path="app.py", start_line=9)],
    )
    loaded_finding = FindingProvenance.model_validate_json(finding.model_dump_json())
    assert loaded_finding.model_invocation_ids == []
