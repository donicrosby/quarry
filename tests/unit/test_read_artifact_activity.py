"""read-artifact-text activity (per-class-dynamic-validation, registry wiring).

Written RED first — fails until ``src/quarry_activities/read_artifact.py`` exists.

The workflow runs under Temporal's sandbox and must stay I/O-free, so body
artifacts are resolved to text activity-side. Locked contracts:

- ``read_artifact_text(store, key)`` reads an artifact by store key, caps the
  text at 64KB, and returns ``None`` on ANY failure (missing artifact,
  traversal-escaping key) — never raises.
- ``body_text_from_response_artifact(raw_text)`` is PURE: it parses a stored
  HTTP_RESPONSE artifact's JSON envelope and extracts its ``body`` field
  (str | None). Deterministic — safe inside sandboxed workflow code.
- The Temporal ``@activity.defn(name="read-artifact-text")`` wrapper takes a
  frozen Pydantic input (``ReadArtifactTextInput`` from quarry_activities.inputs)
  and roots the store at ``artifact_store_path / scan_id`` — the same
  convention as ``http-request``.
- Registered in BOTH quarry_worker/main.py and quarry_server/app.py (parity).
"""

from __future__ import annotations

import json
from pathlib import Path

from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_activities.inputs import ReadArtifactTextInput
from quarry_artifacts.local import LocalArtifactStore


def _store(tmp_path: Path) -> LocalArtifactStore:
    return LocalArtifactStore(tmp_path / "scan-1")


def _put_json(
    store: LocalArtifactStore,
    key: str,
    payload: dict[str, object],
) -> None:
    store.put_bytes(
        key,
        (json.dumps(payload) + "\n").encode("utf-8"),
        kind=ArtifactKind.HTTP_RESPONSE,
        content_type="application/json",
        redaction_status=RedactionStatus.NOT_REQUIRED,
    )


# ---------------------------------------------------------------------------
# read_artifact_text impl (store-injected)
# ---------------------------------------------------------------------------


class TestReadArtifactTextImpl:
    def test_reads_stored_artifact_text(self, tmp_path: Path) -> None:
        from quarry_activities.read_artifact import MAX_ARTIFACT_TEXT_BYTES, read_artifact_text

        store = _store(tmp_path)
        _put_json(store, "http/responses/200_x.json", {"body": "hello world"})
        text = read_artifact_text(store, "http/responses/200_x.json")
        assert text is not None
        assert json.loads(text)["body"] == "hello world"
        assert MAX_ARTIFACT_TEXT_BYTES == 64 * 1024

    def test_missing_artifact_returns_none(self, tmp_path: Path) -> None:
        from quarry_activities.read_artifact import read_artifact_text

        store = _store(tmp_path)
        assert read_artifact_text(store, "http/responses/absent.json") is None

    def test_caps_at_64kb(self, tmp_path: Path) -> None:
        from quarry_activities.read_artifact import read_artifact_text

        store = _store(tmp_path)
        big = "x" * (100 * 1024)
        _put_json(store, "http/responses/big.json", {"body": big})
        text = read_artifact_text(store, "http/responses/big.json")
        assert text is not None
        assert len(text.encode("utf-8")) == 64 * 1024

    def test_traversal_key_returns_none(self, tmp_path: Path) -> None:
        from quarry_activities.read_artifact import read_artifact_text

        store = _store(tmp_path)
        assert read_artifact_text(store, "../../etc/passwd") is None

    def test_binary_garbage_never_raises(self, tmp_path: Path) -> None:
        """Binary garbage decodes with errors='replace', capped, still returns str."""
        from quarry_activities.read_artifact import read_artifact_text

        store = _store(tmp_path)
        store.put_bytes(
            "http/responses/bin.json",
            bytes(range(256)) * 300,
            kind=ArtifactKind.HTTP_RESPONSE,
            content_type="application/octet-stream",
        )
        text = read_artifact_text(store, "http/responses/bin.json")
        assert text is not None
        assert len(text.encode("utf-8", errors="replace")) <= 64 * 1024


# ---------------------------------------------------------------------------
# body_text_from_response_artifact (pure envelope → body extraction)
# ---------------------------------------------------------------------------


class TestBodyTextFromResponseArtifact:
    def test_extracts_body_field(self) -> None:
        from quarry_activities.read_artifact import body_text_from_response_artifact

        envelope = json.dumps({"status_code": 200, "body": "result: 49"})
        assert body_text_from_response_artifact(envelope) == "result: 49"

    def test_none_raw_returns_none(self) -> None:
        from quarry_activities.read_artifact import body_text_from_response_artifact

        assert body_text_from_response_artifact(None) is None

    def test_missing_body_field_returns_none(self) -> None:
        from quarry_activities.read_artifact import body_text_from_response_artifact

        assert body_text_from_response_artifact(json.dumps({"status_code": 200})) is None

    def test_non_dict_json_returns_none(self) -> None:
        from quarry_activities.read_artifact import body_text_from_response_artifact

        assert body_text_from_response_artifact("[1, 2, 3]") is None

    def test_non_string_body_returns_none(self) -> None:
        from quarry_activities.read_artifact import body_text_from_response_artifact

        assert body_text_from_response_artifact(json.dumps({"body": 49})) is None

    def test_invalid_json_returns_none(self) -> None:
        from quarry_activities.read_artifact import body_text_from_response_artifact

        assert body_text_from_response_artifact("not json {{{") is None


# ---------------------------------------------------------------------------
# Temporal activity wrapper + registration parity
# ---------------------------------------------------------------------------


class TestReadArtifactTextActivity:
    def test_has_temporal_definition(self) -> None:
        from quarry_activities.read_artifact import read_artifact_text_activity

        defn = getattr(read_artifact_text_activity, "__temporal_activity_definition", None)
        assert defn is not None
        assert defn.name == "read-artifact-text"

    def test_activity_round_trip(self, tmp_path: Path) -> None:
        from quarry_activities.read_artifact import read_artifact_text_activity

        root = tmp_path
        _put_json(_store(root), "http/responses/a.json", {"body": "xyz"})
        result = read_artifact_text_activity(
            ReadArtifactTextInput(
                artifact_store_path=str(root),
                scan_id="scan-1",
                artifact_key="http/responses/a.json",
            )
        )
        assert result is not None
        assert json.loads(result)["body"] == "xyz"

    def test_activity_returns_none_on_missing(self, tmp_path: Path) -> None:
        from quarry_activities.read_artifact import read_artifact_text_activity

        result = read_artifact_text_activity(
            ReadArtifactTextInput(
                artifact_store_path=str(tmp_path),
                scan_id="scan-1",
                artifact_key="absent.json",
            )
        )
        assert result is None
