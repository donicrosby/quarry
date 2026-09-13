"""read-artifact-text activity — resolve artifact refs to capped text, I/O-free workflows.

Workflow code under Temporal's sandbox must perform no I/O, so the
dynamic-validation stage resolves stored HTTP-response bodies activity-side:
the workflow dispatches ``read-artifact-text`` with the artifact store path and
key, and the activity returns the stored bytes as text (capped at 64KB) — or
``None`` on ANY failure.  A ``None`` body is treated by verdict evaluators as
non-corroboration, never an error (a missing body must never fail the scan).

Also provides :func:`body_text_from_response_artifact`, which parses a stored
``HTTP_RESPONSE`` artifact's JSON envelope and extracts its ``body`` field —
the exact input per-class body evaluators consume.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from temporalio import activity

from quarry_activities.inputs import ReadArtifactTextInput
from quarry_artifacts.local import LocalArtifactStore

# Hard cap on resolved artifact text. Response bodies are already capped at
# 10KB at capture time; this second cap guards against future producers and
# keeps differential comparisons bounded even on hostile bodies.
MAX_ARTIFACT_TEXT_BYTES = 64 * 1024


def read_artifact_text(store: LocalArtifactStore, artifact_key: str) -> str | None:
    """Read an artifact's bytes by key, capped at 64KB; None on ANY failure.

    Never raises: a missing artifact (``store.get_text`` → None) or any OSError
    resolves to None — the evaluator contract treats a missing body as
    non-corroboration rather than an error.
    """
    try:
        text = store.get_text(artifact_key)
    except (OSError, ValueError):
        # get_text suppresses OSError/ValueError itself, but a store backend may
        # still raise before reaching its internal guard — degrade to None.
        return None
    if text is None:
        return None
    return text.encode("utf-8", errors="replace")[:MAX_ARTIFACT_TEXT_BYTES].decode(
        "utf-8", errors="replace"
    )


def body_text_from_response_artifact(raw: str | None) -> str | None:
    """Extract the ``body`` text from a stored HTTP_RESPONSE artifact's text.

    PURE — parses the stored JSON envelope
    (``{"status_code", "headers", "url", "body", ...}``) and returns the
    ``body`` string, or None when *raw* is None, unparseable, not an object, or
    its ``body`` is absent/non-string.  Never raises; safe inside sandboxed
    workflow code (the activity resolves bytes, this maps text → evidence).
    """
    if raw is None:
        return None
    try:
        parsed: object = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    envelope = cast("dict[str, object]", parsed)
    body: object | None = envelope.get("body")
    if not isinstance(body, str):
        return None
    return body


@activity.defn(name="read-artifact-text")
def read_artifact_text_activity(inp: ReadArtifactTextInput) -> str | None:
    """Read one artifact by key from the scan's store; None on any failure.

    The store is rooted at ``artifact_store_path / scan_id`` — the same
    convention as the ``http-request`` activity, so the two share a namespace.
    Returns the artifact text (64KB cap) or None; dispatched by the
    dynamic-validation workflow to resolve response bodies without breaking the
    sandbox's no-I/O rule for workflow code.
    """
    try:
        store = LocalArtifactStore(Path(inp.artifact_store_path) / inp.scan_id)
        return read_artifact_text(store, inp.artifact_key)
    except (OSError, ValueError):
        return None
