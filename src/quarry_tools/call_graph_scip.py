"""SCIP call-graph backend.

Runs an external SCIP indexer binary to produce a type-resolved call graph
for languages where ast-based analysis is insufficient (Go, TypeScript, Java,
Rust).  The resulting :class:`~quarry.schemas.CallGraph` carries
``index_kind="scip"``.

Graceful fallback
-----------------
When the SCIP binary is absent, times out, or exits with a non-zero code, an
**empty** :class:`CallGraph` is returned (no exception propagated).  This
allows CI to run without any SCIP toolchain installed — the tracer will
simply receive an empty graph and reason from file context alone.

Supported languages and their default binary names
---------------------------------------------------
  - ``go`` → ``scip-go``
  - ``typescript`` / ``javascript`` → ``scip-typescript``
  - ``java`` → ``scip-java``
  - ``rust`` → ``scip-rust``

Any other language raises :class:`ValueError`.

SCIP index parsing
------------------
The raw ``.scip`` index is a protobuf binary.  Full graph extraction requires
the ``scip`` CLI (``scip print --json``) or the ``scip-python`` protobuf
bindings.  Both are optional.  When neither is available the backend returns
a graph with ``entry_points`` derived from the indexed document symbols but
with empty ``edges`` — still useful for tracer context.

This module does **not** implement full SCIP protobuf parsing yet.  The
graceful fallback path is the primary behaviour for CI; the parsing path is
a TODO once the toolchain stabilises.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from quarry.schemas import CallGraph

_LOG = logging.getLogger(__name__)

# Seconds to allow the SCIP indexer to run before killing it.
_INDEXER_TIMEOUT_SECONDS = 120

# Mapping from language name → SCIP binary name.
_LANGUAGE_BINARIES: dict[str, str] = {
    "go": "scip-go",
    "typescript": "scip-typescript",
    "javascript": "scip-typescript",
    "java": "scip-java",
    "rust": "scip-rust",
}


def is_scip_available(language: str) -> bool:
    """Return ``True`` when the SCIP indexer binary for *language* is on PATH.

    Parameters
    ----------
    language:
        One of the supported language names (``go``, ``typescript``,
        ``javascript``, ``java``, ``rust``).

    Returns
    -------
    bool
        ``True`` if the binary can be found via :func:`shutil.which`.
    """
    binary = _LANGUAGE_BINARIES.get(language.lower())
    if binary is None:
        return False
    return shutil.which(binary) is not None


def build_scip_call_graph(
    scan_id: str,
    repo_path: Path | str,
    language: str,
    *,
    repo_name: str | None = None,
    timeout: int = _INDEXER_TIMEOUT_SECONDS,
) -> CallGraph:
    """Build a :class:`CallGraph` using the SCIP indexer for *language*.

    Parameters
    ----------
    scan_id:
        The scan identifier to embed in the returned :class:`CallGraph`.
    repo_path:
        Root directory of the repository to index.
    language:
        The programming language to index.  Must be one of ``go``,
        ``typescript``, ``javascript``, ``java``, or ``rust``.
    repo_name:
        Short name for the repo.  Defaults to the directory name.
    timeout:
        Seconds to allow the SCIP indexer to run.  Defaults to 120s.

    Returns
    -------
    CallGraph
        A :class:`~quarry.schemas.CallGraph` with ``index_kind="scip"``.
        Returns an **empty graph** (no edges, no entry points) if the SCIP
        binary is absent, times out, or exits non-zero — never raises.

    Raises
    ------
    ValueError
        If *language* is not in the supported set.
    """
    lang_key = language.lower()
    if lang_key not in _LANGUAGE_BINARIES:
        raise ValueError(
            f"unsupported language for SCIP indexing: {language!r}. "
            f"Supported: {sorted(_LANGUAGE_BINARIES)}"
        )

    repo_path = Path(repo_path)
    if repo_name is None:
        repo_name = repo_path.name

    binary = _LANGUAGE_BINARIES[lang_key]

    try:
        return _run_indexer(
            scan_id=scan_id,
            binary=binary,
            repo_path=repo_path,
            repo_name=repo_name,
            timeout=timeout,
        )
    except FileNotFoundError:
        _LOG.debug("SCIP binary %r not found — returning empty call graph", binary)
    except subprocess.TimeoutExpired:
        _LOG.warning("SCIP indexer %r timed out after %ds — returning empty graph", binary, timeout)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("SCIP indexer %r failed (%s) — returning empty graph", binary, exc)

    return _empty_graph(scan_id)


def _run_indexer(
    *,
    scan_id: str,
    binary: str,
    repo_path: Path,
    repo_name: str,
    timeout: int,
) -> CallGraph:
    """Run the SCIP indexer and parse the output.

    Returns an empty graph if the indexer exits non-zero or produces no
    parseable output.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "index.scip"
        result = subprocess.run(
            [binary, "--output", str(output_path)],
            cwd=str(repo_path),
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            _LOG.debug(
                "SCIP indexer %r exited %d: %s",
                binary,
                result.returncode,
                result.stderr[:200] if result.stderr else "",
            )
            return _empty_graph(scan_id)

        if not output_path.exists():
            _LOG.debug("SCIP indexer produced no output file")
            return _empty_graph(scan_id)

        # TODO(scip-parse): parse index.scip via `scip print --json` or the
        # scip-python protobuf bindings to extract call edges and entry points.
        # For now, return the scan_id + index_kind so the tracer knows a SCIP
        # index was attempted (even if edges are empty).
        return CallGraph(
            scan_id=scan_id,
            index_kind="scip",
        )


def _empty_graph(scan_id: str) -> CallGraph:
    return CallGraph(scan_id=scan_id, index_kind="scip")
