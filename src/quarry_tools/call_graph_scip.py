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
The raw ``.scip`` index is parsed in-process by :func:`parse_scip_index`
using the generated ``scip_pb2`` protobuf bindings (``Index`` / ``Document``
imported at the bottom of this module).  No external ``scip`` CLI is required.
Entry points are extracted from document symbols; call edges are derived from
occurrence relationships within each document.

Graceful fallback
-----------------
When the SCIP indexer binary is absent, times out, exits with a non-zero
code, or the index cannot be decoded, an **empty** :class:`CallGraph` is
returned (no exception propagated).  The tracer will simply receive an empty
graph and reason from file context alone, keeping CI green in environments
without a SCIP toolchain installed.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from quarry.schemas import CallEdge, CallGraph, EntryPoint
from quarry_tools.scip_pb2 import Document as _ScipDocument
from quarry_tools.scip_pb2 import Index as _ScipIndex

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


_SCIP_DEFINITION_ROLE = 1

_HTTP_HANDLER_NAMES: frozenset[str] = frozenset({"Handle", "ServeHTTP", "Handler"})


def _detect_entry_points_from_document(doc: _ScipDocument, repo_name: str) -> list[EntryPoint]:
    # Entry-point detection heuristics for Go SCIP symbols:
    #   - display_name "main"               -> kind="main"  (Go program entry point)
    #   - display_name in _HTTP_HANDLER_NAMES -> kind="http_handler"
    #     (Go http.Handler interface: Handle, ServeHTTP; common handler pattern: Handler)
    # These are name-based; SCIP does not encode framework annotations.
    entry_points: list[EntryPoint] = []
    for sym in doc.symbols:
        display = sym.display_name or _symbol_short_name(sym.symbol)
        if display == "main":
            entry_points.append(
                EntryPoint(repo=repo_name, file=doc.relative_path, function=display, kind="main")
            )
        elif display in _HTTP_HANDLER_NAMES:
            entry_points.append(
                EntryPoint(
                    repo=repo_name, file=doc.relative_path, function=display, kind="http_handler"
                )
            )
    return entry_points


def _symbol_short_name(symbol: str) -> str:
    parts = symbol.rstrip(")").split("/")
    if parts:
        name = parts[-1].rstrip("().")
        if name:
            return name
    return symbol


def _build_sym_info(index: _ScipIndex) -> dict[str, tuple[str, str]]:
    info: dict[str, tuple[str, str]] = {}
    for doc in index.documents:
        for sym in doc.symbols:
            display = sym.display_name or _symbol_short_name(sym.symbol)
            info[sym.symbol] = (doc.relative_path, display)
    for sym in index.external_symbols:
        display = sym.display_name or _symbol_short_name(sym.symbol)
        info[sym.symbol] = ("", display)
    return info


def _extract_edges_from_document(
    doc: _ScipDocument, repo_name: str, sym_info: dict[str, tuple[str, str]]
) -> list[CallEdge]:
    defs: list[tuple[int, str]] = []
    for occ in doc.occurrences:
        if occ.symbol_roles & _SCIP_DEFINITION_ROLE:
            row = occ.range[0] if len(occ.range) >= 1 else 0
            defs.append((row, occ.symbol))
    defs.sort()
    edges: list[CallEdge] = []
    for occ in doc.occurrences:
        if occ.symbol_roles & _SCIP_DEFINITION_ROLE:
            continue
        ref_row = occ.range[0] if len(occ.range) >= 1 else 0
        enclosing_sym: str | None = None
        for def_row, def_sym in defs:
            if def_row <= ref_row:
                enclosing_sym = def_sym
            else:
                break
        if enclosing_sym is None:
            continue
        c_file, c_fn = sym_info.get(
            enclosing_sym, (doc.relative_path, _symbol_short_name(enclosing_sym))
        )
        e_file, e_fn = sym_info.get(occ.symbol, ("", _symbol_short_name(occ.symbol)))
        edges.append(
            CallEdge(
                caller_repo=repo_name,
                caller_file=c_file or doc.relative_path,
                caller_function=c_fn,
                callee_repo=repo_name,
                callee_file=e_file or doc.relative_path,
                callee_function=e_fn,
            )
        )
    return edges


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

        return parse_scip_index(output_path, scan_id, repo_name)


def parse_scip_index(index_path: Path, scan_id: str, repo_name: str) -> CallGraph:
    """Parse a SCIP binary index file and return a CallGraph.

    Gracefully returns an empty CallGraph on missing file, empty file, or
    protobuf decode error so that CI without a SCIP toolchain still passes.
    """
    try:
        data = index_path.read_bytes()
    except OSError as exc:
        _LOG.debug("Failed to read SCIP index at %s: %s", index_path, exc)
        return _empty_graph(scan_id)

    if not data:
        _LOG.debug("SCIP index at %s is empty", index_path)
        return _empty_graph(scan_id)

    try:
        index = _ScipIndex()
        index.ParseFromString(data)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("Failed to parse SCIP index at %s: %s", index_path, exc)
        return _empty_graph(scan_id)

    _LOG.debug("Parsed SCIP index for %s: %d document(s)", repo_name, len(index.documents))
    sym_info = _build_sym_info(index)
    edges: list[CallEdge] = []
    entry_points: list[EntryPoint] = []
    for doc in index.documents:
        edges.extend(_extract_edges_from_document(doc, repo_name, sym_info))
        entry_points.extend(_detect_entry_points_from_document(doc, repo_name))
    return CallGraph(scan_id=scan_id, index_kind="scip", edges=edges, entry_points=entry_points)


def _empty_graph(scan_id: str) -> CallGraph:
    return CallGraph(scan_id=scan_id, index_kind="scip")
