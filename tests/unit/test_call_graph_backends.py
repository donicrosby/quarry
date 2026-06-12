"""Unit tests for the call-graph backends (TDD Red → Green → Clean).

Two backends:
- ``build_python_call_graph`` (call_graph_python.py) — uses Python's ``ast``
  module; no subprocess; produces ``CallGraph(index_kind="ast_grep")``.
- ``build_scip_call_graph`` (call_graph_scip.py) — runs SCIP indexer binary;
  falls back gracefully when binary absent; produces
  ``CallGraph(index_kind="scip")``.

These are pure functions (not Temporal activities).  They are called from
the tracer orchestration logic in the scan workflow.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import CallEdge, CallGraph, EntryPoint

# ---------------------------------------------------------------------------
# Helpers — write small Python fixtures to tmp_path
# ---------------------------------------------------------------------------


def _write_py(tmp_path: Path, filename: str, source: str) -> Path:
    p = tmp_path / filename
    p.write_text(source)
    return p


# ===========================================================================
# Python backend
# ===========================================================================


class TestBuildPythonCallGraphModule:
    def test_module_importable(self) -> None:
        from quarry_tools import (
            call_graph_python,  # noqa: F401  # pyright: ignore[reportUnusedImport]
        )

    def test_build_function_importable(self) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        assert callable(build_python_call_graph)


class TestPythonCallGraphReturnType:
    def test_returns_call_graph_instance(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        result = build_python_call_graph(scan_id="s-1", repo_path=tmp_path)
        assert isinstance(result, CallGraph)

    def test_index_kind_is_ast_grep(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        result = build_python_call_graph(scan_id="s-1", repo_path=tmp_path)
        assert result.index_kind == "ast_grep"

    def test_scan_id_propagated(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        result = build_python_call_graph(scan_id="scan-xyz", repo_path=tmp_path)
        assert result.scan_id == "scan-xyz"


class TestPythonCallGraphEmptyRepo:
    def test_empty_directory_returns_empty_graph(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        result = build_python_call_graph(scan_id="s-empty", repo_path=tmp_path)
        assert result.edges == []
        assert result.entry_points == []

    def test_no_python_files_returns_empty_graph(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        (tmp_path / "README.md").write_text("# project")
        result = build_python_call_graph(scan_id="s-nofiles", repo_path=tmp_path)
        assert result.edges == []


class TestPythonCallGraphEdgeDetection:
    def test_direct_call_produces_edge(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "app.py",
            "def foo():\n    bar()\n\ndef bar():\n    pass\n",
        )
        result = build_python_call_graph(scan_id="s-edge", repo_path=tmp_path)
        callers = {e.caller_function for e in result.edges}
        callees = {e.callee_function for e in result.edges}
        assert "foo" in callers
        assert "bar" in callees

    def test_edge_carries_file_path(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(tmp_path, "srv.py", "def handler():\n    helper()\n\ndef helper():\n    pass\n")
        result = build_python_call_graph(scan_id="s-file", repo_path=tmp_path)
        assert result.edges, "expected at least one edge"
        edge = result.edges[0]
        assert "srv.py" in edge.caller_file

    def test_multiple_calls_in_one_function(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "multi.py",
            "def controller():\n    alpha()\n    beta()\n"
            "\ndef alpha():\n    pass\n\ndef beta():\n    pass\n",
        )
        result = build_python_call_graph(scan_id="s-multi", repo_path=tmp_path)
        callees = {e.callee_function for e in result.edges if e.caller_function == "controller"}
        assert "alpha" in callees
        assert "beta" in callees

    def test_nested_function_calls(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "nested.py",
            "def outer():\n    inner()\n\ndef inner():\n    leaf()\n\ndef leaf():\n    pass\n",
        )
        result = build_python_call_graph(scan_id="s-nested", repo_path=tmp_path)
        caller_callee = {(e.caller_function, e.callee_function) for e in result.edges}
        assert ("outer", "inner") in caller_callee
        assert ("inner", "leaf") in caller_callee

    def test_call_edge_schema_fields(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(tmp_path, "check.py", "def f():\n    g()\n\ndef g():\n    pass\n")
        result = build_python_call_graph(scan_id="s-schema", repo_path=tmp_path)
        assert result.edges
        edge = result.edges[0]
        assert isinstance(edge, CallEdge)
        assert edge.caller_repo != ""
        assert edge.callee_repo != ""


class TestPythonCallGraphEntryPointDetection:
    def test_flask_route_is_http_handler(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "flask_app.py",
            "from flask import Flask\napp = Flask(__name__)\n\n"
            "@app.route('/users')\ndef list_users():\n    return []\n",
        )
        result = build_python_call_graph(scan_id="s-flask", repo_path=tmp_path)
        http_eps = [ep for ep in result.entry_points if ep.kind == "http_handler"]
        assert http_eps, "Flask @app.route should produce an http_handler entry point"
        assert any(ep.function == "list_users" for ep in http_eps)

    def test_fastapi_route_is_http_handler(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n\n"
            "@app.get('/items')\ndef get_items():\n    return []\n",
        )
        result = build_python_call_graph(scan_id="s-fastapi", repo_path=tmp_path)
        http_eps = [ep for ep in result.entry_points if ep.kind == "http_handler"]
        assert http_eps, "FastAPI @app.get should produce an http_handler entry point"
        assert any(ep.function == "get_items" for ep in http_eps)

    def test_main_guard_is_main_entrypoint(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "cli.py",
            'def main():\n    print("hello")\n\nif __name__ == "__main__":\n    main()\n',
        )
        result = build_python_call_graph(scan_id="s-main", repo_path=tmp_path)
        main_eps = [ep for ep in result.entry_points if ep.kind == "main"]
        assert main_eps, "__main__ guard should produce a main entry point"

    def test_click_command_is_cli_arg(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "cli_tool.py",
            "import click\n\n@click.command()\ndef run():\n    pass\n",
        )
        result = build_python_call_graph(scan_id="s-click", repo_path=tmp_path)
        cli_eps = [ep for ep in result.entry_points if ep.kind == "cli_arg"]
        assert cli_eps, "@click.command should produce a cli_arg entry point"

    def test_entry_point_schema_fields(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(
            tmp_path,
            "ep_check.py",
            "@app.route('/ping')\ndef ping():\n    pass\n",
        )
        result = build_python_call_graph(scan_id="s-ep-schema", repo_path=tmp_path)
        if result.entry_points:
            ep = result.entry_points[0]
            assert isinstance(ep, EntryPoint)
            assert ep.file != ""
            assert ep.function != ""
            assert ep.repo != ""


class TestPythonCallGraphNoSubprocess:
    """Python backend must not shell out — it uses Python's ast module."""

    def test_no_subprocess_run_called(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(tmp_path, "code.py", "def foo():\n    bar()\n\ndef bar():\n    pass\n")
        with patch("subprocess.run") as mock_run:
            build_python_call_graph(scan_id="s-no-proc", repo_path=tmp_path)
        mock_run.assert_not_called()


class TestPythonCallGraphMultipleFiles:
    def test_edges_across_multiple_files(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(tmp_path, "a.py", "def caller():\n    callee()\n")
        _write_py(tmp_path, "b.py", "def callee():\n    pass\n")
        result = build_python_call_graph(scan_id="s-multi-file", repo_path=tmp_path)
        # At minimum, edges within a.py caller→callee should be found
        callers = {e.caller_function for e in result.edges}
        assert "caller" in callers

    def test_syntax_error_in_one_file_does_not_crash(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        _write_py(tmp_path, "good.py", "def ok():\n    pass\n")
        _write_py(tmp_path, "bad.py", "def broken(:\n    pass\n")  # syntax error
        # Must not raise
        result = build_python_call_graph(scan_id="s-syntax-err", repo_path=tmp_path)
        assert isinstance(result, CallGraph)

    def test_vendor_directory_skipped(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_python import build_python_call_graph

        vendor = tmp_path / "vendor"
        vendor.mkdir()
        _write_py(vendor, "dep.py", "def vendor_fn():\n    pass\n")
        _write_py(tmp_path, "src.py", "def app_fn():\n    pass\n")
        result = build_python_call_graph(scan_id="s-vendor", repo_path=tmp_path)
        fn_names = {e.caller_function for e in result.edges} | {
            ep.function for ep in result.entry_points
        }
        # vendor functions should not appear in the graph
        assert "vendor_fn" not in fn_names


# ===========================================================================
# SCIP backend
# ===========================================================================


class TestBuildScipCallGraphModule:
    def test_module_importable(self) -> None:
        from quarry_tools import (
            call_graph_scip,  # noqa: F401  # pyright: ignore[reportUnusedImport]
        )

    def test_build_function_importable(self) -> None:
        from quarry_tools.call_graph_scip import build_scip_call_graph

        assert callable(build_scip_call_graph)


class TestScipCallGraphReturnType:
    def test_returns_call_graph_instance(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import build_scip_call_graph

        result = build_scip_call_graph(scan_id="s-scip-1", repo_path=tmp_path, language="go")
        assert isinstance(result, CallGraph)

    def test_index_kind_is_scip(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import build_scip_call_graph

        result = build_scip_call_graph(scan_id="s-scip-kind", repo_path=tmp_path, language="go")
        assert result.index_kind == "scip"

    def test_scan_id_propagated(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import build_scip_call_graph

        result = build_scip_call_graph(scan_id="scan-scip-abc", repo_path=tmp_path, language="go")
        assert result.scan_id == "scan-scip-abc"


class TestScipGracefulFallback:
    def test_returns_empty_graph_when_binary_absent(self, tmp_path: Path) -> None:
        """When the SCIP indexer binary is not present, return an empty graph (no crash)."""
        from unittest.mock import patch

        from quarry_tools.call_graph_scip import build_scip_call_graph

        # Force FileNotFoundError as if the binary doesn't exist
        with patch("subprocess.run", side_effect=FileNotFoundError("scip-go not found")):
            result = build_scip_call_graph(scan_id="s-no-bin", repo_path=tmp_path, language="go")

        assert isinstance(result, CallGraph)
        assert result.index_kind == "scip"
        assert result.edges == []

    def test_returns_empty_graph_on_indexer_timeout(self, tmp_path: Path) -> None:
        from subprocess import TimeoutExpired
        from unittest.mock import patch

        from quarry_tools.call_graph_scip import build_scip_call_graph

        with patch("subprocess.run", side_effect=TimeoutExpired(cmd="scip-go", timeout=60)):
            result = build_scip_call_graph(scan_id="s-timeout", repo_path=tmp_path, language="go")

        assert isinstance(result, CallGraph)
        assert result.edges == []

    def test_returns_empty_graph_on_nonzero_exit(self, tmp_path: Path) -> None:
        from subprocess import CompletedProcess
        from unittest.mock import patch

        from quarry_tools.call_graph_scip import build_scip_call_graph

        with patch(
            "subprocess.run",
            return_value=CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"error"),
        ):
            result = build_scip_call_graph(scan_id="s-fail", repo_path=tmp_path, language="go")

        assert isinstance(result, CallGraph)
        assert result.edges == []

    def test_is_available_returns_bool(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import is_scip_available

        result = is_scip_available("go")
        assert isinstance(result, bool)

    def test_is_available_false_when_binary_absent(self) -> None:
        from unittest.mock import patch

        from quarry_tools.call_graph_scip import is_scip_available

        with patch("shutil.which", return_value=None):
            assert is_scip_available("go") is False

    def test_is_available_true_when_binary_present(self) -> None:
        from unittest.mock import patch

        from quarry_tools.call_graph_scip import is_scip_available

        with patch("shutil.which", return_value="/usr/local/bin/scip-go"):
            assert is_scip_available("go") is True


class TestScipSupportedLanguages:
    @pytest.mark.parametrize("lang", ["go", "typescript", "java", "rust"])
    def test_supported_language_does_not_raise(self, tmp_path: Path, lang: str) -> None:
        from unittest.mock import patch

        from quarry_tools.call_graph_scip import build_scip_call_graph

        with patch("subprocess.run", side_effect=FileNotFoundError("no binary")):
            result = build_scip_call_graph(scan_id="s-lang", repo_path=tmp_path, language=lang)
        assert result.index_kind == "scip"

    def test_unsupported_language_raises_value_error(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import build_scip_call_graph

        with pytest.raises(ValueError, match="unsupported"):
            build_scip_call_graph(scan_id="s-bad-lang", repo_path=tmp_path, language="cobol")


_SCIP_FIXTURE = Path(__file__).parent.parent / "fixtures" / "scip" / "go_simple.scip"


class TestScipIndexParser:
    def test_parse_returns_call_graph(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-parse-1", "test-repo")
        assert isinstance(result, CallGraph)

    def test_parse_index_kind_is_scip(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-parse-2", "test-repo")
        assert result.index_kind == "scip"

    def test_parse_scan_id_propagated(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-parse-xyz", "test-repo")
        assert result.scan_id == "scan-parse-xyz"

    def test_parse_edges_non_none(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-parse-3", "test-repo")
        assert result.edges is not None

    def test_parse_entry_points_non_none(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-parse-4", "test-repo")
        assert result.entry_points is not None

    def test_parse_missing_file_returns_empty_graph(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        missing = tmp_path / "nonexistent.scip"
        result = parse_scip_index(missing, "scan-missing", "test-repo")
        assert isinstance(result, CallGraph)
        assert result.index_kind == "scip"
        assert result.edges == []

    def test_parse_empty_file_returns_empty_graph(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        empty = tmp_path / "empty.scip"
        empty.write_bytes(b"")
        result = parse_scip_index(empty, "scan-empty", "test-repo")
        assert isinstance(result, CallGraph)
        assert result.edges == []

    def test_parse_invalid_proto_returns_empty_graph(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        bad = tmp_path / "bad.scip"
        bad.write_bytes(b"not valid protobuf data")
        result = parse_scip_index(bad, "scan-bad", "test-repo")
        assert isinstance(result, CallGraph)
        assert result.edges == []


class TestScipEdgeExtraction:
    def test_edges_not_empty_for_go_simple_fixture(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-edges-1", "test-repo")
        assert result.edges, "go_simple.scip should yield at least one CallEdge"

    def test_edge_has_main_caller_and_fetchuser_callee(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-edges-2", "test-repo")
        matches = [
            e
            for e in result.edges
            if e.caller_function == "main" and e.callee_function == "fetchUser"
        ]
        assert matches, f"Expected CallEdge main->fetchUser; got: {result.edges}"

    def test_edges_are_call_edge_instances(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-edges-3", "test-repo")
        assert result.edges
        for edge in result.edges:
            assert isinstance(edge, CallEdge)

    def test_index_kind_is_scip(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-edges-4", "test-repo")
        assert result.index_kind == "scip"

    def test_edge_fields_populated(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-edges-5", "test-repo")
        assert result.edges
        edge = result.edges[0]
        assert edge.caller_repo != ""
        assert edge.caller_file != ""
        assert edge.caller_function != ""
        assert edge.callee_repo != ""
        assert edge.callee_file != ""
        assert edge.callee_function != ""

    def test_graceful_fallback_empty_file_still_empty_edges(self, tmp_path: Path) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        empty = tmp_path / "empty.scip"
        empty.write_bytes(b"")
        result = parse_scip_index(empty, "scan-edges-empty", "test-repo")
        assert result.edges == []


class TestScipEntryPointDetection:
    def test_entry_points_not_empty_for_go_simple_fixture(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-ep-1", "test-repo")
        assert result.entry_points, (
            f"go_simple.scip should yield at least one EntryPoint; got: {result.entry_points}"
        )

    def test_main_symbol_yields_main_entry_point(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-ep-2", "test-repo")
        main_eps = [ep for ep in result.entry_points if ep.kind == "main" and ep.function == "main"]
        assert main_eps, (
            f"Expected EntryPoint(kind='main', function='main'); got: {result.entry_points}"
        )

    def test_entry_points_are_entry_point_instances(self) -> None:
        from quarry_tools.call_graph_scip import parse_scip_index

        result = parse_scip_index(_SCIP_FIXTURE, "scan-ep-3", "test-repo")
        assert result.entry_points
        for ep in result.entry_points:
            assert isinstance(ep, EntryPoint)

    def test_http_handler_symbol_yields_http_handler_entry_point(self, tmp_path: Path) -> None:
        from quarry_tools import scip_pb2
        from quarry_tools.call_graph_scip import parse_scip_index

        serve_sym = scip_pb2.SymbolInformation(
            symbol="go . main/handler.ServeHTTP().", display_name="ServeHTTP"
        )
        def_occ = scip_pb2.Occurrence(symbol="go . main/handler.ServeHTTP().", symbol_roles=1)
        def_occ.range.extend([0, 0, 0, 9])
        doc = scip_pb2.Document(relative_path="server.go", language="go")
        doc.symbols.append(serve_sym)
        doc.occurrences.append(def_occ)
        index = scip_pb2.Index()
        index.documents.append(doc)
        fixture = tmp_path / "serve.scip"
        fixture.write_bytes(index.SerializeToString())
        result = parse_scip_index(fixture, "scan-ep-http", "test-repo")
        http_eps = [ep for ep in result.entry_points if ep.kind == "http_handler"]
        assert http_eps, f"Expected http_handler entry point; got: {result.entry_points}"
