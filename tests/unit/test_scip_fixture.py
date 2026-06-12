"""TDD tests for tests/fixtures/scip/go_simple.scip (US-001).

Verifies that the synthetic SCIP fixture can be deserialized with the
quarry_tools.scip_pb2 bindings and contains the expected structure.
"""

from __future__ import annotations

from pathlib import Path

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "scip" / "go_simple.scip"


class TestScipFixtureExists:
    def test_fixture_file_exists(self) -> None:
        assert FIXTURE_PATH.exists(), f"fixture not found: {FIXTURE_PATH}"

    def test_fixture_is_non_empty(self) -> None:
        assert FIXTURE_PATH.stat().st_size > 0


class TestScipFixtureDeserializes:
    def test_deserializes_as_index(self) -> None:
        from quarry_tools.scip_pb2 import Index

        data = FIXTURE_PATH.read_bytes()
        index = Index()
        index.ParseFromString(data)
        assert isinstance(index, Index)

    def test_contains_exactly_one_document(self) -> None:
        from quarry_tools.scip_pb2 import Index

        data = FIXTURE_PATH.read_bytes()
        index = Index()
        index.ParseFromString(data)
        assert len(index.documents) == 1

    def test_document_relative_path_is_main_go(self) -> None:
        from quarry_tools.scip_pb2 import Index

        data = FIXTURE_PATH.read_bytes()
        index = Index()
        index.ParseFromString(data)
        assert index.documents[0].relative_path == "main.go"

    def test_document_has_two_symbols(self) -> None:
        from quarry_tools.scip_pb2 import Index

        data = FIXTURE_PATH.read_bytes()
        index = Index()
        index.ParseFromString(data)
        doc = index.documents[0]
        assert len(doc.symbols) == 2

    def test_symbols_include_main_and_fetch_user(self) -> None:
        from quarry_tools.scip_pb2 import Index

        data = FIXTURE_PATH.read_bytes()
        index = Index()
        index.ParseFromString(data)
        doc = index.documents[0]
        display_names = {sym.display_name for sym in doc.symbols}
        assert "main" in display_names
        assert "fetchUser" in display_names

    def test_document_has_reference_occurrence(self) -> None:
        from quarry_tools.scip_pb2 import Index

        data = FIXTURE_PATH.read_bytes()
        index = Index()
        index.ParseFromString(data)
        doc = index.documents[0]
        assert len(doc.occurrences) >= 1
        fetch_refs = [
            occ for occ in doc.occurrences if "fetchUser" in occ.symbol and occ.symbol_roles == 0
        ]
        assert fetch_refs, "expected at least one reference occurrence for fetchUser"
