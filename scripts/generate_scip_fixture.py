"""One-time generator for tests/fixtures/scip/go_simple.scip.

Creates a minimal synthetic SCIP Index proto representing a tiny Go program:
  - one document 'main.go'
  - two SymbolInformation entries ('main' and 'fetchUser')
  - one Occurrence showing 'main' calling 'fetchUser' (reference role)

Run once to regenerate the fixture:
    uv run python scripts/generate_scip_fixture.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from quarry_tools import scip_pb2  # noqa: E402

DEFINITION = 1
REFERENCE = 0


def main() -> None:
    out_path = ROOT / "tests" / "fixtures" / "scip" / "go_simple.scip"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    main_sym = scip_pb2.SymbolInformation(
        symbol="go . main/main.",
        display_name="main",
    )
    fetch_sym = scip_pb2.SymbolInformation(
        symbol="go . main/fetchUser().",
        display_name="fetchUser",
    )

    def_main = scip_pb2.Occurrence(
        symbol="go . main/main.",
        symbol_roles=DEFINITION,
    )
    def_main.range.extend([0, 5, 0, 9])

    ref_fetch = scip_pb2.Occurrence(
        symbol="go . main/fetchUser().",
        symbol_roles=REFERENCE,
    )
    ref_fetch.range.extend([1, 1, 1, 10])

    doc = scip_pb2.Document(relative_path="main.go", language="go")
    doc.symbols.append(main_sym)
    doc.symbols.append(fetch_sym)
    doc.occurrences.append(def_main)
    doc.occurrences.append(ref_fetch)

    index = scip_pb2.Index()
    index.documents.append(doc)

    out_path.write_bytes(index.SerializeToString())
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
