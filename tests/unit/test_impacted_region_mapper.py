"""Tests for impacted region mapping activity."""

from typing import cast

from quarry.schemas import ChangedFile, DiffLabel, ImpactedCodeRegion
from quarry_activities.inputs import MapRegionsInput
from quarry_activities.mapper import map_impacted_regions


def test_map_impacted_regions_maps_modified_python_file_with_multiple_hunks() -> None:
    result = map_impacted_regions(
        MapRegionsInput(
            changed_files=(
                ChangedFile(
                    path="src/app.py",
                    status="modified",
                    additions=4,
                    deletions=3,
                    hunks=["@@ -1,3 +1,5 @@", "@@ -10,3 +15,4 @@"],
                ),
            )
        )
    )

    regions = _regions(result)

    assert regions == [
        {
            "file_path": "src/app.py",
            "start_line": 1,
            "end_line": 5,
            "label": "introduced_by_diff",
            "scope_name": None,
            "scope_type": None,
            "language": "python",
            "change_type": "modified",
        },
        {
            "file_path": "src/app.py",
            "start_line": 15,
            "end_line": 18,
            "label": "introduced_by_diff",
            "scope_name": None,
            "scope_type": None,
            "language": "python",
            "change_type": "modified",
        },
    ]
    assert ImpactedCodeRegion.model_validate(regions[0]).label is DiffLabel.INTRODUCED_BY_DIFF


def test_map_impacted_regions_preserves_added_change_type() -> None:
    result = map_impacted_regions(
        {
            "changed_files": [
                {
                    "path": "web/app.tsx",
                    "status": "added",
                    "additions": 2,
                    "deletions": 0,
                    "hunks": ["@@ -0,0 +1,2 @@"],
                }
            ]
        }
    )

    regions = _regions(result)

    assert len(regions) == 1
    assert regions[0]["change_type"] == "added"
    assert regions[0]["language"] == "typescript"
    assert regions[0]["label"] == "introduced_by_diff"


def test_map_impacted_regions_maps_deleted_file_to_removed_old_range() -> None:
    result = map_impacted_regions(
        MapRegionsInput(
            changed_files=(
                ChangedFile(
                    path="obsolete.js",
                    status="deleted",
                    additions=0,
                    deletions=3,
                    hunks=["@@ -7,3 +0,0 @@"],
                ),
            )
        )
    )

    regions = _regions(result)

    assert len(regions) == 1
    assert regions[0]["file_path"] == "obsolete.js"
    assert regions[0]["start_line"] == 7
    assert regions[0]["end_line"] == 9
    assert regions[0]["language"] == "javascript"
    assert regions[0]["change_type"] == "deleted"
    assert regions[0]["label"] == "touched_by_diff"


def test_map_impacted_regions_filters_non_scannable_files() -> None:
    result = map_impacted_regions(
        MapRegionsInput(
            changed_files=(
                ChangedFile(path="src/app.go", status="modified", hunks=["@@ -1 +1,2 @@"]),
                ChangedFile(
                    path="node_modules/pkg/index.js", status="modified", hunks=["@@ -1 +1 @@"]
                ),
                ChangedFile(path="assets/logo.png", status="modified", hunks=["@@ -1 +1 @@"]),
                ChangedFile(path="dist/app.min.js", status="modified", hunks=["@@ -1 +1 @@"]),
                ChangedFile(path="package-lock.json", status="modified", hunks=["@@ -1 +1 @@"]),
            )
        )
    )

    regions = _regions(result)

    assert len(regions) == 1
    assert regions[0]["file_path"] == "src/app.go"
    assert regions[0]["language"] == "go"


def test_map_impacted_regions_maps_single_line_hunk() -> None:
    result = map_impacted_regions(
        MapRegionsInput(
            changed_files=(
                ChangedFile(path="lib/main.rs", status="modified", hunks=["@@ -1 +1 @@"]),
            )
        )
    )

    regions = _regions(result)

    assert len(regions) == 1
    assert regions[0]["start_line"] == 1
    assert regions[0]["end_line"] == 1
    assert regions[0]["language"] == "rust"


def test_map_impacted_regions_returns_empty_regions_for_empty_changed_files() -> None:
    result = map_impacted_regions(MapRegionsInput(changed_files=()))

    assert _regions(result) == []


def _regions(result: dict[str, object]) -> list[dict[str, object]]:
    regions = result["regions"]
    assert isinstance(regions, list)
    region_objects = cast(list[object], regions)
    for region in region_objects:
        assert isinstance(region, dict)
    return cast(list[dict[str, object]], region_objects)
