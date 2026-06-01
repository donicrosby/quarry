from quarry.schemas import (
    ChangedFile,
    DiffLabel,
    DiffScanInput,
    DiffScanResult,
    GitDiff,
    ImpactedCodeRegion,
)


def test_diff_label_enum_values() -> None:
    assert DiffLabel.INTRODUCED_BY_DIFF.value == "introduced_by_diff"
    assert DiffLabel.TOUCHED_BY_DIFF.value == "touched_by_diff"
    assert DiffLabel.POSSIBLY_EXPOSED_BY_DIFF.value == "possibly_exposed_by_diff"
    assert DiffLabel.UNCHANGED.value == "unchanged"


def test_diff_label_from_string() -> None:
    assert DiffLabel("introduced_by_diff") is DiffLabel.INTRODUCED_BY_DIFF
    assert DiffLabel("touched_by_diff") is DiffLabel.TOUCHED_BY_DIFF
    assert DiffLabel("possibly_exposed_by_diff") is DiffLabel.POSSIBLY_EXPOSED_BY_DIFF
    assert DiffLabel("unchanged") is DiffLabel.UNCHANGED


def test_changed_file_minimal() -> None:
    changed_file = ChangedFile(path="app.py", status="modified")

    assert changed_file.path == "app.py"
    assert changed_file.status == "modified"
    assert changed_file.additions == 0
    assert changed_file.deletions == 0
    assert changed_file.hunks == []


def test_changed_file_with_all_fields() -> None:
    changed_file = ChangedFile(
        path="app.py",
        status="modified",
        additions=10,
        deletions=5,
        hunks=["@@ -10,5 +10,10 @@ def handler():"],
    )

    assert changed_file.path == "app.py"
    assert changed_file.status == "modified"
    assert changed_file.additions == 10
    assert changed_file.deletions == 5
    assert len(changed_file.hunks) == 1
    assert changed_file.hunks[0] == "@@ -10,5 +10,10 @@ def handler():"


def test_changed_file_serialization_round_trip() -> None:
    changed_file = ChangedFile(
        path="app.py",
        status="modified",
        additions=10,
        deletions=5,
        hunks=["@@ -10,5 +10,10 @@"],
    )

    loaded = ChangedFile.model_validate_json(changed_file.model_dump_json())

    assert loaded.path == "app.py"
    assert loaded.status == "modified"
    assert loaded.additions == 10
    assert loaded.deletions == 5
    assert loaded.hunks == ["@@ -10,5 +10,10 @@"]


def test_impacted_code_region_minimal() -> None:
    region = ImpactedCodeRegion(
        file_path="app.py",
        start_line=10,
        end_line=20,
        label=DiffLabel.INTRODUCED_BY_DIFF,
    )

    assert region.file_path == "app.py"
    assert region.start_line == 10
    assert region.end_line == 20
    assert region.scope_name is None
    assert region.scope_type is None
    assert region.label is DiffLabel.INTRODUCED_BY_DIFF


def test_impacted_code_region_with_scope() -> None:
    region = ImpactedCodeRegion(
        file_path="app.py",
        start_line=10,
        end_line=20,
        scope_name="read_user",
        scope_type="function",
        label=DiffLabel.TOUCHED_BY_DIFF,
    )

    assert region.file_path == "app.py"
    assert region.start_line == 10
    assert region.end_line == 20
    assert region.scope_name == "read_user"
    assert region.scope_type == "function"
    assert region.label is DiffLabel.TOUCHED_BY_DIFF


def test_impacted_code_region_serialization_round_trip() -> None:
    region = ImpactedCodeRegion(
        file_path="app.py",
        start_line=10,
        end_line=20,
        scope_name="read_user",
        scope_type="function",
        label=DiffLabel.POSSIBLY_EXPOSED_BY_DIFF,
    )

    loaded = ImpactedCodeRegion.model_validate_json(region.model_dump_json())

    assert loaded.file_path == "app.py"
    assert loaded.start_line == 10
    assert loaded.end_line == 20
    assert loaded.scope_name == "read_user"
    assert loaded.scope_type == "function"
    assert loaded.label is DiffLabel.POSSIBLY_EXPOSED_BY_DIFF


def test_git_diff_minimal() -> None:
    git_diff = GitDiff(base_commit="abc123", head_commit="def456")

    assert git_diff.base_commit == "abc123"
    assert git_diff.head_commit == "def456"
    assert git_diff.changed_files == []
    assert git_diff.total_additions == 0
    assert git_diff.total_deletions == 0


def test_git_diff_with_changed_files() -> None:
    git_diff = GitDiff(
        base_commit="abc123",
        head_commit="def456",
        changed_files=[
            ChangedFile(path="app.py", status="modified", additions=10, deletions=5),
            ChangedFile(path="new_file.py", status="added", additions=50, deletions=0),
        ],
        total_additions=60,
        total_deletions=5,
    )

    assert git_diff.base_commit == "abc123"
    assert git_diff.head_commit == "def456"
    assert len(git_diff.changed_files) == 2
    assert git_diff.changed_files[0].path == "app.py"
    assert git_diff.changed_files[0].status == "modified"
    assert git_diff.changed_files[1].path == "new_file.py"
    assert git_diff.changed_files[1].status == "added"
    assert git_diff.total_additions == 60
    assert git_diff.total_deletions == 5


def test_git_diff_serialization_round_trip() -> None:
    git_diff = GitDiff(
        base_commit="abc123",
        head_commit="def456",
        changed_files=[
            ChangedFile(path="app.py", status="modified", additions=10, deletions=5),
        ],
        total_additions=10,
        total_deletions=5,
    )

    loaded = GitDiff.model_validate_json(git_diff.model_dump_json())

    assert loaded.base_commit == "abc123"
    assert loaded.head_commit == "def456"
    assert len(loaded.changed_files) == 1
    assert loaded.changed_files[0].path == "app.py"
    assert loaded.total_additions == 10
    assert loaded.total_deletions == 5


def test_diff_scan_input_minimal() -> None:
    scan_input = DiffScanInput(
        repo_path="/path/to/repo",
        base_commit="abc123",
        head_commit="def456",
        db_path="/path/to/db.sqlite",
    )

    assert scan_input.repo_path == "/path/to/repo"
    assert scan_input.base_commit == "abc123"
    assert scan_input.head_commit == "def456"
    assert scan_input.db_path == "/path/to/db.sqlite"
    assert scan_input.target_url is None


def test_diff_scan_input_with_target() -> None:
    scan_input = DiffScanInput(
        repo_path="/path/to/repo",
        base_commit="abc123",
        head_commit="def456",
        db_path="/path/to/db.sqlite",
        target_url="http://localhost:8000",
    )

    assert scan_input.repo_path == "/path/to/repo"
    assert scan_input.base_commit == "abc123"
    assert scan_input.head_commit == "def456"
    assert scan_input.db_path == "/path/to/db.sqlite"
    assert scan_input.target_url == "http://localhost:8000"


def test_diff_scan_input_serialization_round_trip() -> None:
    scan_input = DiffScanInput(
        repo_path="/path/to/repo",
        base_commit="abc123",
        head_commit="def456",
        db_path="/path/to/db.sqlite",
        target_url="http://localhost:8000",
    )

    loaded = DiffScanInput.model_validate_json(scan_input.model_dump_json())

    assert loaded.repo_path == "/path/to/repo"
    assert loaded.base_commit == "abc123"
    assert loaded.head_commit == "def456"
    assert loaded.db_path == "/path/to/db.sqlite"
    assert loaded.target_url == "http://localhost:8000"


def test_diff_scan_result_minimal() -> None:
    git_diff = GitDiff(base_commit="abc123", head_commit="def456")
    result = DiffScanResult(scan_id="scan-1", git_diff=git_diff)

    assert result.scan_id == "scan-1"
    assert result.git_diff.base_commit == "abc123"
    assert result.git_diff.head_commit == "def456"
    assert result.impacted_regions == []
    assert result.candidate_finding_count == 0
    assert result.final_finding_count == 0


def test_diff_scan_result_with_regions() -> None:
    git_diff = GitDiff(base_commit="abc123", head_commit="def456")
    impacted_regions = [
        ImpactedCodeRegion(
            file_path="app.py",
            start_line=10,
            end_line=20,
            scope_name="read_user",
            scope_type="function",
            label=DiffLabel.INTRODUCED_BY_DIFF,
        ),
    ]
    result = DiffScanResult(
        scan_id="scan-1",
        git_diff=git_diff,
        impacted_regions=impacted_regions,
        candidate_finding_count=1,
        final_finding_count=0,
    )

    assert result.scan_id == "scan-1"
    assert len(result.impacted_regions) == 1
    assert result.impacted_regions[0].file_path == "app.py"
    assert result.impacted_regions[0].label is DiffLabel.INTRODUCED_BY_DIFF
    assert result.candidate_finding_count == 1
    assert result.final_finding_count == 0


def test_diff_scan_result_serialization_round_trip() -> None:
    git_diff = GitDiff(
        base_commit="abc123",
        head_commit="def456",
        changed_files=[
            ChangedFile(path="app.py", status="modified", additions=10, deletions=5),
        ],
        total_additions=10,
        total_deletions=5,
    )
    impacted_regions = [
        ImpactedCodeRegion(
            file_path="app.py",
            start_line=10,
            end_line=20,
            scope_name="read_user",
            scope_type="function",
            label=DiffLabel.INTRODUCED_BY_DIFF,
        ),
    ]
    result = DiffScanResult(
        scan_id="scan-1",
        git_diff=git_diff,
        impacted_regions=impacted_regions,
        candidate_finding_count=1,
        final_finding_count=1,
    )

    loaded = DiffScanResult.model_validate_json(result.model_dump_json())

    assert loaded.scan_id == "scan-1"
    assert len(loaded.impacted_regions) == 1
    assert loaded.impacted_regions[0].file_path == "app.py"
    assert loaded.impacted_regions[0].label is DiffLabel.INTRODUCED_BY_DIFF
    assert loaded.candidate_finding_count == 1
    assert loaded.final_finding_count == 1
