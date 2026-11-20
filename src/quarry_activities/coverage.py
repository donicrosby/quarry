"""Coverage ledger activity.

Records what a scan actually covered: which vulnerability classes were requested
and completed, how many agentic tasks were scanned versus emitted, and an
honest list of what was skipped and why. The ledger is stored as an artifact and
surfaced in the report so coverage gaps are never hidden.
"""

import json
from contextlib import suppress
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast
from uuid import uuid4

from temporalio import activity

from quarry.schemas import (
    AgentTask,
    ArtifactKind,
    ArtifactRef,
    CandidateFinding,
    CoverageCell,
    CoverageGap,
    CoverageLedger,
    FileManifestEntry,
    ProductionFileAccounting,
    ProductionFileStatus,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.inputs import BuildCoverageLedgerInput, BuildCoverageLedgerOutput
from quarry_artifacts.local import LocalArtifactStore

# ---------------------------------------------------------------------------
# Proactive production-file accounting (candidate-precision-and-calibration).
#
# The production-code boundary classifies every manifest file. Files outside
# the boundary (tests, vendored, generated, build/config/data) are recorded as
# INTENTIONALLY_EXCLUDED with the boundary reason — never silently omitted.
# Everything inside the boundary is a first-party production source file and
# MUST be accounted for as COVERED or surfaced as a GAP.
# ---------------------------------------------------------------------------

TEST_DIR_PARTS = frozenset({"test", "tests", "spec", "specs", "__tests__", "testing"})
TEST_FILE_MARKERS = ("test_", "tests_", "spec_", "conftest")
TEST_FILE_SUFFIXES = (
    "_test.go",
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
    "_spec.rb",
)
VENDORED_PARTS = frozenset({"vendor", "vendors", "node_modules", "third_party", "external"})
GENERATED_NAME_SUFFIXES = (
    ".min.js",
    ".min.css",
    ".map",
    ".lock",
    ".pb.go",
    ".pb.cc",
    ".pb.h",
)
GENERATED_NAME_MARKERS = (".generated.", "_generated.", ".gen.")
PRODUCTION_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".rb",
        ".java",
        ".kt",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".cs",
        ".php",
    }
)

REASON_TEST_CODE = "test code"
REASON_VENDORED = "vendored"
REASON_GENERATED = "generated or build artifact"
REASON_BUILD_CONFIG = "build, config, or data"


def _file_stem(path: PurePosixPath) -> str:
    name = path.name
    for suffix in PRODUCTION_SOURCE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def production_file_classification(path: str) -> ProductionFileAccounting | None:
    """Classify *path* against the production-code boundary.

    Returns ``None`` when the file is a first-party production source file in
    scope (it must then be accounted for as COVERED or GAP), or an
    ``INTENTIONALLY_EXCLUDED`` accounting with the boundary reason when the
    file is excluded (tests, vendored, generated, build/config/data).
    """
    normalized = PurePosixPath(path.replace("\\", "/"))
    name = normalized.name
    name_lower = name.lower()
    stem_lower = _file_stem(normalized).lower()
    parts_lower = frozenset(part.lower() for part in normalized.parts[:-1])

    if (
        parts_lower & TEST_DIR_PARTS
        or stem_lower.startswith(TEST_FILE_MARKERS)
        or stem_lower.endswith(("_test", "_tests", "_spec"))
        or (name_lower.endswith(TEST_FILE_SUFFIXES))
    ):
        return ProductionFileAccounting(
            path=normalized.as_posix(),
            status=ProductionFileStatus.INTENTIONALLY_EXCLUDED,
            reason=REASON_TEST_CODE,
        )
    if parts_lower & VENDORED_PARTS:
        return ProductionFileAccounting(
            path=normalized.as_posix(),
            status=ProductionFileStatus.INTENTIONALLY_EXCLUDED,
            reason=REASON_VENDORED,
        )
    if name_lower.endswith(GENERATED_NAME_SUFFIXES) or any(
        marker in name_lower for marker in GENERATED_NAME_MARKERS
    ):
        return ProductionFileAccounting(
            path=normalized.as_posix(),
            status=ProductionFileStatus.INTENTIONALLY_EXCLUDED,
            reason=REASON_GENERATED,
        )
    if normalized.suffix.lower() not in PRODUCTION_SOURCE_SUFFIXES:
        return ProductionFileAccounting(
            path=normalized.as_posix(),
            status=ProductionFileStatus.INTENTIONALLY_EXCLUDED,
            reason=REASON_BUILD_CONFIG,
        )
    return None


def compute_file_coverage(
    file_manifest: list[FileManifestEntry],
    *,
    covered_files: list[str] | None = None,
    scope_excluded_files: list[tuple[str, str]] | None = None,
    finding_file_paths: list[str] | None = None,
) -> list[ProductionFileAccounting]:
    """Deterministically account for every manifest file exactly once.

    Precedence: scan-scope exclusions (with their recorded reason) win first,
    then the production-code boundary, then investigations — a file is COVERED
    when a *covered_files* investigation targets it directly or targets a
    parent directory, or when a finding cites it (*finding_file_paths* may
    carry ``path:line`` locators). Anything left over is a GAP. The result is
    sorted by path so identical inputs always produce identical output.
    """
    normalized_scope_exclusions: dict[str, str] = {}
    for path, reason in scope_excluded_files or []:
        normalized_scope_exclusions[path.replace("\\", "/").rstrip("/")] = reason

    investigation_paths = [
        p.replace("\\", "/").strip().rstrip("/") for p in (covered_files or []) if p and p.strip()
    ]
    for locator in finding_file_paths or []:
        path = locator.replace("\\", "/").split(":", 1)[0].strip().rstrip("/")
        if path:
            investigation_paths.append(path)

    accounting: list[ProductionFileAccounting] = []
    for entry in file_manifest:
        path = entry.path.replace("\\", "/")
        scope_reason = normalized_scope_exclusions.get(path.rstrip("/"))
        if scope_reason is not None:
            accounting.append(
                ProductionFileAccounting(
                    path=path,
                    status=ProductionFileStatus.INTENTIONALLY_EXCLUDED,
                    reason=scope_reason,
                )
            )
            continue
        boundary = production_file_classification(path)
        if boundary is not None:
            accounting.append(boundary)
            continue
        if any(path == target or path.startswith(f"{target}/") for target in investigation_paths):
            accounting.append(
                ProductionFileAccounting(path=path, status=ProductionFileStatus.COVERED)
            )
            continue
        accounting.append(ProductionFileAccounting(path=path, status=ProductionFileStatus.GAP))

    accounting.sort(key=lambda item: item.path)
    return accounting


# ---------------------------------------------------------------------------
# Tier-aware cell coverage (credibility-economics)
# ---------------------------------------------------------------------------


def finding_counts_toward_coverage(finding: CandidateFinding) -> bool:
    """Whether *finding* marks its coverage cell covered.

    True when the finding is tool-grounded, was corroborated by the cascade, or
    carries a tier-discounted credibility prior at/above the STRONG factor
    (0.9). A low-tier model judgment that nothing corroborated does NOT count —
    that is the write-time gate's whole point.
    """
    from quarry_models.credibility import TIER_THRESHOLD

    return finding.grounded or finding.corroborated or finding.credibility_prior >= TIER_THRESHOLD


def _cell_scope_of(finding: CandidateFinding) -> str:
    """The path component a finding cites, normalised for scope matching."""
    locator = finding.affected_component or ""
    if not locator and finding.evidence_path:
        locator = finding.evidence_path[0].path
    return locator.replace("\\", "/").split(":", 1)[0].strip().strip("/")


def _occupies(scope: str, finding: CandidateFinding) -> bool:
    """Whether *finding* occupies the cell at *scope*.

    A cell with an empty scope is class-wide (every finding of that class
    occupies it); otherwise the finding's cited path must sit at or under the
    scope path.
    """
    if not scope:
        return True
    path = _cell_scope_of(finding)
    if not path:
        return False
    return path == scope or path.startswith(f"{scope}/")


def compute_cell_coverage(
    tasks: list[AgentTask],
    findings: list[CandidateFinding],
    *,
    credibility_enabled: bool,
) -> list[CoverageCell]:
    """Compute ``(scope, vuln_class)`` cell occupancy from tasks and findings.

    Cells come from the hunted tasks (the same ``(scope, vuln_class)`` vocabulary
    gapfill dedupes on); occupants are the findings whose class matches and whose
    cited path sits under the cell's scope. With *credibility_enabled* the
    tier-aware threshold decides coverage and a cell that was already gapfill-
    hunted but is still uncovered is recorded ``terminal_uncovered`` (it gets no
    further gapfill rounds). With the feature disabled every occupant counts, so
    the ledger behaves exactly as it did before this change.

    Deterministic: output is sorted by ``(scope, vuln_class)``.
    """
    cells: dict[tuple[str, VulnerabilityClass], CoverageCell] = {}
    gapfill_hunted: set[tuple[str, VulnerabilityClass]] = set()
    for task in tasks:
        if task.vuln_class is None:
            continue
        scope = (task.scope or "").replace("\\", "/").strip().strip("/")
        key = (scope, task.vuln_class)
        if task.source == "gapfill":
            gapfill_hunted.add(key)
        cells.setdefault(
            key,
            CoverageCell(vuln_class=task.vuln_class, scope=scope, covered=False),
        )

    result: list[CoverageCell] = []
    for key, cell in sorted(cells.items(), key=lambda item: (item[0][0], item[0][1].value)):
        occupants = [f for f in findings if f.vuln_class == cell.vuln_class]
        occupants = [f for f in occupants if _occupies(cell.scope, f)]
        if credibility_enabled:
            counting = [f for f in occupants if finding_counts_toward_coverage(f)]
        else:
            counting = occupants
        covered = bool(counting)
        promotion = any(f.corroborated and not f.grounded for f in counting)
        tier: str | None = None
        if covered and not promotion:
            from quarry_models.credibility import resolve_model_tier

            deciding = next(
                (f for f in counting if f.grounded or f.corroborated),
                None,
            )
            if deciding is None:
                # Coverage came from the tier-discounted prior: record the tier.
                prior_decider = max(counting, key=lambda f: f.credibility_prior)
                tier = resolve_model_tier(prior_decider.originating_model_id).name.lower()
        result.append(
            cell.model_copy(
                update={
                    "covered": covered,
                    "terminal_uncovered": (
                        credibility_enabled and not covered and key in gapfill_hunted
                    ),
                    "occupant_count": len(occupants),
                    "covered_occupants": len(counting),
                    "corroboration_promotion": promotion,
                    "tier": tier,
                }
            )
        )
    return result


def build_coverage_ledger(
    *,
    scan_id: str,
    workspace_id: str,
    requested_vuln_classes: list[VulnerabilityClass] | None = None,
    completed_vuln_classes: list[VulnerabilityClass] | None = None,
    agent_tasks_total: int = 0,
    agent_tasks_scanned: int = 0,
    skipped_items: list[CoverageGap] | None = None,
    file_manifest: list[FileManifestEntry] | None = None,
    covered_files: list[str] | None = None,
    scope_excluded_files: list[tuple[str, str]] | None = None,
    finding_file_paths: list[str] | None = None,
    tasks: list[AgentTask] | None = None,
    findings: list[CandidateFinding] | None = None,
    credibility_enabled: bool = False,
    id: str | None = None,
    created_at: Any = None,
    scan_ordinal: int = 1,
    artifact_version: int = 1,
) -> CoverageLedger:
    """Build a coverage ledger from already-computed scan facts (no I/O).

    *id* and *created_at* may be supplied by workflow code (using
    ``workflow.uuid4()`` / ``workflow.now()``) to stay within the
    Temporal sandbox.  Both default to fresh values when called from
    activity or non-workflow code.

    When *file_manifest* is supplied, the ledger additionally accounts for
    every first-party file in the snapshot: covered (an investigation or a
    finding touches it), intentionally excluded (production-code boundary or
    scan scope, with reason), or gap. See :func:`compute_file_coverage`.

    When *tasks* is supplied, the ledger additionally records tier-aware
    ``(scope, vuln_class)`` cell occupancy from *findings* (see
    :func:`compute_cell_coverage`). Cells are empty for callers that predate the
    credibility economics.
    """
    file_coverage: list[ProductionFileAccounting] = []
    if file_manifest is not None:
        file_coverage = compute_file_coverage(
            file_manifest,
            covered_files=covered_files,
            scope_excluded_files=scope_excluded_files,
            finding_file_paths=finding_file_paths,
        )
    cells: list[CoverageCell] = []
    if tasks is not None:
        cells = compute_cell_coverage(
            tasks,
            findings or [],
            credibility_enabled=credibility_enabled,
        )
    return CoverageLedger(
        id=id if id is not None else str(uuid4()),
        scan_id=scan_id,
        workspace_id=workspace_id,
        agent_tasks_total=agent_tasks_total,
        agent_tasks_scanned=agent_tasks_scanned,
        vuln_classes_requested=requested_vuln_classes or [],
        vuln_classes_completed=completed_vuln_classes or [],
        skipped_items=skipped_items or [],
        cells=cells,
        file_coverage=file_coverage,
        scan_ordinal=scan_ordinal,
        artifact_version=artifact_version,
        created_at=created_at if isinstance(created_at, datetime) else utc_now(),
    )


def write_coverage_artifact(ledger: CoverageLedger, artifact_root: Path | str) -> ArtifactRef:
    """Persist a coverage ledger as a versioned JSON artifact and return its ArtifactRef.

    Routed through ``LocalArtifactStore.put_json`` (versioned-handoff-artifacts
    task 2.1) rather than a direct filesystem write, so every handoff artifact
    shares one write path. The version stamps live inside the ledger payload and
    are mirrored onto the ArtifactRef metadata for cross-scan diffing.
    """
    store = LocalArtifactStore(artifact_root)
    return store.put_json(
        f"{ledger.scan_id}/coverage-{ledger.id}.json",
        ledger,
        kind=ArtifactKind.COVERAGE_LEDGER,
        metadata={
            "scan_ordinal": str(ledger.scan_ordinal),
            "artifact_version": str(ledger.artifact_version),
        },
    )


@activity.defn(name="build-coverage-ledger")
def build_coverage_ledger_activity(
    input: BuildCoverageLedgerInput | dict[str, Any],
) -> BuildCoverageLedgerOutput:
    """Build the coverage ledger, persist it as an artifact, and return both."""
    if isinstance(input, dict):
        input = BuildCoverageLedgerInput(**input)
    ledger = build_coverage_ledger(
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        requested_vuln_classes=[VulnerabilityClass(v) for v in input.requested_vuln_classes],
        completed_vuln_classes=[VulnerabilityClass(v) for v in input.completed_vuln_classes],
        agent_tasks_total=input.agent_tasks_total,
        agent_tasks_scanned=input.agent_tasks_scanned,
        skipped_items=_coverage_gaps_from_json(input.scan_id, input.skipped_json),
        tasks=_agent_tasks_from_json(input.tasks_json),
        findings=_candidate_findings_from_json(input.findings_json),
        credibility_enabled=input.credibility_enabled,
        scan_ordinal=input.scan_ordinal,
        artifact_version=input.artifact_version,
    )
    artifact_ref = write_coverage_artifact(ledger, input.artifact_root)
    return BuildCoverageLedgerOutput(
        ledger_json=ledger.model_dump_json(),
        artifact_ref_json=artifact_ref.model_dump_json(),
    )


def _agent_tasks_from_json(payload: str) -> list[AgentTask]:
    """Parse a serialised AgentTask list, dropping entries that do not validate.

    Model/activity payloads cross the boundary as JSON; a single malformed entry
    must not fail the whole ledger build (the coverage guarantee is about the
    tasks we DID hunt, and the drop is visible as a smaller cell set).
    """
    raw = json.loads(payload)
    if not isinstance(raw, list):
        msg = "tasks_json must encode a JSON array"
        raise TypeError(msg)
    tasks: list[AgentTask] = []
    for entry in cast(list[Any], raw):
        if not isinstance(entry, dict):
            continue
        with suppress(Exception):
            tasks.append(AgentTask.model_validate(entry))
    return tasks


def _candidate_findings_from_json(payload: str) -> list[CandidateFinding]:
    """Parse a serialised CandidateFinding list, dropping entries that do not validate."""
    raw = json.loads(payload)
    if not isinstance(raw, list):
        msg = "findings_json must encode a JSON array"
        raise TypeError(msg)
    findings: list[CandidateFinding] = []
    for entry in cast(list[Any], raw):
        if not isinstance(entry, dict):
            continue
        with suppress(Exception):
            findings.append(CandidateFinding.model_validate(entry))
    return findings


def _coverage_gaps_from_json(scan_id: str, payload: str) -> list[CoverageGap]:
    raw = json.loads(payload)
    if not isinstance(raw, list):
        msg = "skipped_json must encode a JSON array"
        raise TypeError(msg)
    gaps: list[CoverageGap] = []
    for entry in cast(list[Any], raw):
        if not isinstance(entry, dict):
            msg = "each skipped entry must be a JSON object"
            raise TypeError(msg)
        values = cast(dict[str, Any], entry)
        vuln_class_value = values.get("vuln_class")
        gaps.append(
            CoverageGap(
                id=str(uuid4()),
                scan_id=scan_id,
                scope_unit_id=_optional_str(values.get("scope_unit_id")),
                vuln_class=_coerce_vuln_class(vuln_class_value),
                reason=_required_str(values, "reason"),
                recommended_next_task=_optional_str(values.get("recommended_next_task")),
                severity_hint=_optional_str(values.get("severity_hint")),
            )
        )
    return gaps


def _coerce_vuln_class(value: Any) -> VulnerabilityClass | None:
    """Coerce a raw JSON value to VulnerabilityClass, returning None when absent or unknown.

    Skipped-entry payloads may carry an empty string for class-neutral agent tasks
    (e.g. exploratory gapfill); unknown strings are dropped rather than crashing
    the activity, keeping model-derived data deny-by-default.
    """
    if not isinstance(value, str) or not value:
        return None
    with suppress(ValueError):
        return VulnerabilityClass(value)
    return None


def _required_str(values: dict[str, Any], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise TypeError(msg)
    return value


def _optional_str(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    msg = "value must be a string or None"
    raise TypeError(msg)
