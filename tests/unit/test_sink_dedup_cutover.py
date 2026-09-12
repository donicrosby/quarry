"""Sink-locator dedup cutover (cpc slice 7, task 7.1).

Design D4: fingerprinting/dedup keys on the sink locator + title — the sink
is ``evidence_path[0]`` on the sink-first ordered evidence path. Two findings
with reordered (unordered) ``source_refs`` but the same sink + title are the
same root cause; two findings at different sinks are not, whatever their
legacy ``root_cause_key`` says.

Written RED first.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.fingerprints import compute_sink_dedup_key
from quarry.schemas import (
    CandidateFinding,
    Confidence,
    EvidencePathElement,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_activities.dedup import DedupeResponse, dedup_impl
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 9, 12, tzinfo=UTC)
_SINK = EvidencePathElement(path="app.py", line=78)
_SINK_OTHER_LINE = EvidencePathElement(path="app.py", line=91)
_SINK_OTHER_FILE = EvidencePathElement(path="other.py", line=7)


def _finding(
    finding_id: str,
    *,
    title: str = "SSRF in fetch-local handler",
    evidence_path: list[EvidencePathElement] | None = None,
    source_refs: list[SourceRef] | None = None,
    root_cause_key: str | None = "legacy-key",
) -> CandidateFinding:
    return CandidateFinding(
        id=finding_id,
        scan_id="scan-7",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.SSRF,
        title=title,
        hypothesis="User input reaches an outbound request.",
        source_refs=source_refs if source_refs is not None else [],
        evidence_path=evidence_path if evidence_path is not None else [_SINK],
        root_cause_key=root_cause_key,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        created_by="hunt-agent",
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# compute_sink_dedup_key
# ---------------------------------------------------------------------------


class TestComputeSinkDedupKey:
    def test_key_is_readable_and_stable(self) -> None:
        key = compute_sink_dedup_key(title="SSRF in fetch-local handler", sink_locator="app.py:78")
        assert "app.py:78" in key
        assert key == compute_sink_dedup_key(
            title="SSRF in fetch-local handler", sink_locator="app.py:78"
        )

    def test_title_normalization_is_case_and_whitespace_insensitive(self) -> None:
        key_a = compute_sink_dedup_key(
            title="SSRF in   Fetch-Local Handler", sink_locator="app.py:78"
        )
        key_b = compute_sink_dedup_key(
            title="ssrf in fetch-local handler", sink_locator="app.py:78"
        )
        assert key_a == key_b

    def test_path_separator_normalization(self) -> None:
        key_a = compute_sink_dedup_key(title="t", sink_locator="src\\dao.py:12")
        key_b = compute_sink_dedup_key(title="t", sink_locator="src/dao.py:12")
        assert key_a == key_b

    def test_key_differs_by_sink_line(self) -> None:
        assert compute_sink_dedup_key(
            title="t", sink_locator="app.py:78"
        ) != compute_sink_dedup_key(title="t", sink_locator="app.py:91")

    def test_key_differs_by_title(self) -> None:
        assert compute_sink_dedup_key(
            title="Alpha", sink_locator="app.py:78"
        ) != compute_sink_dedup_key(title="Beta", sink_locator="app.py:78")


# ---------------------------------------------------------------------------
# dedup_impl groups on the sink locator + title
# ---------------------------------------------------------------------------


class TestDedupGroupsOnSinkLocator:
    def test_reordered_source_refs_same_sink_and_title_dedup(self) -> None:
        """Two findings whose unordered source_refs come back in different
        orders — same sink, same title — are one root cause even when their
        legacy root_cause_keys disagree."""
        f1 = _finding(
            "cf-1",
            source_refs=[
                SourceRef(file_path="app.py", start_line=78, end_line=78),
                SourceRef(file_path="routes.py", start_line=12, end_line=12),
            ],
            root_cause_key="legacy-alpha",
        )
        f2 = _finding(
            "cf-2",
            source_refs=[
                SourceRef(file_path="routes.py", start_line=12, end_line=12),
                SourceRef(file_path="app.py", start_line=78, end_line=78),
            ],
            root_cause_key="legacy-beta",
        )
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert len(result) == 1
        assert result[0].id == "cf-1"

    def test_different_sink_lines_never_grouped(self) -> None:
        f1 = _finding("cf-1", evidence_path=[_SINK], root_cause_key="legacy-same")
        f2 = _finding("cf-2", evidence_path=[_SINK_OTHER_LINE], root_cause_key="legacy-same")
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert {f.id for f in result} == {"cf-1", "cf-2"}

    def test_different_sink_files_never_grouped(self) -> None:
        f1 = _finding("cf-1", evidence_path=[_SINK], root_cause_key="legacy-same")
        f2 = _finding("cf-2", evidence_path=[_SINK_OTHER_FILE], root_cause_key="legacy-same")
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert {f.id for f in result} == {"cf-1", "cf-2"}

    def test_distinct_titles_at_same_sink_not_grouped(self) -> None:
        f1 = _finding("cf-1", title="Alpha finding", root_cause_key="legacy-same")
        f2 = _finding("cf-2", title="Beta finding", root_cause_key="legacy-same")
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert {f.id for f in result} == {"cf-1", "cf-2"}

    def test_trailing_path_steps_do_not_change_grouping(self) -> None:
        f1 = _finding(
            "cf-1",
            evidence_path=[
                _SINK,
                EvidencePathElement(path="routes.py", line=12),
                EvidencePathElement(path="main.py", line=3),
            ],
        )
        f2 = _finding(
            "cf-2",
            evidence_path=[
                _SINK,
                EvidencePathElement(path="main.py", line=3),
            ],
        )
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert len(result) == 1
        assert result[0].id == "cf-1"

    def test_sink_key_wins_over_legacy_root_cause_key(self) -> None:
        """Cutover: when the ordered path is populated, grouping ignores the
        legacy root_cause_key entirely."""
        f1 = _finding("cf-1", evidence_path=[_SINK], root_cause_key="legacy-alpha")
        f2 = _finding("cf-2", evidence_path=[_SINK], root_cause_key="legacy-beta")
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert len(result) == 1
        assert result[0].id == "cf-1"

    def test_fallback_to_root_cause_key_without_evidence_path(self) -> None:
        """Back-compat: findings without an ordered path still group on the
        legacy root_cause_key."""
        f1 = _finding("cf-1", evidence_path=[], root_cause_key="legacy-dup", source_refs=[])
        f2 = _finding("cf-2", evidence_path=[], root_cause_key="legacy-dup", source_refs=[])
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert len(result) == 1

    def test_no_key_at_all_stays_singleton(self) -> None:
        f1 = _finding("cf-1", evidence_path=[], root_cause_key=None)
        f2 = _finding("cf-2", evidence_path=[], root_cause_key=None)
        result = dedup_impl(
            candidates=[f1, f2],
            client=MockModelClient(default=DedupeResponse(decision="keep_first")),
        )
        assert {f.id for f in result} == {"cf-1", "cf-2"}
