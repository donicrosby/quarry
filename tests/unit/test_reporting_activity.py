from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    ModelInvocation,
    Scan,
    ScanStatus,
    local_scan_profile,
)
from quarry_activities.reporting import render_markdown_report, summarize_model_cost


def test_render_markdown_report_has_activity_decorator() -> None:
    """Test that render_markdown_report has the Temporal activity decorator."""
    import inspect

    sig = inspect.signature(render_markdown_report)
    params = list(sig.parameters.keys())
    assert "scan" in params
    assert "findings" in params
    assert "snapshot" in params
    assert "attack_surface" in params
    assert "final_findings" in params


def test_render_markdown_report_directly_callable() -> None:
    """Test backward compatibility - function still works when called directly."""
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-test-1",
        workspace_id="local",
        target_id="target-test-1",
        requested_by="test-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )
    findings: list[CandidateFinding] = []

    # Should work as a regular function call
    report = render_markdown_report(scan, findings)

    assert isinstance(report, str)
    assert "Quarry Scan Report" in report
    assert "scan-test-1" in report


def test_render_markdown_report_with_minimal_fixture() -> None:
    """Test with minimal Scan + empty findings fixture."""
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-minimal",
        workspace_id="local",
        target_id="target-minimal",
        requested_by="test-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=now,
    )
    findings: list[CandidateFinding] = []

    report = render_markdown_report(scan, findings)

    # Verify basic structure
    assert "# Quarry Scan Report" in report
    assert "Scan: `scan-minimal`" in report
    assert "Status: `created`" in report
    assert "Profile: `local-fast`" in report
    assert "## Summary" in report
    assert "Quarry produced 0 validated finding(s)" in report
    assert "0 candidate finding(s)" in report
    assert "## Attack surface" in report
    assert "No routes mapped" in report
    assert "## Candidate findings" in report
    assert "No candidate findings recorded" in report


# ---------------------------------------------------------------------------
# Cost & usage (#20)
# ---------------------------------------------------------------------------


def _invocation(
    role: str = "hunt",
    model: str = "chutes/Qwen3-32B",
    ti: int = 100,
    to: int = 20,
    cost: float | None = 0.01,
) -> ModelInvocation:
    return ModelInvocation(
        id="mi-" + role + model + str(ti),
        scan_id="scan-1",
        workspace_id="local",
        task_name=f"{role}-task",
        role=role,
        provider="litellm",
        model=model,
        token_input=ti,
        token_output=to,
        estimated_cost=cost,
        created_at=datetime(2026, 6, 10, tzinfo=UTC),
    )


def test_summarize_model_cost_totals_and_breakdown() -> None:
    invs = [
        _invocation(role="hunt", ti=100, to=20, cost=0.01),
        _invocation(role="hunt", ti=200, to=30, cost=0.02),
        _invocation(role="validate", model="chutes/Kimi", ti=50, to=10, cost=None),
    ]
    s = summarize_model_cost(invs)
    assert s["calls"] == 3
    assert s["total_input_tokens"] == 350
    assert s["total_output_tokens"] == 60
    total_cost = s["total_cost"]
    assert total_cost is not None
    assert abs(total_cost - 0.03) < 1e-9
    # one row per (role, model)
    assert len(s["rows"]) == 2


def test_summarize_model_cost_tokens_only_when_unpriced() -> None:
    invs = [_invocation(cost=None), _invocation(role="validate", cost=None)]
    s = summarize_model_cost(invs)
    assert s["total_cost"] is None  # nothing priced → tokens-only
    assert s["total_input_tokens"] > 0


def test_report_renders_cost_and_usage_section() -> None:
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-cost",
        workspace_id="local",
        target_id="t-cost",
        requested_by="test",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )
    report = render_markdown_report(
        scan,
        [],
        model_invocations=[_invocation(cost=0.0123)],
    )
    assert "## Cost & usage" in report
    assert "0.0123" in report or "$0.01" in report


def test_report_cost_section_tokens_only_fallback() -> None:
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-cost2",
        workspace_id="local",
        target_id="t-cost2",
        requested_by="test",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )
    report = render_markdown_report(scan, [], model_invocations=[_invocation(cost=None)])
    assert "## Cost & usage" in report
    assert "tokens only" in report.lower()


def test_report_omits_cost_section_without_invocations() -> None:
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-nocost",
        workspace_id="local",
        target_id="t-nocost",
        requested_by="test",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )
    report = render_markdown_report(scan, [])
    assert "## Cost & usage" not in report
