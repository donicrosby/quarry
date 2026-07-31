import json
from hashlib import sha256
from pathlib import Path
from typing import TypedDict
from uuid import uuid4

from jinja2 import Template
from temporalio import activity

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    AttackSurfaceItem,
    CandidateFinding,
    CoverageLedger,
    FinalFinding,
    ModelInvocation,
    ProofArtifact,
    RedactionStatus,
    RepositorySnapshot,
    Scan,
    ScanManifest,
    utc_now,
)
from quarry_activities.inputs import RenderReportInput, RenderReportOutput

REPORT_TEMPLATE = Template(
    """# Quarry Scan Report

Scan: `{{ scan.id }}`

Status: `{{ scan.status.value }}`

Profile: `{{ scan.profile.id }}`

## Summary

{{ summary }}

{% if snapshot -%}
## Repository snapshot

- Files: `{{ snapshot.file_count }}`
- Total bytes: `{{ snapshot.total_size_bytes }}`
- Frameworks: `{{ snapshot.detected_frameworks | join(", ") or "unknown" }}`
- Manifest: `{{ snapshot.file_manifest_ref.uri }}`

{% endif -%}

## Attack surface

{% if attack_surface -%}
| Method | Route | Handler | Parameters |
|--------|-------|---------|------------|
{% for item in attack_surface -%}
{% set param_str = item.params | join(", ") or "-" %}
| {{ item.method }} | `{{ item.route }}` | {{ item.handler_symbol or "unknown" }} | {{ param_str }}|
{% endfor %}
{% else -%}
No routes mapped.
{% endif %}

{% if coverage -%}
{% set scanned = coverage.attack_surface_items_scanned -%}
{% set total = coverage.attack_surface_items_total -%}
## Coverage

- Vuln classes requested: `{{ coverage.vuln_classes_requested | join(", ") or "none" }}`
- Vuln classes completed: `{{ coverage.vuln_classes_completed | join(", ") or "none" }}`
- Attack surface items scanned: `{{ scanned }}` of `{{ total }}`
{% if coverage_stop_reason -%}
{% if coverage_stop_reason == "finding_plateau" -%}
- Loop stopped early: **finding plateau** — a round's new findings fell below the
  rising yield bar, so further rounds were not worth their cost.
{% elif coverage_stop_reason == "round_cap" -%}
- Loop stopped: reached the configured **round cap**.
{% elif coverage_stop_reason == "budget" -%}
- Loop stopped: **budget** exhausted.
{% elif coverage_stop_reason == "convergence" -%}
- Loop stopped: **convergence** — no new hunt tasks were produced.
{% endif -%}
{% endif %}

{% if coverage.skipped_items -%}
### Skipped coverage

| Item | Class | Reason | Recommended next task |
|------|-------|--------|-----------------------|
{% for gap in coverage.skipped_items -%}
{% set gap_item = gap.attack_surface_item_id or "-" -%}
{% set gap_class = gap.vuln_class.value if gap.vuln_class else "-" -%}
{% set gap_next = gap.recommended_next_task or "-" -%}
| {{ gap_item }} | {{ gap_class }} | {{ gap.reason }} | {{ gap_next }} |
{% endfor %}
{% else -%}
Full coverage: no items were skipped.
{% endif %}
{% endif -%}

{% if cost -%}
## Cost & usage

- Model calls: `{{ cost.calls }}`
- Input tokens: `{{ cost.total_input_tokens }}`
- Output tokens: `{{ cost.total_output_tokens }}`
{% if cost.total_cost is none -%}
- Total cost: tokens only (no pricing available for these models)
{% else -%}
- Total cost: `${{ "%.4f" | format(cost.total_cost) }}`
{% endif %}

| Role | Model | Calls | Input | Output | Cost |
|------|-------|-------|-------|--------|------|
{% for row in cost.rows -%}
{% set row_cost = ("—" if not row.priced else "$" ~ ("%.4f" | format(row.cost))) -%}
{% set cells = [row.role, "`" ~ row.model ~ "`", row.calls, row.input, row.output, row_cost] -%}
| {{ cells | join(" | ") }} |
{% endfor %}
{% endif -%}

{% if final_findings -%}
## Final findings

{% for finding in final_findings -%}
### {{ finding.title }}

- Class: `{{ finding.vuln_class.value }}`
- Severity: `{{ finding.severity.value }}`
- Component: `{{ finding.affected_component or "unknown" }}`

{{ finding.summary }}

{% set finding_proofs = proofs_by_finding.get(finding.id, []) -%}
{% for proof in finding_proofs -%}
#### Proof: {{ proof.proof_type }}

{{ proof.description }}

{% if proof.safe_payload -%}
- Safe payload: `{{ proof.safe_payload }}`
{% endif -%}
{% for ref in proof.evidence_refs -%}
{% set redaction = ref.redaction_status.value -%}
- `{{ ref.kind.value }}`: {{ ref.uri }} (redaction: `{{ redaction }}`)
{% endfor %}
{% endfor %}
{% endfor %}
{% endif -%}

{% if needs_proof_findings -%}
## Unverified — needs proof

> These findings were flagged by the validator as requiring further proof.
> They are **not confirmed vulnerabilities**. A future proof stage will attempt
> to verify them. Do not treat these as validated findings.

{% for finding in needs_proof_findings -%}
### {{ finding.title }}

- Class: `{{ finding.vuln_class.value }}`
- Confidence: `{{ finding.confidence.value }}`
- Status: `{{ finding.status.value }}`
- Component: `{{ finding.affected_component or "unknown" }}`
{% if finding.cross_vendor_disagreement -%}
- Note: cross-vendor disagreement (credibility signal)
{% endif %}
{{ finding.hypothesis }}

{% endfor %}
{% endif -%}

## Candidate findings

{% for finding in findings -%}
### {{ finding.title }}

- Class: `{{ finding.vuln_class.value }}`
- Confidence: `{{ finding.confidence.value }}`
- Status: `{{ finding.status.value }}`
- Component: `{{ finding.affected_component or "unknown" }}`

{{ finding.hypothesis }}

{% else -%}
No candidate findings recorded.
{% endfor %}
{% if manifest -%}

## Provenance

- Manifest: `{{ manifest.id }}`
- Quarry version: `{{ manifest.quarry_version }}`
- Profile: `{{ manifest.profile_id }}`
- Repo commit: `{{ manifest.repo_commit_sha or "unknown" }}`

{% if final_findings -%}
| Finding | Validation | Proof artifacts |
|---------|------------|-----------------|
{% for finding in final_findings -%}
{% set proofs = finding.proof_artifact_ids | join(", ") or "-" -%}
| `{{ finding.fingerprint[:16] }}` | `{{ finding.validation_result_id }}` | {{ proofs }} |
{% endfor %}
{% endif -%}
{% endif -%}
"""
)


@activity.defn(name="render-markdown-report")
def render_markdown_report_activity(
    input: RenderReportInput | dict[str, str | None],
) -> RenderReportOutput:
    if isinstance(input, dict):
        scan_json = input["scan_json"]
        findings_json = input["findings_json"]
        if not isinstance(scan_json, str) or not isinstance(findings_json, str):
            raise TypeError("scan_json and findings_json must be strings")
        input = RenderReportInput(
            scan_json=scan_json,
            findings_json=findings_json,
            snapshot_json=input.get("snapshot_json"),
            attack_surface_json=input.get("attack_surface_json"),
            final_findings_json=input.get("final_findings_json"),
            report_path=input.get("report_path"),
            coverage_json=input.get("coverage_json"),
            proof_artifacts_json=input.get("proof_artifacts_json"),
            manifest_json=input.get("manifest_json"),
            model_invocations_json=input.get("model_invocations_json"),
        )
    return _render_markdown_report_from_input(input)


def render_markdown_report(
    scan: Scan,
    findings: list[CandidateFinding],
    snapshot: RepositorySnapshot | None = None,
    attack_surface: list[AttackSurfaceItem] | None = None,
    final_findings: list[FinalFinding] | None = None,
    coverage: CoverageLedger | None = None,
    proof_artifacts: list[ProofArtifact] | None = None,
    manifest: ScanManifest | None = None,
    model_invocations: list[ModelInvocation] | None = None,
    needs_proof_findings: list[CandidateFinding] | None = None,
    coverage_stop_reason: str | None = None,
) -> str:
    return _render_markdown_report_impl(
        scan,
        findings,
        snapshot,
        attack_surface,
        final_findings,
        coverage,
        proof_artifacts,
        manifest,
        model_invocations,
        needs_proof_findings,
        coverage_stop_reason,
    )


def _render_markdown_report_from_input(input: RenderReportInput) -> RenderReportOutput:
    scan = Scan.model_validate_json(input.scan_json)
    findings = _candidate_findings_from_json(input.findings_json)
    snapshot = (
        RepositorySnapshot.model_validate_json(input.snapshot_json)
        if input.snapshot_json is not None
        else None
    )
    attack_surface = (
        _attack_surface_from_json(input.attack_surface_json)
        if input.attack_surface_json is not None
        else None
    )
    final_findings = (
        _final_findings_from_json(input.final_findings_json)
        if input.final_findings_json is not None
        else None
    )
    coverage = (
        CoverageLedger.model_validate_json(input.coverage_json)
        if input.coverage_json is not None
        else None
    )
    proof_artifacts = (
        _proof_artifacts_from_json(input.proof_artifacts_json)
        if input.proof_artifacts_json is not None
        else None
    )
    manifest = (
        ScanManifest.model_validate_json(input.manifest_json)
        if input.manifest_json is not None
        else None
    )
    model_invocations = (
        [ModelInvocation.model_validate(item) for item in json.loads(input.model_invocations_json)]
        if input.model_invocations_json is not None
        else None
    )
    needs_proof_findings = (
        _candidate_findings_from_json(input.needs_proof_findings_json)
        if input.needs_proof_findings_json is not None
        else None
    )
    report_text = _render_markdown_report_impl(
        scan,
        findings,
        snapshot,
        attack_surface,
        final_findings,
        coverage,
        proof_artifacts,
        manifest,
        model_invocations,
        needs_proof_findings,
        input.coverage_stop_reason,
    )
    if input.report_path is None:
        raise TypeError("report_path is required for Temporal report rendering")
    report_path = Path(input.report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    report_ref = _report_artifact_ref(report_path)
    return RenderReportOutput(
        report_text=report_text,
        report_path=str(report_path),
        report_ref_json=report_ref.model_dump_json(),
    )


def _render_markdown_report_impl(
    scan: Scan,
    findings: list[CandidateFinding],
    snapshot: RepositorySnapshot | None = None,
    attack_surface: list[AttackSurfaceItem] | None = None,
    final_findings: list[FinalFinding] | None = None,
    coverage: CoverageLedger | None = None,
    proof_artifacts: list[ProofArtifact] | None = None,
    manifest: ScanManifest | None = None,
    model_invocations: list[ModelInvocation] | None = None,
    needs_proof_findings: list[CandidateFinding] | None = None,
    coverage_stop_reason: str | None = None,
) -> str:
    np_findings = needs_proof_findings or []
    summary = (
        f"Quarry produced {len(final_findings or [])} validated finding(s), "
        f"{len(np_findings)} unverified finding(s) needing proof, "
        f"and {len(findings)} candidate finding(s) for the local scan."
    )
    cost = summarize_model_cost(model_invocations) if model_invocations else None
    return REPORT_TEMPLATE.render(
        scan=scan,
        findings=findings,
        summary=summary,
        snapshot=snapshot,
        attack_surface=attack_surface or [],
        final_findings=final_findings or [],
        needs_proof_findings=np_findings,
        coverage=coverage,
        proofs_by_finding=_proofs_by_finding(proof_artifacts or []),
        manifest=manifest,
        cost=cost,
        coverage_stop_reason=coverage_stop_reason,
    )


class CostRow(TypedDict):
    """Per-(role, model) usage row in the report's Cost & usage table."""

    role: str
    model: str
    calls: int
    input: int
    output: int
    cost: float
    priced: bool


class CostSummary(TypedDict):
    """Aggregate token + cost totals for the report's Cost & usage section."""

    calls: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost: float | None
    rows: list[CostRow]


def summarize_model_cost(invocations: list[ModelInvocation]) -> CostSummary:
    """Aggregate token + cost totals over model invocations for the report.

    ``total_cost`` is ``None`` when *no* invocation carried a price (Chutes and
    other unpriced models) — the report then renders a tokens-only line. A
    per-(role, model) breakdown marks each row priced/unpriced so unknown costs
    show as ``—`` rather than a misleading ``$0``.
    """
    rows: dict[tuple[str, str], CostRow] = {}
    total_input = 0
    total_output = 0
    priced_costs: list[float] = []
    for inv in invocations:
        ti = inv.token_input or 0
        to = inv.token_output or 0
        total_input += ti
        total_output += to
        key = (inv.role, inv.model)
        row = rows.get(key)
        if row is None:
            row = CostRow(
                role=inv.role,
                model=inv.model,
                calls=0,
                input=0,
                output=0,
                cost=0.0,
                priced=False,
            )
            rows[key] = row
        row["calls"] += 1
        row["input"] += ti
        row["output"] += to
        if inv.estimated_cost is not None:
            row["cost"] += inv.estimated_cost
            row["priced"] = True
            priced_costs.append(inv.estimated_cost)

    return CostSummary(
        calls=len(invocations),
        total_input_tokens=total_input,
        total_output_tokens=total_output,
        total_cost=sum(priced_costs) if priced_costs else None,
        rows=sorted(rows.values(), key=lambda r: (r["role"], r["model"])),
    )


def _proofs_by_finding(proof_artifacts: list[ProofArtifact]) -> dict[str, list[ProofArtifact]]:
    by_finding: dict[str, list[ProofArtifact]] = {}
    for proof in proof_artifacts:
        key = proof.final_finding_id or proof.candidate_finding_id
        by_finding.setdefault(key, []).append(proof)
    return by_finding


def _candidate_findings_from_json(payload: str) -> list[CandidateFinding]:
    return [CandidateFinding.model_validate(item) for item in json.loads(payload)]


def _attack_surface_from_json(payload: str) -> list[AttackSurfaceItem]:
    return [AttackSurfaceItem.model_validate(item) for item in json.loads(payload)]


def _final_findings_from_json(payload: str) -> list[FinalFinding]:
    return [FinalFinding.model_validate(item) for item in json.loads(payload)]


def _proof_artifacts_from_json(payload: str) -> list[ProofArtifact]:
    return [ProofArtifact.model_validate(item) for item in json.loads(payload)]


def _report_artifact_ref(report_path: Path) -> ArtifactRef:
    data = report_path.read_bytes()
    return ArtifactRef(
        id=str(uuid4()),
        uri=f"file://{report_path}",
        kind=ArtifactKind.REPORT,
        content_type="text/markdown",
        sha256=sha256(data).hexdigest(),
        size_bytes=len(data),
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=utc_now(),
        metadata={"path": str(report_path)},
    )
