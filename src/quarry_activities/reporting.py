"""Report rendering activities."""

from jinja2 import Template

from quarry.schemas import AttackSurfaceItem, CandidateFinding, RepositorySnapshot, Scan

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

## Demo honesty

Real:
- Scan record persisted.
- Candidate finding persisted.
- Markdown report written.
- Attack surface mapped and persisted.

Fake or stubbed:
- Vulnerability detection.
- Validation and proof.
- Model calls.

Known broken:
- Temporal server execution is not required for this local smoke path.
"""
)


def render_markdown_report(
    scan: Scan,
    findings: list[CandidateFinding],
    snapshot: RepositorySnapshot | None = None,
    attack_surface: list[AttackSurfaceItem] | None = None,
) -> str:
    summary = f"Quarry generated {len(findings)} candidate finding(s) for the local scan."
    return REPORT_TEMPLATE.render(
        scan=scan,
        findings=findings,
        summary=summary,
        snapshot=snapshot,
        attack_surface=attack_surface or [],
    )
