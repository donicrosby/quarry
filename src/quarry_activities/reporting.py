"""Report rendering activities."""

from jinja2 import Template

from quarry.schemas import CandidateFinding, Scan

REPORT_TEMPLATE = Template(
    """# Quarry Scan Report

Scan: `{{ scan.id }}`

Status: `{{ scan.status.value }}`

Profile: `{{ scan.profile.id }}`

## Summary

{{ summary }}

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

Fake or stubbed:
- Vulnerability detection.
- Validation and proof.
- Model calls.

Known broken:
- Temporal server execution is not required for this local smoke path.
"""
)


def render_markdown_report(scan: Scan, findings: list[CandidateFinding]) -> str:
    summary = (
        f"Quarry generated {len(findings)} fake candidate finding(s) for the walking skeleton."
    )
    return REPORT_TEMPLATE.render(scan=scan, findings=findings, summary=summary)
