"""Golden acceptance test: malicious fixtures stay inert evidence.

For every seeded prompt-injection fixture, the content must be wrapped as
untrusted evidence (never instructions), secrets must be redacted before the
prompt is built, and no injected directive may leak into the system message.
"""

import re
from pathlib import Path

import pytest

from quarry_models.prompting import EVIDENCE_NOTE, build_prompt, render_messages

FIXTURES = Path("tests/fixtures/prompt-injection")
MALICIOUS_FILES = [
    "malicious_readme.md",
    "malicious_source.py",
    "malicious_http_response.html",
    "malicious_openapi.yaml",
    "malicious_tool_output.txt",
]

# Substrings that must never appear in the clear anywhere in a built prompt.
RAW_SECRETS = [
    "ghp_examplemalicious0123456789ABCDEFhijk",
    "AKIAIOSFODNN7EXAMPLE",
    "sup3r-s3cret-db-pw",
    "abcdef0123456789ghijklmnop",
]


def _build(evidence: str) -> tuple[str, str, str]:
    built = build_prompt(
        system_instructions="You are a security analyst reviewing untrusted evidence.",
        task_instructions="Identify vulnerabilities in the evidence.",
        evidence=evidence,
        output_schema_note="Return JSON matching the Findings schema.",
    )
    system, user = built.messages[0].content, built.messages[1].content
    return render_messages(built.messages), system, user


@pytest.mark.parametrize("fixture", MALICIOUS_FILES)
def test_injected_directives_stay_inside_evidence_block(fixture: str) -> None:
    evidence = (FIXTURES / fixture).read_text(encoding="utf-8")
    _, system, user = _build(evidence)

    # The instruction (system) block must be Quarry's own, never the injection.
    assert EVIDENCE_NOTE in system
    assert "ignore previous instructions" not in system.lower()
    assert "do not report" not in system.lower()

    # All target content lives strictly inside the tagged evidence block.
    match = re.search(r"<target_content>\n(.*)\n</target_content>", user, re.DOTALL)
    assert match is not None
    block = match.group(1)
    # Anything injection-like in the fixture is present only as quoted evidence.
    for needle in ("ignore previous instructions", "system:", "assistant:"):
        if needle in evidence.lower():
            assert needle in block.lower()


@pytest.mark.parametrize("fixture", MALICIOUS_FILES)
def test_secrets_are_redacted_before_prompt(fixture: str) -> None:
    evidence = (FIXTURES / fixture).read_text(encoding="utf-8")
    rendered, _, _ = _build(evidence)

    for secret in RAW_SECRETS:
        assert secret not in rendered


def test_no_fixture_changes_instruction_block() -> None:
    """The system instruction block is identical regardless of evidence content."""
    systems: set[str] = set()
    for fixture in MALICIOUS_FILES:
        evidence = (FIXTURES / fixture).read_text(encoding="utf-8")
        _, system, _ = _build(evidence)
        systems.add(system)

    assert len(systems) == 1  # injection never alters the instruction block
