"""Tests for safe prompt construction."""

from pathlib import Path

from quarry_models.prompting import EVIDENCE_NOTE, build_prompt, render_messages

FIXTURES = Path("tests/fixtures/prompt-injection")


def _build_from_readme() -> tuple[str, int]:
    evidence = (FIXTURES / "malicious_readme.md").read_text(encoding="utf-8")
    built = build_prompt(
        system_instructions="You are a security analyst reviewing untrusted evidence.",
        task_instructions="Identify hardcoded secrets in the evidence.",
        evidence=evidence,
        output_schema_note="Return a JSON object matching the SecretFindings schema.",
        prompt_version="secrets-v1",
    )
    return render_messages(built.messages), built.scrubber_hits


def test_instructions_and_evidence_are_separated() -> None:
    built = build_prompt(
        system_instructions="SYS",
        task_instructions="TASK",
        evidence="some evidence",
        output_schema_note="SCHEMA",
    )
    system = built.messages[0]
    user = built.messages[1]

    assert system.role == "system"
    assert EVIDENCE_NOTE in system.content
    assert "<target_content>" in user.content
    assert "</target_content>" in user.content
    # Evidence lives only inside the tagged block of the user message.
    assert "some evidence" in user.content
    assert "some evidence" not in system.content


def test_evidence_is_redacted_before_wrapping() -> None:
    text, hits = _build_from_readme()

    assert "ghp_examplemalicious0123456789ABCDEFhijk" not in text
    assert "[REDACTED_SECRET_1]" in text
    assert hits == 1


def test_prompt_hash_is_deterministic() -> None:
    def build() -> str:
        return build_prompt(
            system_instructions="SYS",
            task_instructions="TASK",
            evidence='ADMIN_API_KEY = "abc12345"',
            output_schema_note="SCHEMA",
            prompt_version="v1",
        ).prompt_hash

    first = build()
    second = build()

    assert first == second
    assert len(first) == 64


def test_matches_golden_sanitized_prompt() -> None:
    expected = (FIXTURES / "expected_sanitized_prompt.txt").read_text(encoding="utf-8")
    text, _ = _build_from_readme()

    assert text == expected
