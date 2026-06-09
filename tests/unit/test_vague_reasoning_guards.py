"""Session B — check_vague_reasoning guard tests.

TDD: written before implementation. Tests cover the four sub-checks (presence,
context_reference, lexicon, args_coherence) and graduated strictness by action kind.
Fixture-driven tests load JSON from tests/fixtures/mock_reasoning_fixtures/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import ActionReasoning, ProposedAction, ReasoningCheckResult
from quarry_models.guards import check_vague_reasoning

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "mock_reasoning_fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action(
    kind: str,
    hypothesis: str = "h",
    target_ref: str = "t",
    expected_evidence: str = "e",
    why_this_tool: str = "w",
    args: dict[str, Any] | None = None,
) -> ProposedAction:
    return ProposedAction(
        kind=kind,
        tool_name=kind,
        args=args or {},
        reasoning=ActionReasoning(
            hypothesis=hypothesis,
            target_ref=target_ref,
            expected_evidence=expected_evidence,
            why_this_tool=why_this_tool,
        ),
    )


def _ctx(vuln_class: str = "xss") -> dict[str, Any]:
    return {"vuln_class": vuln_class}


# ---------------------------------------------------------------------------
# Presence check
# ---------------------------------------------------------------------------


class TestPresenceCheck:
    def test_empty_hypothesis_fails(self) -> None:
        action = _action("read_file", hypothesis="")
        result = check_vague_reasoning(action, _ctx(), action.args)
        assert not result.passed
        assert "presence" in result.failed_checks

    def test_single_word_fails(self) -> None:
        """Hypothesis with only one token (below min_token_length=4) must fail."""
        action = _action("read_file", hypothesis="yes")
        result = check_vague_reasoning(action, _ctx(), action.args)
        assert not result.passed
        assert "presence" in result.failed_checks

    def test_empty_expected_evidence_fails(self) -> None:
        action = _action("read_file", expected_evidence="")
        result = check_vague_reasoning(action, _ctx(), action.args)
        assert not result.passed
        assert "presence" in result.failed_checks

    def test_sufficient_tokens_passes_presence(self) -> None:
        """Prose fields with ≥4 tokens + non-empty target_ref pass the presence check."""
        action = _action(
            "read_file",
            hypothesis="command injection via exec call",
            target_ref="src/auth.py",  # locator — non-empty is sufficient
            expected_evidence="os.system receives user input",
            why_this_tool="reads the source file directly",
        )
        result = check_vague_reasoning(action, {"vuln_class": "command_injection"}, action.args)
        # presence check must pass (may fail other checks — that's fine here)
        assert "presence" not in result.failed_checks


# ---------------------------------------------------------------------------
# Context reference check
# ---------------------------------------------------------------------------


class TestContextReferenceCheck:
    def test_no_locator_fails(self) -> None:
        """Hypothesis names the vuln class but has no concrete locator."""
        action = _action(
            "read_file",
            hypothesis="there might be xss in the code base",
            target_ref="somewhere in frontend",
            expected_evidence="reflected input in response",
            why_this_tool="reads the source to find reflection points",
        )
        result = check_vague_reasoning(action, _ctx("xss"), action.args)
        assert not result.passed
        assert "context_reference" in result.failed_checks

    def test_concrete_url_param_passes(self) -> None:
        """target_ref with a concrete URL param passes context_reference."""
        action = _action(
            "read_file",
            hypothesis="reflected xss via q param in search endpoint",
            target_ref="GET /search?q=",
            expected_evidence="template renders q without html.escape",
            why_this_tool="reads the template to confirm unescaped output",
        )
        result = check_vague_reasoning(action, _ctx("xss"), action.args)
        assert "context_reference" not in result.failed_checks

    def test_file_line_ref_passes(self) -> None:
        """target_ref with file:line notation passes context_reference."""
        action = _action(
            "read_file",
            hypothesis="command injection in src/auth.py run_command",
            target_ref="src/auth.py:42",
            expected_evidence="subprocess.Popen receives unsanitized user input",
            why_this_tool="reads the function to verify no shlex.quote call",
        )
        result = check_vague_reasoning(action, _ctx("command_injection"), action.args)
        assert "context_reference" not in result.failed_checks


# ---------------------------------------------------------------------------
# Lexicon check
# ---------------------------------------------------------------------------


class TestLexiconCheck:
    def test_banned_phrase_in_hypothesis_fails(self) -> None:
        action = _action(
            "read_file",
            hypothesis="test the exploit in the search endpoint query param",
            target_ref="GET /search?q=",
            expected_evidence="xss payload reflected in html body",
            why_this_tool="reads the template to verify reflection",
        )
        result = check_vague_reasoning(action, _ctx("xss"), action.args)
        assert not result.passed
        assert "lexicon" in result.failed_checks

    def test_banned_evidence_claim_fails(self) -> None:
        """expected_evidence 'it works' is explicitly banned."""
        action = _action(
            "read_file",
            hypothesis="reflected xss via q param in /search",
            target_ref="GET /search?q=",
            expected_evidence="it works",
            why_this_tool="reads the template to confirm unescaped output",
        )
        result = check_vague_reasoning(action, _ctx("xss"), action.args)
        assert not result.passed
        assert "lexicon" in result.failed_checks

    def test_specific_reasoning_passes_lexicon(self) -> None:
        action = _action(
            "read_file",
            hypothesis="reflected xss via q param — /search endpoint renders q without escaping",
            target_ref="GET /search?q=",
            expected_evidence="<script> tag echoed verbatim in response html",
            why_this_tool="grep locates the template render call for /search",
        )
        result = check_vague_reasoning(action, _ctx("xss"), action.args)
        assert "lexicon" not in result.failed_checks


# ---------------------------------------------------------------------------
# Args coherence check (high-risk only)
# ---------------------------------------------------------------------------


class TestArgsCoherenceCheck:
    def test_http_request_path_mismatch_fails(self) -> None:
        """target_ref says /profile but args path is /admin/users → incoherent."""
        action = _action(
            "http_request",
            hypothesis="idor via id param in /profile — user can access other users",
            target_ref="GET /profile?id=",
            expected_evidence="response contains another user data when id is changed",
            why_this_tool="http_request sends crafted request to /profile to confirm idor",
            args={"method": "GET", "path": "/admin/users"},
        )
        result = check_vague_reasoning(action, _ctx("idor"), action.args)
        assert not result.passed
        assert "args_coherence" in result.failed_checks

    def test_http_request_matching_path_passes(self) -> None:
        action = _action(
            "http_request",
            hypothesis="reflected xss via q param in /search endpoint",
            target_ref="GET /search?q=",
            expected_evidence="script tag echoed unescaped in response body",
            why_this_tool="http_request sends payload to /search to confirm reflection",
            args={"method": "GET", "path": "/search?q=<script>"},
        )
        result = check_vague_reasoning(action, _ctx("xss"), action.args)
        assert "args_coherence" not in result.failed_checks

    def test_read_only_action_skips_coherence_check(self) -> None:
        """read_file and grep do not require args_coherence (read-only tier)."""
        action = _action(
            "read_file",
            hypothesis="command injection via exec in src/auth.py",
            target_ref="src/auth.py",
            expected_evidence="subprocess.Popen with unsanitized arg",
            why_this_tool="read_file inspects the exec call location",
            args={"path": "src/other.py"},  # different file — would fail coherence if applied
        )
        result = check_vague_reasoning(action, _ctx("command_injection"), action.args)
        # coherence is NOT checked for read_file — different file path is fine
        assert "args_coherence" not in result.failed_checks


# ---------------------------------------------------------------------------
# Graduated strictness
# ---------------------------------------------------------------------------


class TestGraduatedStrictness:
    def test_high_risk_gets_all_four_checks(self) -> None:
        """http_request triggers all four checks including args_coherence."""
        action = _action(
            "http_request",
            hypothesis="test the exploit",
            target_ref="GET /profile?id=",
            expected_evidence="it works",
            why_this_tool="see what happens",
            args={"method": "GET", "path": "/admin"},
        )
        result = check_vague_reasoning(action, _ctx("idor"), action.args)
        assert not result.passed
        # Should fail multiple checks
        assert len(result.failed_checks) >= 2

    def test_read_only_skips_coherence(self) -> None:
        """grep (read-only) must not apply args_coherence even with a mismatched path."""
        action = _action(
            "grep",
            hypothesis="command injection via unescaped shell call in src/auth.py",
            target_ref="src/auth.py:exec",
            expected_evidence="subprocess.Popen or os.system without shlex.quote",
            why_this_tool="grep finds all subprocess and os.system usages in the codebase",
            args={"pattern": "subprocess.Popen", "path": "src/"},
        )
        result = check_vague_reasoning(action, _ctx("command_injection"), action.args)
        assert "args_coherence" not in result.failed_checks


# ---------------------------------------------------------------------------
# Fixture-driven tests
# ---------------------------------------------------------------------------


@pytest.fixture(params=[
    "good_xss_reasoning.json",
    "good_read_reasoning.json",
    "vague_xss_reasoning.json",
    "bad_coherence_reasoning.json",
])
def reasoning_fixture(request: pytest.FixtureRequest) -> dict[str, Any]:
    fixture_path = _FIXTURES / request.param  # type: ignore[attr-defined]
    return json.loads(fixture_path.read_text())  # type: ignore[return-value]


def test_good_xss_reasoning_passes() -> None:
    """Fixture: well-formed XSS http_request reasoning should pass all checks."""
    data = json.loads((_FIXTURES / "good_xss_reasoning.json").read_text())
    action = ProposedAction.model_validate(data)
    result = check_vague_reasoning(action, _ctx("xss"), action.args)
    assert result.passed, f"Expected pass; failed checks: {result.failed_checks}\n{result.detail}"


def test_vague_xss_reasoning_fails() -> None:
    """Fixture: vague XSS http_request reasoning should fail multiple checks."""
    data = json.loads((_FIXTURES / "vague_xss_reasoning.json").read_text())
    action = ProposedAction.model_validate(data)
    result = check_vague_reasoning(action, _ctx("xss"), action.args)
    assert not result.passed
    assert len(result.failed_checks) >= 1


def test_good_read_reasoning_passes() -> None:
    """Fixture: well-formed read_file reasoning for command_injection should pass."""
    data = json.loads((_FIXTURES / "good_read_reasoning.json").read_text())
    action = ProposedAction.model_validate(data)
    result = check_vague_reasoning(action, _ctx("command_injection"), action.args)
    assert result.passed, f"Expected pass; failed checks: {result.failed_checks}\n{result.detail}"


def test_bad_coherence_reasoning_fails_coherence() -> None:
    """Fixture: http_request where target_ref path doesn't match args path → fails."""
    data = json.loads((_FIXTURES / "bad_coherence_reasoning.json").read_text())
    action = ProposedAction.model_validate(data)
    result = check_vague_reasoning(action, _ctx("idor"), action.args)
    assert not result.passed
    assert "args_coherence" in result.failed_checks


def test_fixture_result_has_detail_on_failure() -> None:
    """Any failed result must populate the detail field for re-prompt feedback."""
    data = json.loads((_FIXTURES / "vague_xss_reasoning.json").read_text())
    action = ProposedAction.model_validate(data)
    result = check_vague_reasoning(action, _ctx("xss"), action.args)
    if not result.passed:
        assert len(result.detail) > 0
