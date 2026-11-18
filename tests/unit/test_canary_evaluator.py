"""Unit tests for canary evidence evaluation in the prove outcome.

Pins the Tier-2-only corroboration contract from openspec change
canary-callback-listener:
  - A callback whose source_ip is a resolved target IP AND whose path contains
    the token yields "corroborated".
  - A callback from the sandbox's own address space (not a resolved target IP)
    is ignored even when it carries the token.
  - Tier-1 (empty resolved_target_ips) callbacks never corroborate.
  - Corroboration is consulted before the exit-code / HTTP checks, but a
    sandbox timeout still outranks it.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from quarry.schemas import (
    CanaryCallback,
    HttpResponseCapture,
    RedactionStatus,
    SandboxExecCapture,
)
from quarry_workflows.prove_stage import _evaluate_canary_callbacks, prove_outcome_from_captures

_TOKEN = "0123456789abcdef0123456789abcdef"
_TARGET_IP = "10.0.0.5"
_SANDBOX_IP = "10.0.0.99"


def _callback(
    *,
    path: str = f"/{_TOKEN}",
    source_ip: str = _TARGET_IP,
) -> CanaryCallback:
    return CanaryCallback(
        timestamp="2026-01-01T00:00:00+00:00",
        method="GET",
        path=path,
        source_ip=source_ip,
    )


def _exec_cap(exit_code: int = 0, timed_out: bool = False) -> SandboxExecCapture:
    return SandboxExecCapture(
        exit_code=exit_code,
        stdout_artifact_ref="art-stdout",
        stderr_artifact_ref="art-stderr",
        elapsed_ms=250,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        timed_out=timed_out,
    )


def _http_cap(status_code: int = 200) -> HttpResponseCapture:
    return HttpResponseCapture(
        status_code=status_code,
        body_artifact_ref="art-body",
        elapsed_ms=120,
        redaction_status=RedactionStatus.NOT_REQUIRED,
    )


class TestEvaluateCanaryCallbacks:
    def test_target_ip_with_token_corroborates(self) -> None:
        verdict = _evaluate_canary_callbacks([_callback()], _TOKEN, [_TARGET_IP])
        assert verdict == "corroborated"

    def test_sandbox_ip_with_token_is_ignored(self) -> None:
        verdict = _evaluate_canary_callbacks(
            [_callback(source_ip=_SANDBOX_IP)], _TOKEN, [_TARGET_IP]
        )
        assert verdict is None

    def test_tier1_empty_target_ips_never_corroborates(self) -> None:
        # Tier 1 leaves resolved_target_ips empty (loopback presents 127.0.0.1).
        verdict = _evaluate_canary_callbacks([_callback(source_ip="127.0.0.1")], _TOKEN, [])
        assert verdict is None

    def test_non_matching_token_is_ignored(self) -> None:
        verdict = _evaluate_canary_callbacks(
            [_callback(path="/some-other-path")], _TOKEN, [_TARGET_IP]
        )
        assert verdict is None

    def test_empty_callbacks(self) -> None:
        assert _evaluate_canary_callbacks([], _TOKEN, [_TARGET_IP]) is None

    def test_missing_token(self) -> None:
        assert _evaluate_canary_callbacks([_callback()], None, [_TARGET_IP]) is None

    def test_one_authorized_callback_among_many(self) -> None:
        callbacks = [
            _callback(source_ip=_SANDBOX_IP),
            _callback(source_ip="203.0.113.7"),
            _callback(source_ip=_TARGET_IP),
        ]
        assert _evaluate_canary_callbacks(callbacks, _TOKEN, [_TARGET_IP]) == "corroborated"


class TestProveOutcomeCanary:
    def test_corroborated_outranks_zero_exit_code(self) -> None:
        verdict = prove_outcome_from_captures(
            [_exec_cap(exit_code=0)],
            [],
            canary_callbacks=[_callback()],
            canary_token=_TOKEN,
            resolved_target_ips=[_TARGET_IP],
        )
        assert verdict == "corroborated"

    def test_corroborated_outranks_http_success(self) -> None:
        verdict = prove_outcome_from_captures(
            [],
            [_http_cap(200)],
            canary_callbacks=[_callback()],
            canary_token=_TOKEN,
            resolved_target_ips=[_TARGET_IP],
        )
        assert verdict == "corroborated"

    def test_timeout_outranks_corroboration(self) -> None:
        verdict = prove_outcome_from_captures(
            [_exec_cap(exit_code=124, timed_out=True)],
            [],
            canary_callbacks=[_callback()],
            canary_token=_TOKEN,
            resolved_target_ips=[_TARGET_IP],
        )
        assert verdict == "needs_manual_review"

    def test_sandbox_ip_callback_falls_through_to_exit_code(self) -> None:
        verdict = prove_outcome_from_captures(
            [_exec_cap(exit_code=0)],
            [],
            canary_callbacks=[_callback(source_ip=_SANDBOX_IP)],
            canary_token=_TOKEN,
            resolved_target_ips=[_TARGET_IP],
        )
        assert verdict == "proved"

    def test_tier1_callback_falls_through(self) -> None:
        verdict = prove_outcome_from_captures(
            [_exec_cap(exit_code=0)],
            [],
            canary_callbacks=[_callback(source_ip="127.0.0.1")],
            canary_token=_TOKEN,
            resolved_target_ips=[],
        )
        assert verdict == "proved"

    def test_no_canary_callbacks_leaves_verdict_unchanged(self) -> None:
        verdict = prove_outcome_from_captures(
            [_exec_cap(exit_code=1)],
            [],
            canary_callbacks=[],
            canary_token=_TOKEN,
            resolved_target_ips=[_TARGET_IP],
        )
        assert verdict == "not_proved"

    def test_back_compat_without_canary_kwargs(self) -> None:
        assert prove_outcome_from_captures([_exec_cap(0)], []) == "proved"
        assert prove_outcome_from_captures([], []) == "not_proved"
