"""Unit tests for the fuzz crash oracle (C5 fuzzing-harness, tasks.md 4-5).

The oracle is backend-aware: tier-1 proc returns negative exit codes on signal
death, tier-2 ContainerSandbox passes docker's ``128+N`` verbatim.  Sandbox
rlimit deaths (SIGKILL/SIGXCPU from RLIMIT_CPU, SIGABRT from RLIMIT_AS) and the
wall-clock timeout are *boundary* outcomes, not crashes.
"""

from __future__ import annotations

import pytest

from quarry_activities.fuzz import (
    CrashClass,
    classify_result,
    compute_crash_hash,
    decode_signal,
    detect_sanitizer,
    normalize_crash_output,
    signal_name,
)
from quarry_activities.sandbox import SandboxResult


def _result(
    exit_code: int, *, stdout: str = "", stderr: str = "", timed_out: bool = False
) -> SandboxResult:
    return SandboxResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=1,
        timed_out=timed_out,
    )


class TestSignalDecode:
    @pytest.mark.parametrize(
        ("exit_code", "expected"),
        [
            (-11, 11),
            (-9, 9),
            (-6, 6),
            (139, 11),
            (137, 9),
            (134, 6),
            (0, None),
            (1, None),
            (124, None),
        ],
    )
    def test_decode_signal(self, exit_code: int, expected: int | None) -> None:
        assert decode_signal(exit_code) == expected

    def test_signal_names(self) -> None:
        assert signal_name(11) == "SIGSEGV"
        assert signal_name(7) == "SIGBUS"
        assert signal_name(9) == "SIGKILL"
        assert signal_name(6) == "SIGABRT"
        assert signal_name(24) == "SIGXCPU"
        assert signal_name(99) == "SIG99"


class TestClassification:
    def test_negative_exit_code_is_a_crash(self) -> None:
        verdict = classify_result(_result(-11))
        assert verdict.kind is CrashClass.CRASH
        assert verdict.signal == "SIGSEGV"

    def test_exit_128_plus_n_is_a_crash(self) -> None:
        verdict = classify_result(_result(139))
        assert verdict.kind is CrashClass.CRASH
        assert verdict.signal == "SIGSEGV"

    def test_sigbus_is_a_crash(self) -> None:
        assert classify_result(_result(-7)).kind is CrashClass.CRASH

    @pytest.mark.parametrize("exit_code", [-9, -24])
    def test_rlimit_signal_is_boundary_not_crash(self, exit_code: int) -> None:
        verdict = classify_result(_result(exit_code))
        assert verdict.kind is CrashClass.BOUNDARY
        assert verdict.signal in {"SIGKILL", "SIGXCPU"}

    def test_sigkill_from_128_plus_n_is_boundary(self) -> None:
        # tier-2 cgroup OOM surfaces as 137 (128+9).
        assert classify_result(_result(137)).kind is CrashClass.BOUNDARY

    def test_sigabrt_without_sanitizer_is_boundary(self) -> None:
        verdict = classify_result(_result(-6))
        assert verdict.kind is CrashClass.BOUNDARY
        assert verdict.signal == "SIGABRT"

    def test_wall_clock_timeout_is_boundary(self) -> None:
        verdict = classify_result(_result(124, timed_out=True))
        assert verdict.kind is CrashClass.BOUNDARY

    def test_positive_nonzero_exit_is_not_a_crash(self) -> None:
        verdict = classify_result(_result(1))
        assert verdict.kind is CrashClass.NON_CRASH

    def test_zero_exit_is_not_a_crash(self) -> None:
        assert classify_result(_result(0)).kind is CrashClass.NON_CRASH


class TestSanitizer:
    @pytest.mark.parametrize(
        ("stderr", "kind"),
        [
            ("==1==ERROR: AddressSanitizer: heap-buffer-overflow", "asan"),
            ("SUMMARY: AddressSanitizer: stack-buffer-overflow", "asan"),
            ("file.c:3:5: runtime error: load of misaligned address", "ubsan"),
            ("UndefinedBehaviorSanitizer: signed integer overflow", "ubsan"),
        ],
    )
    def test_detect_sanitizer(self, stderr: str, kind: str) -> None:
        assert detect_sanitizer(stderr) == kind

    def test_no_sanitizer(self) -> None:
        assert detect_sanitizer("plain stderr") == ""

    def test_sanitizer_output_is_a_crash(self) -> None:
        verdict = classify_result(_result(1, stderr="ERROR: AddressSanitizer: bad-free"))
        assert verdict.kind is CrashClass.CRASH
        assert verdict.sanitizer == "asan"

    def test_sanitizer_wins_over_wall_clock_timeout(self) -> None:
        # (124, timed_out=True, ASan stderr) is the documented corner: the
        # sanitizer report takes precedence regardless of exit code.
        verdict = classify_result(
            _result(124, timed_out=True, stderr="ERROR: AddressSanitizer: use-after-free")
        )
        assert verdict.kind is CrashClass.CRASH
        assert verdict.sanitizer == "asan"

    def test_sigabrt_with_sanitizer_is_a_crash(self) -> None:
        verdict = classify_result(
            _result(-6, stderr="ERROR: AddressSanitizer: heap-use-after-free")
        )
        assert verdict.kind is CrashClass.CRASH


class TestCrashHash:
    def test_normalize_collapses_addresses_and_whitespace(self) -> None:
        assert normalize_crash_output("at   0xdeadbeef") == "at 0xADDR"

    def test_same_signature_same_hash(self) -> None:
        first = compute_crash_hash(exit_code=-11, signal_number=11, stderr="segv at 0x1111")
        second = compute_crash_hash(exit_code=-11, signal_number=11, stderr="segv at 0x2222")
        assert first == second

    def test_different_signal_different_hash(self) -> None:
        first = compute_crash_hash(exit_code=-11, signal_number=11, stderr="boom")
        second = compute_crash_hash(exit_code=-7, signal_number=7, stderr="boom")
        assert first != second

    def test_different_stderr_different_hash(self) -> None:
        first = compute_crash_hash(exit_code=-11, signal_number=11, stderr="one")
        second = compute_crash_hash(exit_code=-11, signal_number=11, stderr="two")
        assert first != second

    def test_hash_is_sha256_hex(self) -> None:
        digest = compute_crash_hash(exit_code=-11, signal_number=11, stderr="")
        assert len(digest) == 64
        assert all(char in "0123456789abcdef" for char in digest)
