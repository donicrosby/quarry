"""Unit tests for the fuzz dispatch gate (C5, tasks.md 9, 12).

The gate is pure workflow code: it must refuse ambiguous focus, refuse to guess
an invocation, and skip non-args channels — always with a recorded reason.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from quarry.schemas import AgentTask, EntryPoint, VulnerabilityClass
from quarry_workflows.run_scan import (
    fuzz_binary_path,
    fuzz_entry_points_for_dispatch,
    fuzz_focus_skip_reason,
    fuzz_skip_reason,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)

EntryPointKind = Literal[
    "http_handler",
    "cli_arg",
    "library_export",
    "fuzz_harness",
    "main",
    "message_handler",
    "unknown",
]
ACI = Literal["args", "stdin", "env", "config_file", "none"]


def _entry_point(
    *,
    kind: EntryPointKind = "cli_arg",
    invocation: tuple[str, ...] = ("./target/release/vulnerable-cli",),
    aci: ACI = "args",
    function: str = "main",
) -> EntryPoint:
    return EntryPoint(
        repo=".",
        file="src/main.rs",
        function=function,
        kind=kind,
        invocation=list(invocation),
        attacker_controlled_input=aci,
    )


def _task(entry_points: list[EntryPoint]) -> AgentTask:
    return AgentTask(
        id="t1",
        scan_id="s1",
        role="hunter",
        task_name="task",
        entry_points=entry_points,
        status="pending",
        created_at=NOW,
    )


class TestFocusGate:
    def test_single_class_focus_dispatches(self) -> None:
        assert fuzz_focus_skip_reason([VulnerabilityClass.COMMAND_INJECTION]) is None

    def test_multi_class_focus_skips(self) -> None:
        skip = fuzz_focus_skip_reason(
            [VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.SSRF]
        )
        assert skip == "focus-not-single-class"

    def test_default_all_focus_skips(self) -> None:
        assert fuzz_focus_skip_reason(list(VulnerabilityClass)) == "focus-not-single-class"


class TestEntryPointGate:
    def test_args_entry_point_is_dispatchable(self) -> None:
        assert fuzz_skip_reason(_entry_point()) is None

    def test_fuzz_harness_kind_is_dispatchable(self) -> None:
        assert fuzz_skip_reason(_entry_point(kind="fuzz_harness")) is None

    def test_non_fuzzable_kind_skips(self) -> None:
        assert fuzz_skip_reason(_entry_point(kind="main")) == "kind-not-fuzzable"

    def test_empty_invocation_skips(self) -> None:
        assert fuzz_skip_reason(_entry_point(invocation=())) == "missing-invocation"

    def test_stdin_channel_skips(self) -> None:
        assert fuzz_skip_reason(_entry_point(aci="stdin")) == "channel-not-args:stdin"

    def test_config_file_channel_skips(self) -> None:
        assert fuzz_skip_reason(_entry_point(aci="config_file")) == "channel-not-args:config_file"

    def test_env_and_none_channels_skip(self) -> None:
        assert fuzz_skip_reason(_entry_point(aci="env")) == "channel-not-args:env"
        assert fuzz_skip_reason(_entry_point(aci="none")) == "channel-not-args:none"


class TestEntryPointCollection:
    def test_only_fuzzable_kinds_are_collected(self) -> None:
        entry_points = fuzz_entry_points_for_dispatch(
            [
                _task(
                    [
                        _entry_point(),
                        _entry_point(kind="http_handler", function="handler"),
                        _entry_point(kind="fuzz_harness", function="harness"),
                    ]
                )
            ]
        )
        assert [ep.function for ep in entry_points] == ["main", "harness"]

    def test_duplicates_are_collapsed(self) -> None:
        entry_points = fuzz_entry_points_for_dispatch(
            [_task([_entry_point()]), _task([_entry_point()])]
        )
        assert len(entry_points) == 1

    def test_no_tasks_yields_nothing(self) -> None:
        assert fuzz_entry_points_for_dispatch([]) == []


class TestBinaryPath:
    def test_leading_dot_slash_is_stripped(self) -> None:
        assert fuzz_binary_path(_entry_point()) == "target/release/vulnerable-cli"

    def test_plain_relative_path_is_kept(self) -> None:
        assert fuzz_binary_path(_entry_point(invocation=("build/app",))) == "build/app"
