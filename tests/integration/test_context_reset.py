"""End-to-end hunter context reset (hunter-context-reset, tasks 6.1/6.2).

Drives the real ``hunt_impl`` — real prompt rendering, real tool registry, real
``read_file`` execution against a generated repo, real agent loop — with a scripted
model client standing in for the hunter. The hunter emits a finding on turn 1 and a
second on turn 2, then keeps reading the same large file until the accumulated
history crosses a deliberately small context-window limit.

The scripted client behaves like a model that re-emits the findings it can still
see in its context: it reads them out of the assistant responses still in history
AND out of the ``## Compressed context`` summary a reset injects. That makes the
acceptance check a real diff between "findings mentioned in context" and "findings
emitted to the workflow" — any candidate the reset silently dropped would surface
as a missing title, because no context source would carry it any more.
"""

from __future__ import annotations

import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from quarry.panel_config import DEFAULT_PANEL
from quarry.schemas import AgentTask, CandidateFinding, HunterGap, VulnerabilityClass
from quarry_activities.hunt import hunt_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.types import BudgetSpec

_FINDING_A: dict[str, Any] = {
    "title": "command injection in big.py",
    "hypothesis": "shell=True with attacker-controlled argv",
    "affected_component": "big.py:10",
    "confidence": "high",
    "severity": "high",
}
_FINDING_B: dict[str, Any] = {
    "title": "path traversal in big.py",
    "hypothesis": "unchecked join on user path",
    "affected_component": "big.py:120",
    "confidence": "medium",
    "severity": "medium",
}
_FINDINGS_BY_TITLE = {_FINDING_A["title"]: _FINDING_A, _FINDING_B["title"]: _FINDING_B}

# Small enough that the two tool-call turns cross it; comfortably above the
# 80%-of-limit default threshold once three turns of history accumulate.
_CONTEXT_WINDOW_TOKENS = 2000


class _PreservingHunterClient:
    """Scripted hunter that re-emits every finding still visible in its context."""

    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.mentions: list[str] = []
        self.final_visible: list[str] = []

    @staticmethod
    def _titles_in_context(messages: list[Any]) -> list[str]:
        titles: list[str] = []
        for message in messages:
            if message.role == "assistant":
                with suppress(json.JSONDecodeError):
                    payload = cast("dict[str, Any]", json.loads(message.content))
                    for finding in cast("list[dict[str, Any]]", payload.get("findings") or []):
                        title = finding.get("title")
                        if isinstance(title, str) and title not in titles:
                            titles.append(title)
            elif message.content.startswith("## Compressed context"):
                for title in re.findall(r'title="([^"]*)"', message.content):
                    if title not in titles:
                        titles.append(title)
        return titles

    @staticmethod
    def _gaps_in_context(messages: list[Any]) -> list[dict[str, str]]:
        gaps: list[dict[str, str]] = []
        for message in messages:
            if message.role == "assistant":
                with suppress(json.JSONDecodeError):
                    payload = cast("dict[str, Any]", json.loads(message.content))
                    for gap in cast("list[dict[str, Any]]", payload.get("coverage_gaps") or []):
                        area = gap.get("area")
                        reason = gap.get("reason")
                        if isinstance(area, str) and all(entry["area"] != area for entry in gaps):
                            gaps.append({"area": area, "reason": str(reason or "")})
            elif message.content.startswith("## Compressed context"):
                for area, reason in re.findall(r'area="([^"]*)" reason="([^"]*)"', message.content):
                    if all(gap["area"] != area for gap in gaps):
                        gaps.append({"area": area, "reason": reason})
        return gaps

    def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
        self.requests.append(request)
        turn = len(self.requests)
        payload: dict[str, Any]
        if turn <= 2:
            finding = _FINDING_A if turn == 1 else _FINDING_B
            self.mentions.append(finding["title"])
            payload = {
                "findings": [finding],
                "coverage_gaps": (
                    [{"area": "big.py", "reason": "only the head was read"}] if turn == 1 else []
                ),
                "tool_calls": [ToolCallRequest(tool="read_file", inputs={"path": "big.py"})],
            }
        elif turn == 3:
            payload = {
                "findings": [],
                "coverage_gaps": [],
                "tool_calls": [ToolCallRequest(tool="read_file", inputs={"path": "big.py"})],
            }
        else:
            self.final_visible = self._titles_in_context(request.messages)
            payload = {
                "findings": [
                    _FINDINGS_BY_TITLE[title]
                    for title in self.final_visible
                    if title in _FINDINGS_BY_TITLE
                ],
                "coverage_gaps": self._gaps_in_context(request.messages),
                "tool_calls": [],
            }
        return type(
            "Resp",
            (),
            {"parsed": response_model(**payload), "estimated_cost": 0.0},
        )()


def _make_repo(tmp_path: Path) -> Path:
    # ~400 lines of filler: one read_file result is big enough that three turns of
    # history cross the 2000-token window above.
    lines = [
        f"value_{index} = {index}  # filler line for the context-window test"
        for index in range(400)
    ]
    (tmp_path / "big.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tmp_path


def _run_hunt(
    tmp_path: Path,
) -> tuple[
    list[CandidateFinding],
    list[HunterGap],
    list[tuple[str, dict[str, Any]]],
    _PreservingHunterClient,
]:
    task = AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-scan-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope=".",
        status="pending",
        created_at=datetime.now(UTC),
    )
    client = _PreservingHunterClient()
    events: list[tuple[str, dict[str, Any]]] = []

    def _sink(event_type: str, payload: dict[str, Any]) -> None:
        events.append((event_type, payload))

    findings, gaps = hunt_impl(
        task=task,
        repo_path=str(_make_repo(tmp_path)),
        max_iterations=6,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
        event_sink=_sink,
        context_window_tokens=_CONTEXT_WINDOW_TOKENS,
        context_window_threshold=DEFAULT_PANEL["hunt"].context_window_threshold,
    )
    return findings, gaps, events, client


def _reset_events(events: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [payload for event_type, payload in events if event_type == "agent.context_reset"]


def test_hunt_crossing_the_window_resets_and_loses_no_candidate(tmp_path: Path) -> None:
    findings, _gaps, events, client = _run_hunt(tmp_path)

    resets = _reset_events(events)
    assert resets, "expected the hunter loop to cross the context-window threshold"
    assert resets[0]["turns_compressed"] >= 1
    assert resets[0]["tokens_before"] >= int(_CONTEXT_WINDOW_TOKENS * 0.8)

    # Zero candidate loss: every finding the hunter mentioned in context reached
    # the workflow exactly once.
    emitted = sorted(finding.title for finding in findings)
    assert emitted == sorted(client.mentions) == sorted(_FINDINGS_BY_TITLE)


def test_findings_produced_before_the_first_reset_survive_it(tmp_path: Path) -> None:
    findings, gaps, events, client = _run_hunt(tmp_path)

    assert _reset_events(events), "expected at least one reset"
    # The turn-1 finding was emitted before the first reset, so its only surviving
    # context source after the reset is the compressed summary.
    assert _FINDING_A["title"] in client.final_visible
    assert _FINDING_A["title"] in {finding.title for finding in findings}
    assert {gap.area for gap in gaps} == {"big.py"}


def test_reset_replaces_raw_turns_with_the_compressed_summary(tmp_path: Path) -> None:
    _findings, _gaps, _events, client = _run_hunt(tmp_path)

    post_reset = client.requests[3].messages
    assert post_reset[0].role == "system"
    assert post_reset[1].role == "user"  # original task directive, preserved verbatim
    assert post_reset[2].content.startswith("## Compressed context")
    assert f'title="{_FINDING_A["title"]}"' in post_reset[2].content
    # The raw turn-1 response is gone; only the summary mentions that finding.
    assert not any(
        message.role == "assistant" and _FINDING_A["title"] in message.content
        for message in post_reset
    )
