"""Tests for the CyberGym PoC-reproduction agent loop."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from pydantic import ValidationError

from quarry_benchmark.agent import (
    AgentFailed,
    ReproductionAttempt,
    build_user_message,
    reproduce,
    SYSTEM_PROMPT,
)
from quarry_benchmark.cybergym import CybergymTask, MaterializedTask
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, ModelRequest, ModelResponse

POC_BYTES = bytes(range(64))


def _attempt(poc: bytes = POC_BYTES) -> ReproductionAttempt:
    return ReproductionAttempt(
        poc_base64=base64.b64encode(poc).decode(),
        poc_format="fuzzer-input-bytes",
        rationale="crafted from error.txt analysis",
        target_function="magic_fuzzer",
    )


def _task() -> CybergymTask:
    return CybergymTask(
        task_id="arvo:1065",
        project_name="file",
        project_homepage="http://www.darwinsys.com/file/",
        project_main_repo="https://github.com/file/file.git",
        project_language="c",
        vulnerability_description="regex regexec uninitialized pmatch.",
        task_difficulty={"level1": ["data/arvo/1065/repo-vul.tar.gz"]},
    )


def _materialized(repo: Path) -> MaterializedTask:
    return MaterializedTask(
        task=_task(),
        level="level1",
        repo_dir=repo.resolve(),
        description_path=None,
    )


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "magic.c").write_text("int x;", encoding="utf-8")
    return repo


class FlakyClient(MockModelClient):
    """Raises a real ValidationError on the first call, then answers validly."""

    def __init__(self) -> None:
        super().__init__(default=_attempt())
        self.calls = 0

    def complete_structured(  # type: ignore[override]
        self, request: ModelRequest, response_model: type[ReproductionAttempt]
    ) -> ModelResponse[ReproductionAttempt]:
        self.calls += 1
        if self.calls == 1:
            # genuine schema failure, like a misbehaving provider
            response_model.model_validate(
                {"poc_base64": "!!!not base64!!!", "poc_format": "x", "rationale": "r"}
            )
        return super().complete_structured(request, response_model)


class AlwaysBadClient(MockModelClient):
    """Always fails schema validation, like a provider that never complies."""

    def complete_structured(  # type: ignore[override]
        self, request: ModelRequest, response_model: type[ReproductionAttempt]
    ) -> ModelResponse[ReproductionAttempt]:
        response_model.model_validate(
            {"poc_base64": "!!!not base64!!!", "poc_format": "x", "rationale": "r"}
        )
        raise AssertionError("model_validate above must raise")


class TestReproductionAttempt:
    def test_valid_base64_decodes(self) -> None:
        attempt = ReproductionAttempt(
            poc_base64=base64.b64encode(b"abc").decode(),
            poc_format="fuzzer-input-bytes",
            rationale="r",
            target_function=None,
        )
        assert attempt.decode_poc() == b"abc"

    def test_invalid_base64_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ReproductionAttempt(
                poc_base64="!!!not base64!!!",
                poc_format="fuzzer-input-bytes",
                rationale="r",
                target_function=None,
            )

    def test_empty_poc_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ReproductionAttempt(
                poc_base64=base64.b64encode(b"").decode(),
                poc_format="fuzzer-input-bytes",
                rationale="r",
                target_function=None,
            )

    def test_oversized_poc_rejected(self) -> None:
        big = base64.b64encode(b"x" * (1024 * 1024 + 1)).decode()
        with pytest.raises(ValidationError):
            ReproductionAttempt(
                poc_base64=big,
                poc_format="fuzzer-input-bytes",
                rationale="r",
                target_function=None,
            )


class TestPrompt:
    def test_user_message_includes_description_and_repo(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        msg = build_user_message(
            _materialized(repo),
            description_text="buffer overflow in magic byte parsing",
        )
        assert "buffer overflow in magic byte parsing" in msg
        assert "src/magic.c" in msg
        assert "arvo:1065" in msg

    def test_user_message_without_description_is_level0(
        self, tmp_path: Path
    ) -> None:
        msg = build_user_message(_materialized(_repo(tmp_path)), description_text=None)
        assert "level 0" in msg.lower()

    def test_system_prompt_states_single_submission(self) -> None:
        assert "exactly one" in SYSTEM_PROMPT.lower()
        assert "base64" in SYSTEM_PROMPT.lower()


class TestReproduce:
    def test_valid_attempt_writes_poc(self, tmp_path: Path) -> None:
        outcome = reproduce(
            _materialized(_repo(tmp_path)),
            client=MockModelClient(default=_attempt()),
            budget=BudgetSpec(max_cost_usd=2.0),
            max_iterations=3,
            work_dir=tmp_path / "work",
        )
        assert outcome.poc_path.read_bytes() == POC_BYTES
        assert outcome.iterations >= 1

    def test_invalid_then_valid_attempts_retry(self, tmp_path: Path) -> None:
        client = FlakyClient()
        outcome = reproduce(
            _materialized(_repo(tmp_path)),
            client=client,
            budget=BudgetSpec(max_cost_usd=2.0),
            max_iterations=3,
            work_dir=tmp_path / "work",
        )
        assert client.calls == 2
        assert outcome.poc_path.read_bytes() == POC_BYTES

    def test_all_invalid_attempts_raise_agent_failed(self, tmp_path: Path) -> None:
        with pytest.raises(AgentFailed, match="schema_rejected|max_iterations"):
            reproduce(
                _materialized(_repo(tmp_path)),
                client=AlwaysBadClient(),
                budget=BudgetSpec(max_cost_usd=2.0),
                max_iterations=2,
                work_dir=tmp_path / "work",
            )
        assert not (tmp_path / "work" / "arvo_1065_poc.bin").exists()
