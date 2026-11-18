"""Integration test: Tier-1 (local) canary proof is logging-only.

A local subprocess prove reaches the loopback canary listener; the callback is
recorded on the capture but — because Tier 1 has no enforced egress policy and
resolved_target_ips stays empty — it NEVER corroborates (a loopback listener
presents source 127.0.0.1 for every natural callback).

Acceptance: SSRF/XXE out-of-band proof works with no external infrastructure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import SandboxExecSpec
from quarry_activities.inputs import SandboxExecActivityInput
from quarry_activities.sandbox_exec import sandbox_exec_activity
from quarry_workflows.prove_stage import prove_outcome_from_captures

_TOKEN = "0123456789abcdef0123456789abcdef"

_FETCH_CODE = (
    "import os, urllib.request; "
    "print(urllib.request.urlopen(os.environ['QUARRY_CANARY_URL']).status)"
)
# Exit 0 only when QUARRY_CANARY_URL is a well-formed loopback canary URL.
_URL_CHECK_CODE = (
    "import os, sys; "
    "sys.exit(0 if os.environ.get('QUARRY_CANARY_URL', '').startswith("
    "'http://127.0.0.1:') and '" + _TOKEN + "' in os.environ['QUARRY_CANARY_URL'] else 3)"
)


def _local_input(
    tmp_path: Path, *, code: str = _FETCH_CODE, canary_token: str | None = _TOKEN
) -> SandboxExecActivityInput:
    spec = SandboxExecSpec(command="python3", args=["-c", code], timeout_seconds=20)
    return SandboxExecActivityInput(
        spec_json=spec.model_dump_json(),
        egress_policy_json=None,
        allowed_hosts=(),
        artifact_store_path=str(tmp_path / "artifacts"),
        scan_id="scan-canary-local",
        candidate_finding_id="cf-canary-local",
        canary_token=canary_token,
    )


@pytest.fixture(autouse=True)
def _force_local_backend(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    """Tier-1 must be the configured backend for this module."""
    monkeypatch.setenv("QUARRY_SANDBOX_BACKEND", "")
    monkeypatch.delenv("QUARRY_CANARY_HOST", raising=False)


def test_local_prove_logs_callback_but_does_not_corroborate(tmp_path: Path) -> None:
    capture = sandbox_exec_activity(_local_input(tmp_path))

    # The sandbox reached the listener: one callback carrying the token.
    assert capture.exit_code == 0, capture
    assert len(capture.canary_callbacks) == 1
    callback = capture.canary_callbacks[0]
    assert _TOKEN in callback.path
    assert callback.source_ip == "127.0.0.1"

    # Tier 1 enforces no egress policy ⇒ no resolved target IPs.
    assert capture.resolved_target_ips == []

    # Logged but never corroborated: the callback cannot outrank the proof.
    verdict = prove_outcome_from_captures(
        [capture],
        [],
        canary_callbacks=capture.canary_callbacks,
        canary_token=_TOKEN,
        resolved_target_ips=capture.resolved_target_ips,
    )
    assert verdict == "proved"  # via exit_code==0, NOT "corroborated"
    assert verdict != "corroborated"


def test_no_canary_token_yields_no_callbacks(tmp_path: Path) -> None:
    spec = SandboxExecSpec(command="true", timeout_seconds=10)
    inp = _local_input(tmp_path, canary_token=None).model_copy(
        update={"spec_json": spec.model_dump_json()}
    )
    capture = sandbox_exec_activity(inp)
    assert capture.canary_callbacks == []
    assert capture.resolved_target_ips == []


def test_canary_url_is_forwarded_to_the_sandbox(tmp_path: Path) -> None:
    """The sandbox sees QUARRY_CANARY_URL pointing at the loopback listener."""
    capture = sandbox_exec_activity(_local_input(tmp_path, code=_URL_CHECK_CODE))
    assert capture.exit_code == 0, capture
