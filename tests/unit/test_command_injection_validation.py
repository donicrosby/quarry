"""Tests for the safe command-injection dynamic proof."""

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from quarry.schemas import CandidateFinding, VulnerabilityClass, utc_now
from quarry_activities.dynamic_validation import validate_command_injection_candidate
from quarry_activities.inputs import ValidateCommandInjectionInput

Handler = Callable[[httpx.Request], httpx.Response]


def _candidate(route: str = "/debug/ping", param: str = "host") -> CandidateFinding:
    return CandidateFinding(
        id="cmdi-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Potential command injection via host",
        hypothesis="host flows into subprocess.run",
        created_by="test",
        created_at=utc_now(),
        metadata={"route": route, "param": param, "sink": "subprocess.run"},
    )


def _input(**kwargs: object) -> ValidateCommandInjectionInput:
    base: dict[str, object] = {
        "finding_json": _candidate().model_dump_json(),
        "target_url": "http://localhost:9000",
        "allowed_hosts": ("localhost", "127.0.0.1"),
    }
    base.update(kwargs)
    return ValidateCommandInjectionInput.model_validate(base)


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _echoing_handler(request: httpx.Request) -> httpx.Response:
    host = request.url.params.get("host", "")
    marker = host.split("echo ", 1)[1] if "echo " in host else ""
    return httpx.Response(200, json={"command": "ping", "stdout": f"PING 127.0.0.1\n{marker}\n"})


def _silent_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"command": "ping", "stdout": "PING 127.0.0.1: ok"})


def test_validated_when_marker_is_echoed() -> None:
    with _client(_echoing_handler) as client:
        result = validate_command_injection_candidate(_input(), http_client=client)

    assert result.verdict == "validated"
    assert result.safe_payload is not None
    assert "echo QUARRY_PROOF_" in result.safe_payload
    assert result.safe_payload.startswith("127.0.0.1; echo QUARRY_PROOF_")


def test_rejected_when_marker_absent() -> None:
    with _client(_silent_handler) as client:
        result = validate_command_injection_candidate(_input(), http_client=client)

    assert result.verdict == "rejected"
    assert result.safe_payload is not None  # payload still recorded


def test_inconclusive_without_target() -> None:
    result = validate_command_injection_candidate(_input(target_url=None))

    assert result.verdict == "inconclusive"


def test_allowed_hosts_enforced() -> None:
    with (
        _client(_echoing_handler) as client,
        pytest.raises(ValueError, match="not in allowed_hosts"),
    ):
        validate_command_injection_candidate(
            _input(allowed_hosts=("example.com",)), http_client=client
        )


def test_captures_http_evidence(tmp_path: Path) -> None:
    with _client(_echoing_handler) as client:
        result = validate_command_injection_candidate(
            _input(artifact_store_path=str(tmp_path)), http_client=client
        )

    assert result.verdict == "validated"
    assert len(result.evidence_refs) == 2
    assert any(p.suffix == ".json" for p in tmp_path.rglob("*.json"))
